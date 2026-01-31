#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 性能优化版
"""

import os
import re
import json
import time
import hashlib
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, Dict, List, Optional, Tuple
import requests
import urllib.parse
from collections import defaultdict
import sys
from tqdm import tqdm  # 进度条库

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 3,  # 减少并发，避免被限速
    'TIMEOUT': 60,     # 增加超时时间
    'RETRY_TIMES': 3,
    
    # 规则源文件
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    'CHINA_SOURCE': 'rules/sources/china.txt',
    'ENHANCED_SOURCE': 'rules/sources/enhanced.txt',
    
    # 输出文件
    'OUTPUT_FILES': {
        'ad': 'rules/outputs/ad.txt',
        'dns': 'rules/outputs/dns.txt',
        'hosts': 'rules/outputs/hosts.txt',
        'black': 'rules/outputs/black.txt',
        'white': 'rules/outputs/white.txt',
        'info': 'rules/outputs/info.json',
        'smart_ad': 'rules/outputs/smart_ad.txt',
        'mobile_ad': 'rules/outputs/mobile_ad.txt',
    },
    
    # 性能优化配置
    'PERFORMANCE': {
        'max_total_domains': 300000,  # 最大域名总数
        'skip_some_sources': True,    # 跳过部分大文件源
        'batch_size': 10000,          # 批量处理大小
        'enable_progress_bar': True,  # 启用进度条
        'use_bloom_filter': False,    # 使用布隆过滤器去重（需要安装pybloom-live）
    },
    
    # 排除的域名
    'EXCLUDE_DOMAINS': [
        'localhost', 'local', 'broadcasthost',
        '127.0.0.1', '0.0.0.0', '::1'
    ],
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProgressTracker:
    """进度跟踪器"""
    
    def __init__(self):
        self.start_time = time.time()
        self.stages = {}
        self.current_stage = None
    
    def start_stage(self, name: str):
        """开始一个阶段"""
        self.current_stage = name
        self.stages[name] = {'start': time.time(), 'items_processed': 0}
        logger.info(f"开始阶段: {name}")
    
    def update_progress(self, items: int = 1):
        """更新进度"""
        if self.current_stage and self.current_stage in self.stages:
            self.stages[self.current_stage]['items_processed'] += items
    
    def end_stage(self):
        """结束当前阶段"""
        if self.current_stage and self.current_stage in self.stages:
            end_time = time.time()
            stage_info = self.stages[self.current_stage]
            elapsed = end_time - stage_info['start']
            items = stage_info['items_processed']
            logger.info(f"完成阶段 {self.current_stage}: 处理 {items} 个项目，耗时 {elapsed:.2f}秒")
            self.current_stage = None

class OptimizedDomainFilter:
    """优化版域名过滤器"""
    
    @staticmethod
    def optimize_domains(domains: Set[str]) -> Set[str]:
        """优化域名集合，移除重复和低质量域名"""
        logger.info(f"开始优化域名集合: {len(domains):,} 个")
        
        # 1. 去重
        unique_domains = set(domains)
        logger.info(f"去重后: {len(unique_domains):,} 个")
        
        # 2. 移除无效域名
        valid_domains = set()
        for domain in unique_domains:
            if OptimizedDomainFilter.is_valid_domain(domain):
                valid_domains.add(domain)
        
        logger.info(f"有效域名: {len(valid_domains):,} 个")
        
        # 3. 按域名质量排序并截取
        if len(valid_domains) > CONFIG['PERFORMANCE']['max_total_domains']:
            logger.info(f"域名过多，截取前 {CONFIG['PERFORMANCE']['max_total_domains']:,} 个")
            # 按域名长度和质量排序
            sorted_domains = sorted(valid_domains, 
                                   key=lambda x: (len(x.split('.')), -len(x)))
            valid_domains = set(sorted_domains[:CONFIG['PERFORMANCE']['max_total_domains']])
        
        return valid_domains
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """检查域名有效性"""
        if not domain or domain in CONFIG['EXCLUDE_DOMAINS']:
            return False
        
        # 基本长度检查
        if len(domain) < 3 or len(domain) > 253:
            return False
        
        # 必须包含点号
        if '.' not in domain:
            return False
        
        # 检查每个部分
        parts = domain.split('.')
        for part in parts:
            if not part:  # 不能有空的段
                return False
            if len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        # 顶级域名至少2个字符
        if len(parts[-1]) < 2:
            return False
        
        return True

class OptimizedAdBlockGenerator:
    """优化版广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        self.progress = ProgressTracker()
        
        # 创建必要目录
        self.setup_directories()
    
    def setup_directories(self):
        """创建必要目录"""
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建精简的源文件
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源（精简版）\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
                f.write("https://easylist.to/easylist/easylist.txt\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ChineseFilter.txt\n")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
    
    def load_sources(self):
        """加载规则源URL"""
        self.progress.start_stage("加载规则源")
        
        # 黑名单源
        with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # 跳过可能的大文件源以提高性能
                    if CONFIG['PERFORMANCE']['skip_some_sources']:
                        if any(skip in line for skip in [
                            'blocklistproject',
                            'hblock',
                            'big.oisd.nl'
                        ]):
                            logger.info(f"跳过可能的大文件源: {line}")
                            continue
                    self.black_urls.append(line)
        
        # 白名单源
        with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.white_urls.append(line)
        
        self.progress.end_stage()
        logger.info(f"加载 {len(self.black_urls)} 个黑名单源")
        logger.info(f"加载 {len(self.white_urls)} 个白名单源")
    
    def download_url(self, url: str) -> Optional[str]:
        """下载URL内容"""
        for attempt in range(CONFIG['RETRY_TIMES']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                
                # 检查内容大小
                content_length = len(response.content)
                if content_length > 10 * 1024 * 1024:  # 10MB
                    logger.warning(f"内容过大 ({content_length/1024/1024:.1f}MB): {url}")
                
                return response.text
            except Exception as e:
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(3)
                else:
                    logger.warning(f"下载失败 {url}: {e}")
                    return None
    
    def extract_domain_simple(self, line: str) -> Optional[str]:
        """简单高效的域名提取"""
        line = line.strip()
        
        # 快速跳过
        if not line or len(line) < 3:
            return None
        
        # 跳过注释
        if line[0] in '!#/':
            return None
        
        # 常见模式匹配
        patterns = [
            (r'^\|\|([a-zA-Z0-9.-]+)\^', 1),  # ||domain.com^
            (r'^@@\|\|([a-zA-Z0-9.-]+)\^', 1), # @@||domain.com^
            (r'^([a-zA-Z0-9.-]+)$', 1),       # domain.com
            (r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+)', 1), # 0.0.0.0 domain.com
            (r'^127\.0\.0\.1\s+([a-zA-Z0-9.-]+)', 1), # 127.0.0.1 domain.com
            (r'^\*\.([a-zA-Z0-9.-]+)', 1),    # *.domain.com
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(group).lower().strip()
                # 简单清理
                domain = re.sub(r'^www\.', '', domain)
                domain = re.sub(r'^m\.', '', domain)
                domain = re.sub(r'^static\.', '', domain)
                
                # 快速验证
                if (domain and '.' in domain and 
                    len(domain) >= 4 and len(domain) <= 253 and
                    domain not in CONFIG['EXCLUDE_DOMAINS']):
                    return domain
        
        return None
    
    def parse_content_fast(self, content: str) -> tuple:
        """快速解析规则内容"""
        black_domains = set()
        white_domains = set()
        
        lines = content.split('\n')
        batch_size = CONFIG['PERFORMANCE']['batch_size']
        
        for i in range(0, len(lines), batch_size):
            batch = lines[i:i+batch_size]
            for line in batch:
                domain = self.extract_domain_simple(line)
                if domain:
                    if line.startswith('@@'):
                        white_domains.add(domain)
                    else:
                        black_domains.add(domain)
            
            self.progress.update_progress(len(batch))
        
        return black_domains, white_domains
    
    def download_and_parse_all(self):
        """下载并解析所有规则"""
        logger.info("开始下载和解析规则...")
        self.progress.start_stage("下载解析规则")
        
        all_urls = self.black_urls + self.white_urls
        total_urls = len(all_urls)
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            # 提交下载任务
            future_to_url = {executor.submit(self.download_url, url): url for url in all_urls}
            
            # 处理结果
            for i, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        black_domains, white_domains = self.parse_content_fast(content)
                        results.append((black_domains, white_domains))
                    
                    # 显示进度
                    if i % 5 == 0 or i == total_urls:
                        logger.info(f"处理进度: {i}/{total_urls}")
                    
                    self.progress.update_progress()
                        
                except Exception as e:
                    logger.error(f"处理失败 {url}: {e}")
        
        # 合并结果
        for black_domains, white_domains in results:
            self.black_domains.update(black_domains)
            self.white_domains.update(white_domains)
        
        self.progress.end_stage()
        logger.info(f"解析完成: 黑名单域名 {len(self.black_domains):,} 个")
        logger.info(f"白名单域名 {len(self.white_domains):,} 个")
    
    def apply_whitelist_fast(self):
        """快速应用白名单"""
        if not self.white_domains:
            logger.warning("没有白名单域名")
            return
        
        self.progress.start_stage("应用白名单")
        
        original_count = len(self.black_domains)
        
        # 直接匹配移除
        self.black_domains -= self.white_domains
        
        # 简单的子域名匹配（只检查一级子域名）
        white_suffixes = set()
        for white_domain in self.white_domains:
            white_suffixes.add(f".{white_domain}")
        
        to_remove = set()
        batch_size = CONFIG['PERFORMANCE']['batch_size']
        black_list = list(self.black_domains)
        
        for i in range(0, len(black_list), batch_size):
            batch = black_list[i:i+batch_size]
            for black_domain in batch:
                # 检查是否以任何白名单后缀结尾
                for suffix in white_suffixes:
                    if black_domain.endswith(suffix):
                        to_remove.add(black_domain)
                        break
            
            self.progress.update_progress(len(batch))
        
        self.black_domains -= to_remove
        
        removed = original_count - len(self.black_domains)
        self.progress.end_stage()
        logger.info(f"白名单应用完成: 移除 {removed} 个域名，剩余 {len(self.black_domains):,} 个")
    
    def optimize_domains(self):
        """优化域名集合"""
        self.progress.start_stage("优化域名")
        
        # 使用优化过滤器
        self.black_domains = OptimizedDomainFilter.optimize_domains(self.black_domains)
        
        self.progress.end_stage()
    
    def generate_files(self):
        """生成规则文件"""
        logger.info("生成规则文件...")
        self.progress.start_stage("生成文件")
        
        # 优化域名
        self.optimize_domains()
        
        # 1. Adblock规则 (ad.txt)
        with open(CONFIG['OUTPUT_FILES']['ad'], 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n")
            f.write(f"! 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write("! 来源: https://github.com/wansheng8/adblock\n\n")
            
            # 黑名单域名规则（批量写入提高性能）
            domains = sorted(self.black_domains)
            for i in range(0, len(domains), CONFIG['PERFORMANCE']['batch_size']):
                batch = domains[i:i+CONFIG['PERFORMANCE']['batch_size']]
                for domain in batch:
                    f.write(f"||{domain}^\n")
                
                self.progress.update_progress(len(batch))
        
        # 2. DNS规则 (dns.txt)
        with open(CONFIG['OUTPUT_FILES']['dns'], 'w', encoding='utf-8') as f:
            f.write(f"# DNS过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n\n")
            
            domains = sorted(self.black_domains)
            for i in range(0, len(domains), CONFIG['PERFORMANCE']['batch_size']):
                batch = domains[i:i+CONFIG['PERFORMANCE']['batch_size']]
                for domain in batch:
                    f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open(CONFIG['OUTPUT_FILES']['hosts'], 'w', encoding='utf-8') as f:
            f.write(f"# Hosts格式广告过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            
            domains = sorted(self.black_domains)
            for i in range(0, len(domains), CONFIG['PERFORMANCE']['batch_size']):
                batch = domains[i:i+CONFIG['PERFORMANCE']['batch_size']]
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 黑名单规则 (black.txt) - 简化的adblock格式
        with open(CONFIG['OUTPUT_FILES']['black'], 'w', encoding='utf-8') as f:
            domains = sorted(self.black_domains)
            for domain in domains:
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open(CONFIG['OUTPUT_FILES']['white'], 'w', encoding='utf-8') as f:
            f.write("# 白名单规则\n")
            f.write("# 这些域名不会被拦截\n\n")
            for domain in sorted(self.white_domains):
                f.write(f"@@||{domain}^\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': datetime.now().strftime('%Y%m%d'),
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains),
                'total_domains': len(self.black_domains) + len(self.white_domains)
            },
            'performance': {
                'max_domains': CONFIG['PERFORMANCE']['max_total_domains'],
                'optimized': True
            }
        }
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        self.progress.end_stage()
        logger.info("规则文件生成完成")
    
    def generate_readme(self):
        """生成README.md文件"""
        logger.info("生成README.md...")
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        version = info['version']
        
        readme_content = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {version} 规则统计：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 总域名数：{info['rules']['total_domains']:,} 个

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*

## 性能优化说明

为确保生成速度和规则质量，本规则集进行了以下优化：

1. **域名数量限制**：限制在 {info['performance']['max_domains']:,} 个高质量域名内
2. **智能过滤**：自动移除无效和低质量域名
3. **批量处理**：使用批量处理提高性能
4. **资源优化**：优化内存使用和CPU占用

## 使用建议

1. **AdGuard/uBlock Origin**：使用 `ad.txt` 文件
2. **Pi-hole/AdGuard Home**：使用 `dns.txt` 文件
3. **系统Hosts**：使用 `hosts.txt` 文件
4. **误报处理**：查看 `white.txt` 或提交Issue

---
*生成器代码：https://github.com/wansheng8/adblock*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info("README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 50)
        print("广告过滤规则生成器 - 性能优化版")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            # 1. 加载规则源
            self.load_sources()
            
            # 2. 下载和解析规则
            self.download_and_parse_all()
            
            # 3. 应用白名单
            self.apply_whitelist_fast()
            
            # 4. 生成规则文件
            self.generate_files()
            
            # 5. 生成README.md
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 50)
            print("✅ 处理完成！")
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"✅ 白名单域名: {len(self.white_domains):,}个")
            print(f"📁 规则文件: rules/outputs/")
            print("📖 文档更新: README.md")
            print("=" * 50)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    # 在GitHub Actions中自动使用优化版
    print("\n⚡ 使用性能优化版...")
    generator = OptimizedAdBlockGenerator()
    
    # 运行生成器
    success = generator.run()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("🚀 GitHub Actions会自动提交更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
