#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 轻量优化版
不使用tqdm依赖
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

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 3,
    'TIMEOUT': 60,
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
        'max_total_domains': 200000,  # 最大域名总数
        'skip_some_sources': True,    # 跳过部分大文件源
        'batch_size': 5000,           # 批量处理大小
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

class SimpleProgressBar:
    """简单的进度条（不使用tqdm）"""
    
    @staticmethod
    def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
        """创建文本进度条"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        return f'\r{prefix} |{bar}| {percent}% {suffix}'
    
    @staticmethod
    def print_progress(iteration, total, prefix='', suffix=''):
        """打印进度条"""
        print(SimpleProgressBar.progress_bar(iteration, total, prefix, suffix), end='\r')
        if iteration == total:
            print()

class LightweightAdBlockGenerator:
    """轻量版广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 创建必要目录
        self.setup_directories()
    
    def setup_directories(self):
        """创建必要目录"""
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建精简的源文件
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源（精简高效版）\n")
                f.write("# 核心广告过滤规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
                f.write("https://easylist.to/easylist/easylist.txt\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ChineseFilter.txt\n")
                f.write("# 仅保留高质量源，避免过多域名\n")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
        
        # 创建中文源文件
        if not os.path.exists(CONFIG['CHINA_SOURCE']):
            with open(CONFIG['CHINA_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 中文广告规则源\n")
                f.write("https://easylist-downloads.adblockplus.org/easylistchina.txt\n")
                f.write("https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt\n")
    
    def load_sources(self):
        """加载规则源URL"""
        logger.info("加载规则源...")
        
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
                            'big.oisd.nl',
                            'oisd.nl',
                            'hagezi'
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
        
        # 中文源
        try:
            with open(CONFIG['CHINA_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.black_urls.append(line)
        except FileNotFoundError:
            pass
        
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
                return response.text
            except Exception as e:
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    logger.warning(f"下载失败 {url}: {e}")
                    return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain or domain in CONFIG['EXCLUDE_DOMAINS']:
            return False
        
        # 基本长度检查
        if len(domain) < 4 or len(domain) > 253:
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
            # 允许字母、数字、连字符
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        # 顶级域名至少2个字符
        if len(parts[-1]) < 2:
            return False
        
        return True
    
    def extract_domain_fast(self, line: str) -> Optional[str]:
        """快速域名提取"""
        line = line.strip()
        
        # 快速跳过
        if not line or len(line) < 4:
            return None
        
        # 跳过注释
        if line[0] in '!#/':
            return None
        
        # 常见模式匹配
        if '||' in line and '^' in line:
            # 处理 ||domain.com^ 格式
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^', line)
            if match:
                domain = match.group(1).lower()
                domain = domain.replace('www.', '').replace('*.', '')
                if self.is_valid_domain(domain):
                    return domain
        
        elif line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
            # 处理 hosts 格式
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                domain = domain.replace('www.', '').replace('*.', '')
                if self.is_valid_domain(domain):
                    return domain
        
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
            # 纯域名格式
            domain = line.lower()
            domain = domain.replace('www.', '').replace('*.', '')
            if self.is_valid_domain(domain):
                return domain
        
        return None
    
    def parse_content_fast(self, content: str) -> tuple:
        """快速解析规则内容"""
        black_domains = set()
        white_domains = set()
        
        lines = content.split('\n')
        total_lines = len(lines)
        
        # 显示进度
        for i, line in enumerate(lines):
            if i % 10000 == 0 and i > 0:
                logger.debug(f"解析进度: {i}/{total_lines} 行")
            
            domain = self.extract_domain_fast(line)
            if domain:
                if line.startswith('@@'):
                    white_domains.add(domain)
                else:
                    black_domains.add(domain)
        
        return black_domains, white_domains
    
    def download_and_parse_all(self):
        """下载并解析所有规则"""
        logger.info("开始下载和解析规则...")
        
        all_urls = self.black_urls + self.white_urls
        total_urls = len(all_urls)
        
        results = []
        failed_urls = []
        
        # 显示进度
        print(f"总共有 {total_urls} 个URL需要处理")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            # 提交下载任务
            future_to_url = {executor.submit(self.download_url, url): url for url in all_urls}
            
            # 处理结果
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                
                # 显示进度
                if completed % 5 == 0 or completed == total_urls:
                    SimpleProgressBar.print_progress(completed, total_urls, prefix='下载进度:', suffix='完成')
                
                try:
                    content = future.result()
                    if content:
                        black_domains, white_domains = self.parse_content_fast(content)
                        results.append((black_domains, white_domains))
                        logger.debug(f"处理完成: {url} ({len(black_domains)} 域名)")
                    else:
                        failed_urls.append(url)
                        
                except Exception as e:
                    logger.error(f"处理失败 {url}: {e}")
                    failed_urls.append(url)
        
        print()  # 换行
        
        # 合并结果
        for black_domains, white_domains in results:
            self.black_domains.update(black_domains)
            self.white_domains.update(white_domains)
        
        if failed_urls:
            logger.warning(f"有 {len(failed_urls)} 个URL处理失败")
        
        logger.info(f"解析完成: 黑名单域名 {len(self.black_domains):,} 个")
        logger.info(f"白名单域名 {len(self.white_domains):,} 个")
    
    def apply_whitelist_simple(self):
        """简单应用白名单"""
        if not self.white_domains:
            logger.warning("没有白名单域名")
            return
        
        logger.info("应用白名单...")
        
        original_count = len(self.black_domains)
        
        # 直接匹配移除
        self.black_domains -= self.white_domains
        
        # 只检查直接子域名（性能更好）
        white_suffixes = {f".{domain}" for domain in self.white_domains}
        
        to_remove = set()
        for black_domain in self.black_domains:
            for suffix in white_suffixes:
                if black_domain.endswith(suffix):
                    to_remove.add(black_domain)
                    break
        
        self.black_domains -= to_remove
        
        removed = original_count - len(self.black_domains)
        logger.info(f"白名单应用完成: 移除 {removed} 个域名，剩余 {len(self.black_domains):,} 个")
    
    def filter_domains(self):
        """过滤域名，保留高质量域名"""
        logger.info("过滤域名...")
        
        original_count = len(self.black_domains)
        
        # 如果域名太多，进行筛选
        if len(self.black_domains) > CONFIG['PERFORMANCE']['max_total_domains']:
            logger.info(f"域名过多 ({len(self.black_domains):,})，进行筛选...")
            
            # 将域名转换为列表以便排序
            domains_list = list(self.black_domains)
            
            # 按域名质量排序（较短的域名通常更重要）
            domains_list.sort(key=lambda x: (len(x.split('.')), len(x)))
            
            # 取前N个
            domains_list = domains_list[:CONFIG['PERFORMANCE']['max_total_domains']]
            self.black_domains = set(domains_list)
            
            logger.info(f"筛选后域名: {len(self.black_domains):,} 个")
        
        # 移除一些明显不是广告的域名
        good_domains = set()
        ad_keywords = ['ad', 'ads', 'adv', 'track', 'analytics', 'pixel', 'beacon', 'doubleclick', 'googlead']
        
        for domain in self.black_domains:
            # 包含广告关键词的域名优先保留
            has_ad_keyword = any(keyword in domain for keyword in ad_keywords)
            
            # 域名长度适中（太长的可能是路径）
            is_reasonable_length = 4 <= len(domain) <= 50
            
            # 不是纯数字域名
            not_all_numbers = not all(c.isdigit() or c == '.' for c in domain)
            
            if has_ad_keyword or (is_reasonable_length and not_all_numbers):
                good_domains.add(domain)
        
        self.black_domains = good_domains
        logger.info(f"最终域名数: {len(self.black_domains):,} 个")
    
    def generate_files_efficient(self):
        """高效生成规则文件"""
        logger.info("生成规则文件...")
        
        # 先过滤域名
        self.filter_domains()
        
        # 排序域名
        sorted_domains = sorted(self.black_domains)
        sorted_white_domains = sorted(self.white_domains)
        
        # 1. Adblock规则 (ad.txt) - 最常用
        logger.info("生成 ad.txt...")
        with open(CONFIG['OUTPUT_FILES']['ad'], 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 黑名单域名: {len(sorted_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(sorted_white_domains):,} 个\n")
            f.write(f"! 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write("! 来源: https://github.com/wansheng8/adblock\n\n")
            
            # 批量写入提高性能
            batch_size = CONFIG['PERFORMANCE']['batch_size']
            total_batches = (len(sorted_domains) + batch_size - 1) // batch_size
            
            for i in range(total_batches):
                start_idx = i * batch_size
                end_idx = min((i + 1) * batch_size, len(sorted_domains))
                batch = sorted_domains[start_idx:end_idx]
                
                for domain in batch:
                    f.write(f"||{domain}^\n")
                
                # 显示进度
                if i % 10 == 0 or i == total_batches - 1:
                    SimpleProgressBar.print_progress(i + 1, total_batches, prefix='生成ad.txt:', suffix='完成')
        
        print()  # 换行
        
        # 2. DNS规则 (dns.txt) - 第二常用
        logger.info("生成 dns.txt...")
        with open(CONFIG['OUTPUT_FILES']['dns'], 'w', encoding='utf-8') as f:
            f.write(f"# DNS过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(sorted_domains):,}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n\n")
            
            batch_size = CONFIG['PERFORMANCE']['batch_size']
            total_batches = (len(sorted_domains) + batch_size - 1) // batch_size
            
            for i in range(total_batches):
                start_idx = i * batch_size
                end_idx = min((i + 1) * batch_size, len(sorted_domains))
                batch = sorted_domains[start_idx:end_idx]
                
                for domain in batch:
                    f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt) - 可选，可以跳过以减少时间
        logger.info("生成 hosts.txt...")
        with open(CONFIG['OUTPUT_FILES']['hosts'], 'w', encoding='utf-8') as f:
            f.write(f"# Hosts格式广告过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(sorted_domains):,}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            
            # 只写前10万条，避免文件过大
            max_hosts = min(100000, len(sorted_domains))
            for i, domain in enumerate(sorted_domains[:max_hosts]):
                f.write(f"0.0.0.0 {domain}\n")
                if i % 10000 == 0 and i > 0:
                    logger.debug(f"hosts.txt 进度: {i}/{max_hosts}")
        
        # 4. 黑名单规则 (black.txt)
        logger.info("生成 black.txt...")
        with open(CONFIG['OUTPUT_FILES']['black'], 'w', encoding='utf-8') as f:
            for domain in sorted_domains[:100000]:  # 限制数量
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        logger.info("生成 white.txt...")
        with open(CONFIG['OUTPUT_FILES']['white'], 'w', encoding='utf-8') as f:
            f.write("# 白名单规则\n")
            f.write("# 这些域名不会被拦截\n\n")
            for domain in sorted_white_domains:
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
                'optimized': True,
                'source_count': len(self.black_urls) + len(self.white_urls)
            }
        }
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        logger.info("规则文件生成完成")
    
    def generate_readme_simple(self):
        """生成简单的README.md文件"""
        logger.info("生成README.md...")
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        version = info['version']
        
        readme_content = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 | 说明 |
|----------|----------|----------|----------|------|
| 广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` | 主规则，推荐使用 |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` | Pi-hole/AdGuard Home |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` | 系统Hosts文件 |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` | 纯黑名单域名 |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` | 排除误杀 |

**版本 {version} 规则统计：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 总域名数：{info['rules']['total_domains']:,} 个
- 规则源：{info['performance']['source_count']} 个

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*

## 使用建议

1. **AdGuard/uBlock Origin**：使用 `ad.txt` 文件
2. **Pi-hole/AdGuard Home**：使用 `dns.txt` 文件
3. **系统Hosts**：使用 `hosts.txt` 文件（前10万条）
4. **误报处理**：查看 `white.txt` 或提交Issue

## 特点

- **轻量高效**：经过优化，生成速度快
- **质量优先**：筛选高质量广告域名
- **自动更新**：每日自动更新
- **多格式支持**：支持Adblock、DNS、Hosts格式

---
*生成器代码：https://github.com/wansheng8/adblock*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info("README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("广告过滤规则生成器 - 轻量优化版")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载规则源
            self.load_sources()
            
            # 2. 下载和解析规则
            self.download_and_parse_all()
            
            # 3. 应用白名单
            self.apply_whitelist_simple()
            
            # 4. 生成规则文件
            self.generate_files_efficient()
            
            # 5. 生成README.md
            self.generate_readme_simple()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("✅ 处理完成！")
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"✅ 白名单域名: {len(self.white_domains):,}个")
            print(f"📁 规则文件: rules/outputs/")
            print("📖 文档更新: README.md")
            print("=" * 60)
            
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
    
    print("\n🚀 启动轻量版广告过滤规则生成器...")
    generator = LightweightAdBlockGenerator()
    
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
