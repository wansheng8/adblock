#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器
所有功能都在一个文件中
"""

import os
import re
import json
import time
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, Dict, List, Optional
import requests

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 5,
    'TIMEOUT': 30,
    'RETRY_TIMES': 3,
    
    # 规则源文件
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 输出文件（固定名称）
    'OUTPUT_FILES': {
        'ad': 'rules/outputs/ad.txt',      # Adblock规则
        'dns': 'rules/outputs/dns.txt',    # DNS规则
        'hosts': 'rules/outputs/hosts.txt', # Hosts规则
        'black': 'rules/outputs/black.txt', # 黑名单规则
        'white': 'rules/outputs/white.txt', # 白名单规则
        'info': 'rules/outputs/info.json'  # 规则信息
    }
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AdBlockGenerator:
    """广告过滤规则生成器"""
    
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
        
        # 创建示例源文件（如果不存在）
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
            logger.info(f"创建示例黑名单源: {CONFIG['BLACK_SOURCE']}")
            
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
            logger.info(f"创建示例白名单源: {CONFIG['WHITE_SOURCE']}")
    
    def load_sources(self):
        """加载规则源URL"""
        # 黑名单源
        with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.black_urls.append(line)
        
        # 白名单源
        with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.white_urls.append(line)
        
        logger.info(f"加载 {len(self.black_urls)} 个黑名单源")
        logger.info(f"加载 {len(self.white_urls)} 个白名单源")
    
    def download_url(self, url: str) -> Optional[str]:
        """下载URL内容"""
        for attempt in range(CONFIG['RETRY_TIMES']):
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    logger.warning(f"下载失败 {url}: {e}")
                    return None
    
    def parse_content(self, content: str) -> tuple:
        """解析规则内容"""
        black_domains = set()
        black_rules = set()
        white_domains = set()
        white_rules = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # 白名单规则
            if line.startswith('@@'):
                domain = self.extract_domain(line)
                if domain:
                    white_domains.add(domain)
                    white_rules.add(f"@@||{domain}^")
                else:
                    white_rules.add(line)
            
            # 黑名单规则
            else:
                domain = self.extract_domain(line)
                if domain:
                    black_domains.add(domain)
                else:
                    if re.search(r'[a-zA-Z0-9]', line):
                        black_rules.add(line)
        
        return black_domains, black_rules, white_domains, white_rules
    
    def extract_domain(self, text: str) -> Optional[str]:
        """提取域名"""
        text = text.strip()
        
        # 移除注释
        if '#' in text:
            text = text.split('#')[0].strip()
        
        # 处理各种格式
        patterns = [
            r'^@@\|\|([^\^\$]+)\^',  # @@||domain.com^
            r'^\|\|([^\^\$]+)\^',    # ||domain.com^
            r'^@@([^\|\^\$]+)$',     # @@domain.com
            r'^([a-zA-Z0-9.-]+)$',   # domain.com
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',  # 127.0.0.1 domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',  # *.domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, text)
            if match:
                domain = match.group(1).lower()
                domain = re.sub(r'^www\.', '', domain)
                if self.is_valid_domain(domain):
                    return domain
        
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        local_domains = ['localhost', 'local', 'broadcasthost']
        if domain in local_domains:
            return False
        
        # 基本域名格式检查
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def download_and_parse_all(self):
        """下载并解析所有规则"""
        logger.info("开始下载和解析规则...")
        
        # 下载所有URL
        all_urls = [(url, 'black') for url in self.black_urls] + \
                   [(url, 'white') for url in self.white_urls]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = {executor.submit(self.download_url, url): (url, type_) for url, type_ in all_urls}
            
            for future in concurrent.futures.as_completed(futures):
                url, type_ = futures[future]
                try:
                    content = future.result()
                    if content:
                        black_domains, black_rules, white_domains, white_rules = self.parse_content(content)
                        
                        if type_ == 'black':
                            self.black_domains.update(black_domains)
                            self.black_rules.update(black_rules)
                            # 黑名单源中的白名单也加入
                            self.white_domains.update(white_domains)
                            self.white_rules.update(white_rules)
                        else:
                            self.white_domains.update(white_domains)
                            self.white_rules.update(white_rules)
                            # 白名单源中的黑名单也加入
                            self.black_domains.update(black_domains)
                            self.black_rules.update(black_rules)
                            
                        logger.debug(f"处理完成: {url}")
                except Exception as e:
                    logger.error(f"处理失败 {url}: {e}")
        
        logger.info(f"解析完成: 黑名单域名 {len(self.black_domains):,} 个")
        logger.info(f"白名单域名 {len(self.white_domains):,} 个")
    
    def apply_whitelist(self):
        """应用白名单"""
        if not self.white_domains:
            return
        
        original = len(self.black_domains)
        self.black_domains -= self.white_domains
        
        # 简单子域名匹配
        if len(self.white_domains) < 10000:
            to_remove = set()
            for black_domain in self.black_domains:
                for white_domain in self.white_domains:
                    if black_domain.endswith(f".{white_domain}"):
                        to_remove.add(black_domain)
                        break
            
            self.black_domains -= to_remove
            removed = original - len(self.black_domains)
            logger.info(f"白名单应用完成: 移除 {removed} 个域名")
    
    def generate_files(self):
        """生成规则文件"""
        logger.info("生成规则文件...")
        
        # 1. Adblock规则 (ad.txt)
        with open(CONFIG['OUTPUT_FILES']['ad'], 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n\n")
            
            # 白名单规则
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
            
            f.write("\n")
            
            # 黑名单域名规则
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
            
            f.write("\n")
            
            # 其他规则
            for rule in sorted(self.black_rules):
                f.write(f"{rule}\n")
        
        # 2. DNS规则 (dns.txt)
        with open(CONFIG['OUTPUT_FILES']['dns'], 'w', encoding='utf-8') as f:
            f.write(f"# DNS过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n\n")
            
            for domain in sorted(self.black_domains):
                f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open(CONFIG['OUTPUT_FILES']['hosts'], 'w', encoding='utf-8') as f:
            f.write(f"# Hosts格式广告过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            
            for domain in sorted(self.black_domains):
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 黑名单规则 (black.txt)
        with open(CONFIG['OUTPUT_FILES']['black'], 'w', encoding='utf-8') as f:
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open(CONFIG['OUTPUT_FILES']['white'], 'w', encoding='utf-8') as f:
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': datetime.now().strftime('%Y%m%d'),
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains),
                'blacklist_rules': len(self.black_rules),
                'whitelist_rules': len(self.white_rules)
            }
        }
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        logger.info("规则文件生成完成")
    
    def generate_readme(self):
        """生成README.md文件"""
        logger.info("生成README.md...")
        
        # 获取规则信息
        with open(CONFIG['OUTPUT_FILES']['info'], 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
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

**版本 {info['version']} 规则统计：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 其他规则：黑名单 {info['rules']['blacklist_rules']:,} 条，白名单 {info['rules']['whitelist_rules']:,} 条

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info("README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 50)
        print("广告过滤规则生成器")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            # 1. 加载规则源
            self.load_sources()
            
            # 2. 下载和解析规则
            self.download_and_parse_all()
            
            # 3. 应用白名单
            self.apply_whitelist()
            
            # 4. 生成规则文件
            self.generate_files()
            
            # 5. 生成README.md
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 50)
            print("✅ 处理完成！")
            print(f"⏱️  耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
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
    
    # 运行生成器
    generator = AdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
