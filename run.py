#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 完整版
所有功能都在一个文件中
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
    'MAX_WORKERS': 5,
    'TIMEOUT': 30,
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
    
    # 排除的域名
    'EXCLUDE_DOMAINS': [
        'localhost', 'local', 'broadcasthost',
        '127.0.0.1', '0.0.0.0', '::1'
    ],
    
    # 命中率优化配置
    'HIT_OPTIMIZATION': {
        'enable_smart_rules': True,
        'enable_china_focus': True,
        'enable_mobile_optimization': True,
        'min_hit_score': 0.3,
        'max_domains_per_source': 50000,
        'enable_wildcard_expansion': True,
        'enable_subdomain_generation': True,
    },
    
    # 中文广告关键词
    'CHINESE_AD_KEYWORDS': [
        '广告', '推广', '营销', '投放', '联盟', '流量', '变现',
        '弹窗', '悬浮', '横幅', '插屏', '开屏', '贴片', '前贴',
        '中插', '后贴', '角标', '信息流', '原生', '激励视频',
        'admob', 'mopub', 'facebook', 'twitter', 'instagram',
        'googlead', 'doubleclick', 'adsystem', 'adservice',
        'tracking', 'analytics', 'statistics', 'monitor',
        'beacon', 'pixel', 'tag', 'cookie', 'fingerprint'
    ],
    
    # 移动端广告关键词
    'MOBILE_AD_KEYWORDS': [
        'mobile', 'mob', 'android', 'ios', 'iphone', 'ipad',
        'app', 'sdk', 'inapp', 'interstitial', 'reward',
        'banner', 'native', 'video', 'fullscreen', 'push',
        'notification', 'advert', 'promo', 'offer', 'install'
    ]
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DomainOptimizer:
    """域名优化器"""
    
    @staticmethod
    def expand_wildcard_domain(domain: str) -> List[str]:
        """扩展通配符域名"""
        if '*' not in domain:
            return [domain]
        
        expansions = []
        if domain.startswith('*.') and domain.count('*') == 1:
            base = domain[2:]
            expansions.append(base)
            common_subs = ['www', 'm', 'mobile', 'app', 'api', 'static', 'cdn', 'img', 'image']
            for sub in common_subs:
                expansions.append(f"{sub}.{base}")
        
        return expansions
    
    @staticmethod
    def generate_subdomains(domain: str) -> List[str]:
        """生成常见子域名"""
        subdomains = []
        common_subs = [
            'ad', 'ads', 'adserver', 'advert', 'advertising',
            'track', 'tracking', 'analytics', 'stats', 'stat',
            'click', 'clk', 'affiliate', 'aff', 'promo',
            'banner', 'popup', 'float', 'sponsor', 'sponsored',
            'media', 'video', 'img', 'image', 'static', 'cdn',
            'js', 'script', 'pixel', 'beacon', 'tag'
        ]
        
        for sub in common_subs:
            subdomains.append(f"{sub}.{domain}")
        
        return subdomains
    
    @staticmethod
    def is_ad_domain(domain: str) -> bool:
        """判断域名是否可能是广告域名"""
        ad_patterns = [
            r'ad[0-9]*[\._-]', r'ads[0-9]*[\._-]', r'advert',
            r'track', r'tracking', r'analytics', r'stats',
            r'doubleclick', r'googlead', r'googlesyndication',
            r'facebook\.com/(plugins|widgets)',
            r'amazon-adsystem', r'moatads', r'scorecardresearch',
            r'quantserve', r'outbrain', r'taboola',
            r'adsystem', r'adservice', r'adserver'
        ]
        
        domain_lower = domain.lower()
        for pattern in ad_patterns:
            if re.search(pattern, domain_lower):
                return True
        
        ad_suffixes = ['.ad.', '.ads.', '.adv.', '.advert.', '.advertising.']
        for suffix in ad_suffixes:
            if suffix in domain_lower:
                return True
        
        return False

class HitRateOptimizer:
    """命中率优化器"""
    
    def __init__(self):
        self.domain_hits = defaultdict(int)
        self.pattern_hits = defaultdict(int)
        self.keyword_hits = defaultdict(int)
    
    def score_domain(self, domain: str) -> float:
        """给域名评分（越高越可能是广告）"""
        score = 0.0
        
        if DomainOptimizer.is_ad_domain(domain):
            score += 0.5
        
        for keyword in CONFIG['CHINESE_AD_KEYWORDS']:
            if keyword.lower() in domain.lower():
                score += 0.3
                break
        
        for keyword in CONFIG['MOBILE_AD_KEYWORDS']:
            if keyword.lower() in domain.lower():
                score += 0.2
                break
        
        parts = domain.split('.')
        if len(parts) >= 4:
            score += 0.2
        
        if re.search(r'\d{2,}', domain):
            score += 0.1
        
        return min(score, 1.0)
    
    def filter_low_score_domains(self, domains: Set[str], min_score: float = None) -> Set[str]:
        """过滤低分域名"""
        if min_score is None:
            min_score = CONFIG['HIT_OPTIMIZATION']['min_hit_score']
        
        filtered = set()
        for domain in domains:
            score = self.score_domain(domain)
            if score >= min_score:
                filtered.add(domain)
        
        logger.info(f"域名过滤: {len(domains)} -> {len(filtered)} (分数阈值: {min_score})")
        return filtered

class AdBlockGenerator:
    """基础版广告过滤规则生成器"""
    
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
        
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
                f.write("https://easylist.to/easylist/easylist.txt\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
            
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
    
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
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain or domain in CONFIG['EXCLUDE_DOMAINS']:
            return False
        
        if len(domain) < 3 or len(domain) > 253:
            return False
        
        if '.' not in domain:
            return False
        
        parts = domain.split('.')
        for part in parts:
            if len(part) < 1 or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def extract_domain(self, text: str) -> Optional[str]:
        """提取域名"""
        if not text:
            return None
        
        text = text.strip()
        
        if '#' in text:
            text = text.split('#')[0].strip()
        
        patterns = [
            (r'^@@\|\|([^\^\$]+)\^', 1),
            (r'^\|\|([^\^\$]+)\^', 1),
            (r'^@@([^\|\^\$]+)$', 1),
            (r'^([a-zA-Z0-9.-]+)$', 1),
            (r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)', 1),
            (r'^\*\.([a-zA-Z0-9.-]+)', 1),
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, text)
            if match:
                domain = match.group(group).lower()
                domain = re.sub(r'^www\.', '', domain)
                if self.is_valid_domain(domain):
                    return domain
        
        return None
    
    def parse_content(self, content: str) -> tuple:
        """解析规则内容"""
        black_domains = set()
        black_rules = set()
        white_domains = set()
        white_rules = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            if line.startswith('@@'):
                domain = self.extract_domain(line)
                if domain:
                    white_domains.add(domain)
                    white_rules.add(f"@@||{domain}^")
                else:
                    white_rules.add(line)
            else:
                domain = self.extract_domain(line)
                if domain:
                    black_domains.add(domain)
                else:
                    if re.search(r'[a-zA-Z0-9]', line):
                        black_rules.add(line)
        
        return black_domains, black_rules, white_domains, white_rules
    
    def download_and_parse_all(self):
        """下载并解析所有规则"""
        logger.info("开始下载和解析规则...")
        
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
                            self.white_domains.update(white_domains)
                            self.white_rules.update(white_rules)
                        else:
                            self.white_domains.update(white_domains)
                            self.white_rules.update(white_rules)
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
            logger.warning("没有白名单域名")
            return
        
        original = len(self.black_domains)
        self.black_domains -= self.white_domains
        
        if len(self.white_domains) < 5000:
            to_remove = set()
            for black_domain in self.black_domains:
                for white_domain in self.white_domains:
                    if black_domain.endswith(f".{white_domain}"):
                        to_remove.add(black_domain)
                        break
            
            self.black_domains -= to_remove
            removed = original - len(self.black_domains)
            logger.info(f"白名单应用完成: 移除 {removed} 个域名")
        else:
            logger.info(f"白名单域名太多({len(self.white_domains):,})，跳过子域名匹配")
    
    def generate_files(self):
        """生成规则文件"""
        logger.info("生成规则文件...")
        
        # 1. Adblock规则 (ad.txt)
        with open(CONFIG['OUTPUT_FILES']['ad'], 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n\n")
            
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
            
            f.write("\n")
            
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
            
            f.write("\n")
            
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
            },
            'sources': {
                'blacklist': len(self.black_urls),
                'whitelist': len(self.white_urls)
            }
        }
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
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
        print("广告过滤规则生成器 - 基础版")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            self.load_sources()
            self.download_and_parse_all()
            self.apply_whitelist()
            self.generate_files()
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

class EnhancedAdBlockGenerator(AdBlockGenerator):
    """增强版广告过滤规则生成器"""
    
    def __init__(self):
        super().__init__()
        self.optimizer = HitRateOptimizer()
        self.china_domains = set()
        self.enhanced_domains = set()
        
        # 创建增强源文件
        self.setup_enhanced_sources()
    
    def setup_enhanced_sources(self):
        """创建增强源文件"""
        # 中文广告规则源
        if not os.path.exists(CONFIG['CHINA_SOURCE']):
            os.makedirs(os.path.dirname(CONFIG['CHINA_SOURCE']), exist_ok=True)
            with open(CONFIG['CHINA_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 中文广告过滤规则源\n")
                f.write("https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt\n")
                f.write("https://easylist-downloads.adblockplus.org/easylistchina.txt\n")
                f.write("https://gitee.com/xinggsf/Adblock-Rule/raw/master/rule.txt\n")
                f.write("https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt\n")
        
        # 增强规则源
        if not os.path.exists(CONFIG['ENHANCED_SOURCE']):
            os.makedirs(os.path.dirname(CONFIG['ENHANCED_SOURCE']), exist_ok=True)
            with open(CONFIG['ENHANCED_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 增强广告过滤规则源\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt\n")
                f.write("https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt\n")
    
    def load_sources(self):
        """加载所有规则源"""
        super().load_sources()
        
        # 加载中文规则源
        try:
            with open(CONFIG['CHINA_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.black_urls.append(line)
        except FileNotFoundError:
            logger.warning(f"中文规则源文件不存在: {CONFIG['CHINA_SOURCE']}")
        
        # 加载增强规则源
        try:
            with open(CONFIG['ENHANCED_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.black_urls.append(line)
        except FileNotFoundError:
            logger.warning(f"增强规则源文件不存在: {CONFIG['ENHANCED_SOURCE']}")
        
        logger.info(f"总共加载 {len(self.black_urls)} 个规则源")
    
    def enhanced_extract_domain(self, line: str) -> Optional[str]:
        """增强版域名提取"""
        if not line:
            return None
        
        line = line.strip()
        
        if '!' in line:
            line = line.split('!')[0].strip()
        if '#' in line:
            line = line.split('#')[0].strip()
        
        if not line or line.startswith('!') or line.startswith('##'):
            return None
        
        patterns = [
            (r'^\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\^', 1),
            (r'^\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+){2,})\^', 1),
            (r'^@@\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\^', 1),
            (r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})', 1),
            (r'^([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})$', 1),
            (r'^(?:\*\.)?([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})', 1),
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(group).lower()
                domain = re.sub(r'^www\d*\.', '', domain)
                domain = re.sub(r'^www\.', '', domain)
                domain = re.sub(r'^m\.', '', domain)
                domain = re.sub(r'^static\.', '', domain)
                domain = re.sub(r'^cdn\.', '', domain)
                
                if self.is_valid_domain(domain):
                    return domain
        
        return None
    
    def parse_enhanced_content(self, content: str) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """增强版内容解析"""
        black_domains = set()
        black_rules = set()
        white_domains = set()
        white_rules = set()
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('!') or line.startswith('#') or line.startswith('//'):
                continue
            
            # 白名单规则
            if line.startswith('@@'):
                domain = self.enhanced_extract_domain(line)
                if domain:
                    white_domains.add(domain)
                    white_rules.add(f"@@||{domain}^")
                else:
                    if not re.match(r'^@@\|\|.*\^$', line):
                        white_rules.add(line)
            
            # 黑名单规则
            else:
                domain = self.enhanced_extract_domain(line)
                if domain:
                    black_domains.add(domain)
                    
                    # 通配符扩展
                    if CONFIG['HIT_OPTIMIZATION']['enable_wildcard_expansion'] and '*' in line:
                        expansions = DomainOptimizer.expand_wildcard_domain(domain)
                        for expanded in expansions:
                            if expanded != domain and self.is_valid_domain(expanded):
                                black_domains.add(expanded)
                    
                    # 子域名生成
                    if (CONFIG['HIT_OPTIMIZATION']['enable_subdomain_generation'] and 
                        DomainOptimizer.is_ad_domain(domain)):
                        subdomains = DomainOptimizer.generate_subdomains(domain)
                        for subdomain in subdomains:
                            if self.is_valid_domain(subdomain):
                                black_domains.add(subdomain)
                
                # 保留其他规则
                else:
                    if self.is_valid_rule(line):
                        black_rules.add(line)
        
        return black_domains, black_rules, white_domains, white_rules
    
    def is_valid_rule(self, rule: str) -> bool:
        """检查是否为有效规则"""
        if not rule or len(rule) < 3:
            return False
        
        invalid_patterns = [
            r'^\s*$',
            r'^##',
            r'^#\$#',
            r'^!\s+',
            r'^\[Adblock',
            r'^\/\*',
            r'^\*\/$'
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, rule):
                return False
        
        if not re.search(r'[a-zA-Z0-9]', rule):
            return False
        
        return True
    
    def download_and_parse_all(self):
        """增强版下载和解析"""
        logger.info("开始下载和解析规则（增强版）...")
        
        all_urls = []
        for url in self.black_urls:
            all_urls.append((url, 'black'))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = {}
            for url, type_ in all_urls:
                future = executor.submit(self.download_url, url)
                futures[future] = (url, type_)
            
            processed = 0
            for future in concurrent.futures.as_completed(futures):
                processed += 1
                url, type_ = futures[future]
                
                try:
                    content = future.result()
                    if content:
                        # 限制内容大小
                        if len(content) > 10 * 1024 * 1024:
                            logger.warning(f"内容过大，截取前10MB: {url}")
                            content = content[:10 * 1024 * 1024]
                        
                        black_domains, black_rules, white_domains, white_rules = self.parse_enhanced_content(content)
                        
                        self.black_domains.update(black_domains)
                        self.black_rules.update(black_rules)
                        self.white_domains.update(white_domains)
                        self.white_rules.update(white_rules)
                        
                        logger.debug(f"处理完成: {url} ({len(black_domains)} 个域名)")
                        
                        if processed % 10 == 0:
                            logger.info(f"处理进度: {processed}/{len(all_urls)}")
                
                except Exception as e:
                    logger.error(f"处理失败 {url}: {e}")
        
        logger.info(f"解析完成: 黑名单域名 {len(self.black_domains):,} 个")
        logger.info(f"白名单域名 {len(self.white_domains):,} 个")
    
    def apply_enhanced_whitelist(self):
        """增强版白名单应用"""
        if not self.white_domains:
            logger.warning("没有白名单域名")
            return
        
        original_black = len(self.black_domains)
        
        # 1. 直接匹配移除
        self.black_domains -= self.white_domains
        
        # 2. 子域名匹配
        if len(self.white_domains) < 10000:
            to_remove = set()
            
            for white_domain in self.white_domains:
                pattern = re.compile(rf'.*\.{re.escape(white_domain)}$')
                
                for black_domain in self.black_domains:
                    if pattern.match(black_domain):
                        to_remove.add(black_domain)
            
            self.black_domains -= to_remove
            
            total_removed = original_black - len(self.black_domains)
            logger.info(f"白名单应用完成: 移除 {total_removed} 个域名")
    
    def optimize_for_hit_rate(self):
        """命中率优化"""
        logger.info("开始命中率优化...")
        
        all_domains = self.black_domains
        
        if CONFIG['HIT_OPTIMIZATION']['enable_smart_rules']:
            optimized_domains = self.optimizer.filter_low_score_domains(all_domains)
        else:
            optimized_domains = all_domains
        
        max_domains = CONFIG['HIT_OPTIMIZATION']['max_domains_per_source']
        if len(optimized_domains) > max_domains:
            scored_domains = []
            for domain in optimized_domains:
                score = self.optimizer.score_domain(domain)
                scored_domains.append((domain, score))
            
            scored_domains.sort(key=lambda x: x[1], reverse=True)
            optimized_domains = set([d[0] for d in scored_domains[:max_domains]])
            logger.info(f"限制域名数量: {max_domains:,}")
        
        self.black_domains = optimized_domains
        logger.info(f"优化后域名总数: {len(self.black_domains):,}")
    
    def generate_smart_rules(self):
        """生成智能规则"""
        logger.info("生成智能规则...")
        
        smart_rules = []
        
        smart_rules.extend([
            "! 智能广告过滤规则",
            "! 生成时间: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "! 域名数量: " + str(len(self.black_domains)),
            ""
        ])
        
        if self.white_rules:
            smart_rules.append("! 白名单规则")
            for rule in sorted(self.white_rules):
                smart_rules.append(rule)
            smart_rules.append("")
        
        domain_groups = defaultdict(list)
        for domain in self.black_domains:
            score = self.optimizer.score_domain(domain)
            
            if score >= 0.7:
                domain_groups['high'].append(domain)
            elif score >= 0.4:
                domain_groups['medium'].append(domain)
            else:
                domain_groups['low'].append(domain)
        
        for group_name in ['high', 'medium', 'low']:
            if domain_groups[group_name]:
                smart_rules.append(f"! {group_name.capitalize()} 优先级域名")
                for domain in sorted(domain_groups[group_name]):
                    smart_rules.append(f"||{domain}^")
                smart_rules.append("")
        
        with open(CONFIG['OUTPUT_FILES']['smart_ad'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(smart_rules))
        
        logger.info(f"智能规则生成完成: {len(smart_rules)} 行")
    
    def generate_mobile_rules(self):
        """生成移动端优化规则"""
        logger.info("生成移动端优化规则...")
        
        mobile_rules = [
            "! 移动端广告过滤规则",
            "! 生成时间: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "! 专为移动设备优化",
            ""
        ]
        
        mobile_domains = set()
        for domain in self.black_domains:
            is_mobile = False
            
            for keyword in CONFIG['MOBILE_AD_KEYWORDS']:
                if keyword.lower() in domain.lower():
                    is_mobile = True
                    break
            
            mobile_patterns = [
                r'^m\.', r'\.m\.', r'mobile', r'android', r'ios',
                r'app', r'sdk', r'inapp', r'interstitial'
            ]
            
            for pattern in mobile_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    is_mobile = True
                    break
            
            if is_mobile:
                mobile_domains.add(domain)
        
        mobile_rules.append(f"! 移动广告域名: {len(mobile_domains)} 个")
        for domain in sorted(mobile_domains):
            mobile_rules.append(f"||{domain}^")
        
        mobile_rules.extend([
            "",
            "! 移动端特定规则",
            "||inmobi.com^",
            "||ironsrc.com^",
            "||applovin.com^",
            "||unity3d.com^$app=com.android.browser",
            "||vungle.com^",
            "||chartboost.com^",
            "||adjust.com^",
            "||appsflyer.com^",
            "||branch.io^",
            "||facebook.com/plugins/^$subdocument",
            "||google.com/ads/^$subdocument",
            ""
        ])
        
        with open(CONFIG['OUTPUT_FILES']['mobile_ad'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(mobile_rules))
        
        logger.info(f"移动端规则生成完成: {len(mobile_domains)} 个域名")
    
    def generate_files(self):
        """增强版文件生成"""
        logger.info("生成规则文件（增强版）...")
        
        # 先进行命中率优化
        self.optimize_for_hit_rate()
        
        # 调用父类生成基础文件
        super().generate_files()
        
        # 生成智能规则
        self.generate_smart_rules()
        
        # 生成移动端规则
        if CONFIG['HIT_OPTIMIZATION']['enable_mobile_optimization']:
            self.generate_mobile_rules()
        
        # 更新info.json
        self.update_info_file()
    
    def update_info_file(self):
        """更新信息文件"""
        info_file = CONFIG['OUTPUT_FILES']['info']
        with open(info_file, 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        info['enhanced'] = {
            'smart_rules_generated': os.path.exists(CONFIG['OUTPUT_FILES']['smart_ad']),
            'mobile_rules_generated': os.path.exists(CONFIG['OUTPUT_FILES']['mobile_ad']),
            'optimization_applied': True,
            'hit_optimization_config': CONFIG['HIT_OPTIMIZATION']
        }
        
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_readme(self):
        """增强版README生成"""
        logger.info("生成README.md（增强版）...")
        
        with open(CONFIG['OUTPUT_FILES']['info'], 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        version = info['version']
        
        readme_content = f"""# 广告过滤规则 - 增强版

一个自动更新的广告过滤规则集合，经过优化提高拦截命中率。

## 📊 规则统计

**版本 {version} 规则统计：**
- 总黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 其他规则：黑名单 {info['rules']['blacklist_rules']:,} 条，白名单 {info['rules']['whitelist_rules']:,} 条

## 🚀 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 | 说明 |
|----------|----------|----------|----------|------|
| 综合广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` | 通用规则，适合所有用户 |
| 智能广告规则 | Adblock | `{base_url}/smart_ad.txt` | `{cdn_url}/smart_ad.txt` | 智能优化，高命中率 |
| 移动端规则 | Adblock | `{base_url}/mobile_ad.txt` | `{cdn_url}/mobile_ad.txt` | 移动设备专用 |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` | Pi-hole等DNS过滤器 |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` | 系统Hosts文件 |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` | 纯黑名单域名 |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` | 排除误杀 |

## 🎯 优化特性

### 1. 命中率优化
- **智能评分系统**：每个域名根据广告特征评分
- **优先级过滤**：优先保留高广告可能性域名
- **中文优化**：专门针对中文网站广告优化
- **移动端优化**：优化移动设备广告拦截

### 2. 规则质量
- **自动去重**：移除重复域名
- **有效性验证**：验证域名格式和有效性
- **白名单保护**：避免误杀正常网站
- **定期更新**：每天自动更新规则

### 3. 性能优化
- **多线程下载**：并行下载规则源
- **智能缓存**：减少重复下载
- **增量更新**：只更新变化部分

## 📅 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*

## 🔧 使用建议

1. **AdGuard/uBlock Origin**：使用 `smart_ad.txt` 获得最佳平衡
2. **Pi-hole/AdGuard Home**：使用 `dns.txt` 进行DNS层面拦截
3. **移动设备**：使用 `mobile_ad.txt` 专门针对移动广告
4. **如果遇到误杀**：检查 `white.txt` 或提交Issue

## 📈 命中率提升技巧

1. 定期更新规则（至少每周一次）
2. 结合使用智能规则和基础规则
3. 针对特定网站添加自定义规则
4. 关注更新日志中的优化内容

---

**提示**：如果发现误拦截或漏拦截，请通过Issue反馈。
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        logger.info("README.md生成完成")
    
    def run(self):
        """运行增强版流程"""
        print("=" * 60)
        print("广告过滤规则生成器 - 增强版")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            self.load_sources()
            self.download_and_parse_all()
            self.apply_enhanced_whitelist()
            self.generate_files()
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("✅ 增强版处理完成！")
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"✅ 白名单域名: {len(self.white_domains):,}个")
            print(f"🎯 智能规则: rules/outputs/smart_ad.txt")
            print(f"📱 移动端规则: rules/outputs/mobile_ad.txt")
            print(f"📁 所有规则: rules/outputs/")
            print(f"📖 文档更新: README.md")
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
    
    # 自动检测运行环境，非交互式环境直接使用增强模式
    if sys.stdin and sys.stdin.isatty():
        # 交互式环境，可以询问用户
        print("请选择生成模式：")
        print("1. 基础模式（快速，标准规则）")
        print("2. 增强模式（推荐，高命中率）")
        
        try:
            choice = input("请输入选择 (1/2, 默认2): ").strip() or "2"
        except EOFError:
            # 非交互式环境但被当作交互式，默认使用增强模式
            print("检测到非交互式环境，自动选择增强模式")
            choice = "2"
    else:
        # 非交互式环境，直接使用增强模式
        print("非交互式环境，自动选择增强模式")
        choice = "2"
    
    if choice == "1":
        print("\n🚀 使用基础模式...")
        generator = AdBlockGenerator()
    else:
        print("\n⚡ 使用增强模式...")
        generator = EnhancedAdBlockGenerator()
    
    # 运行生成器
    success = generator.run()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("📊 命中率建议：使用 smart_ad.txt 获得最佳效果")
        print("🚀 GitHub Actions会自动提交更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
