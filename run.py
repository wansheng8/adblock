#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 增强版
优化规则处理，提高拦截命中率
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

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 10,  # 增加并发数
    'TIMEOUT': 45,      # 增加超时
    'RETRY_TIMES': 5,   # 增加重试次数
    
    # 规则源文件 - 增强版
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    'CHINA_SOURCE': 'rules/sources/china.txt',  # 新增中文广告规则源
    'ENHANCED_SOURCE': 'rules/sources/enhanced.txt',  # 新增增强规则源
    
    # 输出文件
    'OUTPUT_FILES': {
        'ad': 'rules/outputs/ad.txt',
        'dns': 'rules/outputs/dns.txt',
        'hosts': 'rules/outputs/hosts.txt',
        'black': 'rules/outputs/black.txt',
        'white': 'rules/outputs/white.txt',
        'info': 'rules/outputs/info.json',
        'smart_ad': 'rules/outputs/smart_ad.txt',  # 新增智能规则
        'mobile_ad': 'rules/outputs/mobile_ad.txt',  # 新增移动端规则
    },
    
    # 排除的域名
    'EXCLUDE_DOMAINS': [
        'localhost', 'local', 'broadcasthost',
        '127.0.0.1', '0.0.0.0', '::1',
        'ip6-localhost', 'ip6-loopback'
    ],
    
    # 通用顶级域名（避免误杀）
    'TLD_WHITELIST': [
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'cn', 'uk', 'de', 'fr', 'jp', 'ru', 'br', 'in',
        'it', 'ca', 'au', 'es', 'mx', 'kr', 'nl', 'ch',
        'se', 'no', 'fi', 'dk', 'pl', 'be', 'at', 'gr',
        'pt', 'il', 'ie', 'sg', 'hk', 'tw', 'my', 'th',
        'id', 'vn', 'ph', 'tr', 'sa', 'ae', 'eg'
    ],
    
    # 命中率优化配置
    'HIT_OPTIMIZATION': {
        'enable_smart_rules': True,  # 启用智能规则
        'enable_china_focus': True,  # 启用中文网站专注模式
        'enable_mobile_optimization': True,  # 移动端优化
        'min_hit_score': 0.3,  # 最小命中分数阈值
        'max_domains_per_source': 50000,  # 每个源的最大域名数
        'enable_wildcard_expansion': True,  # 通配符扩展
        'enable_subdomain_generation': True,  # 子域名生成
    },
    
    # 中文广告关键词（用于增强匹配）
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
        # 简单的通配符扩展
        if domain.startswith('*.') and domain.count('*') == 1:
            base = domain[2:]  # 移除*.前缀
            expansions.append(base)
            # 添加常见子域名
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
        
        # 检查常见广告域名后缀
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
        
    def analyze_url(self, url: str) -> Dict:
        """分析URL特征"""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        features = {
            'domain': domain,
            'has_ad_keyword': False,
            'has_tracking': False,
            'has_analytics': False,
            'query_params': len(parsed.query) > 0,
            'path_length': len(path),
            'subdomain_count': domain.count('.')
        }
        
        # 检查广告关键词
        ad_patterns = ['ad', 'ads', 'adv', 'advert', 'track', 'analytic', 'pixel', 'beacon']
        for pattern in ad_patterns:
            if pattern in domain or pattern in path or pattern in query:
                features['has_ad_keyword'] = True
                break
        
        # 检查追踪参数
        track_params = ['utm_', 'ref=', 'source=', 'campaign=', 'cid=', 'gclid=']
        for param in track_params:
            if param in query:
                features['has_tracking'] = True
                break
        
        return features
    
    def score_domain(self, domain: str) -> float:
        """给域名评分（越高越可能是广告）"""
        score = 0.0
        
        # 基本特征评分
        if DomainOptimizer.is_ad_domain(domain):
            score += 0.5
        
        # 关键词匹配
        for keyword in CONFIG['CHINESE_AD_KEYWORDS']:
            if keyword.lower() in domain.lower():
                score += 0.3
                break
        
        for keyword in CONFIG['MOBILE_AD_KEYWORDS']:
            if keyword.lower() in domain.lower():
                score += 0.2
                break
        
        # 域名结构评分
        parts = domain.split('.')
        if len(parts) >= 4:  # 多层子域名更可能是广告
            score += 0.2
        
        # 检查数字编号（常见于广告服务器）
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

class EnhancedAdBlockGenerator(AdBlockGenerator):
    """增强版广告过滤规则生成器"""
    
    def __init__(self):
        super().__init__()
        self.optimizer = HitRateOptimizer()
        self.china_domains = set()
        self.enhanced_domains = set()
        
        # 创建额外源文件
        self.setup_enhanced_sources()
    
    def setup_enhanced_sources(self):
        """创建增强源文件"""
        # 中文广告规则源
        if not os.path.exists(CONFIG['CHINA_SOURCE']):
            with open(CONFIG['CHINA_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 中文广告过滤规则源\n")
                f.write("https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt\n")
                f.write("https://easylist-downloads.adblockplus.org/easylistchina.txt\n")
                f.write("https://gitee.com/xinggsf/Adblock-Rule/raw/master/rule.txt\n")
                f.write("https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt\n")
                f.write("https://anti-ad.net/easylist.txt\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ChineseFilter.txt\n")
        
        # 增强规则源
        if not os.path.exists(CONFIG['ENHANCED_SOURCE']):
            with open(CONFIG['ENHANCED_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 增强广告过滤规则源\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt\n")
                f.write("https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt\n")
                f.write("https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt\n")
                f.write("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdBlocked.txt\n")
                f.write("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt\n")
                f.write("https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt\n")
    
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
        
        # 移除注释和多余空格
        if '!' in line:
            line = line.split('!')[0].strip()
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # 跳过空行和特殊规则
        if not line or line.startswith('!') or line.startswith('##'):
            return None
        
        # 处理Adblock规则
        patterns = [
            # 标准域名规则: ||domain.com^
            (r'^\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\^', 1),
            # 带子域: ||sub.domain.com^
            (r'^\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+){2,})\^', 1),
            # 白名单规则: @@||domain.com^
            (r'^@@\|\|([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})\^', 1),
            # Hosts格式: 0.0.0.0 domain.com
            (r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})', 1),
            # 简单域名
            (r'^([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})$', 1),
            # 通配符域名: *.domain.com
            (r'^(?:\*\.)?([a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,})', 1),
            # 包含下划线的域名（虽然不规范但实际存在）
            (r'([a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+\.[a-zA-Z]{2,})', 1),
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(group).lower()
                # 清理域名
                domain = re.sub(r'^www\d*\.', '', domain)
                domain = re.sub(r'^www\.', '', domain)
                domain = re.sub(r'^m\.', '', domain)
                domain = re.sub(r'^static\.', '', domain)
                domain = re.sub(r'^cdn\.', '', domain)
                
                # 验证域名
                if self.is_valid_enhanced_domain(domain):
                    return domain
        
        return None
    
    def is_valid_enhanced_domain(self, domain: str) -> bool:
        """增强版域名验证"""
        if not domain:
            return False
        
        # 排除配置中的域名
        if domain in CONFIG['EXCLUDE_DOMAINS']:
            return False
        
        # 检查长度
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        # 检查是否包含点号
        if '.' not in domain:
            return False
        
        # 检查顶级域名
        parts = domain.split('.')
        tld = parts[-1]
        
        # 跳过太短的TLD（可能是误匹配）
        if len(tld) < 2:
            return False
        
        # 检查是否为公共后缀
        if tld not in CONFIG['TLD_WHITELIST']:
            # 如果是数字TLD（可能是IP），跳过
            if tld.isdigit():
                return False
        
        # 检查每个部分
        for part in parts:
            if len(part) < 1 or len(part) > 63:
                return False
            # 允许字母、数字、连字符，但不能以连字符开头或结尾
            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', part):
                return False
        
        # 额外的广告域名检查
        if not DomainOptimizer.is_ad_domain(domain):
            # 如果不是明显的广告域名，检查是否为有效域名
            # 跳过看起来像路径的字符串
            if '/' in domain or '?' in domain or '&' in domain:
                return False
        
        return True
    
    def parse_enhanced_content(self, content: str, source_type: str = 'black') -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
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
            
            # 跳过注释和空行
            if line.startswith('!') or line.startswith('#') or line.startswith('//'):
                continue
            
            # 白名单规则
            if line.startswith('@@'):
                domain = self.enhanced_extract_domain(line)
                if domain:
                    white_domains.add(domain)
                    white_rules.add(f"@@||{domain}^")
                else:
                    # 保留非域名白名单规则
                    if not re.match(r'^@@\|\|.*\^$', line):
                        white_rules.add(line)
            
            # 黑名单规则
            else:
                # 尝试提取域名
                domain = self.enhanced_extract_domain(line)
                if domain:
                    black_domains.add(domain)
                    
                    # 通配符扩展
                    if CONFIG['HIT_OPTIMIZATION']['enable_wildcard_expansion'] and '*' in line:
                        expansions = DomainOptimizer.expand_wildcard_domain(domain)
                        for expanded in expansions:
                            if expanded != domain and self.is_valid_enhanced_domain(expanded):
                                black_domains.add(expanded)
                    
                    # 子域名生成（针对广告域名）
                    if (CONFIG['HIT_OPTIMIZATION']['enable_subdomain_generation'] and 
                        DomainOptimizer.is_ad_domain(domain)):
                        subdomains = DomainOptimizer.generate_subdomains(domain)
                        for subdomain in subdomains:
                            if self.is_valid_enhanced_domain(subdomain):
                                black_domains.add(subdomain)
                
                # 保留其他规则
                else:
                    # 检查是否为有效规则
                    if self.is_valid_rule(line):
                        black_rules.add(line)
        
        return black_domains, black_rules, white_domains, white_rules
    
    def is_valid_rule(self, rule: str) -> bool:
        """检查是否为有效规则"""
        if not rule or len(rule) < 3:
            return False
        
        # 跳过明显无效的规则
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
        
        # 检查是否包含至少一个字母或数字
        if not re.search(r'[a-zA-Z0-9]', rule):
            return False
        
        return True
    
    def download_and_parse_all(self):
        """增强版下载和解析"""
        logger.info("开始下载和解析规则（增强版）...")
        
        # 准备URL列表
        all_urls = []
        for url in self.black_urls:
            all_urls.append((url, 'black', 'normal'))
        
        # 添加中文源
        try:
            with open(CONFIG['CHINA_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_urls.append((line, 'black', 'china'))
        except:
            pass
        
        # 并发下载
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = {}
            for url, type_, source_category in all_urls:
                future = executor.submit(self.download_url, url)
                futures[future] = (url, type_, source_category)
            
            # 处理结果
            processed = 0
            for future in concurrent.futures.as_completed(futures):
                processed += 1
                url, type_, source_category = futures[future]
                
                try:
                    content = future.result()
                    if content:
                        # 限制内容大小
                        if len(content) > 10 * 1024 * 1024:  # 10MB
                            logger.warning(f"内容过大，截取前10MB: {url}")
                            content = content[:10 * 1024 * 1024]
                        
                        # 解析内容
                        black_domains, black_rules, white_domains, white_rules = self.parse_enhanced_content(content)
                        
                        # 根据来源分类存储
                        if source_category == 'china':
                            self.china_domains.update(black_domains)
                        else:
                            self.black_domains.update(black_domains)
                            self.black_rules.update(black_rules)
                        
                        # 白名单处理
                        self.white_domains.update(white_domains)
                        self.white_rules.update(white_rules)
                        
                        logger.debug(f"处理完成: {url} ({len(black_domains)} 个域名)")
                        
                        # 进度显示
                        if processed % 10 == 0:
                            logger.info(f"处理进度: {processed}/{len(all_urls)}")
                
                except Exception as e:
                    logger.error(f"处理失败 {url}: {e}")
        
        logger.info(f"解析完成: 黑名单域名 {len(self.black_domains):,} 个")
        logger.info(f"中文域名 {len(self.china_domains):,} 个")
        logger.info(f"白名单域名 {len(self.white_domains):,} 个")
    
    def apply_enhanced_whitelist(self):
        """增强版白名单应用"""
        if not self.white_domains:
            logger.warning("没有白名单域名")
            return
        
        original_black = len(self.black_domains)
        original_china = len(self.china_domains)
        
        # 1. 直接匹配移除
        self.black_domains -= self.white_domains
        self.china_domains -= self.white_domains
        
        # 2. 子域名匹配（更精确）
        if len(self.white_domains) < 10000:  # 避免性能问题
            to_remove_black = set()
            to_remove_china = set()
            
            for white_domain in self.white_domains:
                # 构建正则模式，匹配以 .whitedomain 结尾的域名
                pattern = re.compile(rf'.*\.{re.escape(white_domain)}$')
                
                # 检查黑名单
                for black_domain in self.black_domains:
                    if pattern.match(black_domain):
                        to_remove_black.add(black_domain)
                
                # 检查中文域名
                for china_domain in self.china_domains:
                    if pattern.match(china_domain):
                        to_remove_china.add(china_domain)
            
            self.black_domains -= to_remove_black
            self.china_domains -= to_remove_china
            
            total_removed = (original_black + original_china) - (len(self.black_domains) + len(self.china_domains))
            logger.info(f"白名单应用完成: 移除 {total_removed} 个域名")
    
    def optimize_for_hit_rate(self):
        """命中率优化"""
        logger.info("开始命中率优化...")
        
        # 合并所有域名
        all_domains = self.black_domains.union(self.china_domains)
        logger.info(f"合并后域名总数: {len(all_domains):,}")
        
        # 应用命中率优化
        if CONFIG['HIT_OPTIMIZATION']['enable_smart_rules']:
            optimized_domains = self.optimizer.filter_low_score_domains(all_domains)
        else:
            optimized_domains = all_domains
        
        # 限制最大域名数
        max_domains = CONFIG['HIT_OPTIMIZATION']['max_domains_per_source']
        if len(optimized_domains) > max_domains:
            # 优先保留高分域名
            scored_domains = []
            for domain in optimized_domains:
                score = self.optimizer.score_domain(domain)
                scored_domains.append((domain, score))
            
            # 按分数降序排序
            scored_domains.sort(key=lambda x: x[1], reverse=True)
            
            # 取前N个
            optimized_domains = set([d[0] for d in scored_domains[:max_domains]])
            logger.info(f"限制域名数量: {max_domains:,}")
        
        self.black_domains = optimized_domains
        logger.info(f"优化后域名总数: {len(self.black_domains):,}")
    
    def generate_smart_rules(self):
        """生成智能规则"""
        logger.info("生成智能规则...")
        
        # 智能Adblock规则
        smart_rules = []
        
        # 添加基础规则
        smart_rules.extend([
            "! 智能广告过滤规则",
            "! 生成时间: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "! 域名数量: " + str(len(self.black_domains)),
            ""
        ])
        
        # 添加白名单规则
        if self.white_rules:
            smart_rules.append("! 白名单规则")
            for rule in sorted(self.white_rules):
                smart_rules.append(rule)
            smart_rules.append("")
        
        # 按域名类型分组
        domain_groups = defaultdict(list)
        for domain in self.black_domains:
            score = self.optimizer.score_domain(domain)
            
            if score >= 0.7:
                domain_groups['high'].append(domain)
            elif score >= 0.4:
                domain_groups['medium'].append(domain)
            else:
                domain_groups['low'].append(domain)
        
        # 按分组添加规则
        for group_name in ['high', 'medium', 'low']:
            if domain_groups[group_name]:
                smart_rules.append(f"! {group_name.capitalize()} 优先级域名")
                for domain in sorted(domain_groups[group_name]):
                    smart_rules.append(f"||{domain}^")
                smart_rules.append("")
        
        # 保存智能规则
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
        
        # 筛选移动端相关域名
        mobile_domains = set()
        for domain in self.black_domains:
            # 检查是否为移动广告相关
            is_mobile = False
            
            # 检查关键词
            for keyword in CONFIG['MOBILE_AD_KEYWORDS']:
                if keyword.lower() in domain.lower():
                    is_mobile = True
                    break
            
            # 检查常见移动广告模式
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
        
        # 添加移动端专用规则
        mobile_rules.append(f"! 移动广告域名: {len(mobile_domains)} 个")
        for domain in sorted(mobile_domains):
            mobile_rules.append(f"||{domain}^")
        
        # 添加移动端特定规则
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
        
        # 保存移动端规则
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
        
        # 添加增强信息
        info['enhanced'] = {
            'smart_rules_generated': os.path.exists(CONFIG['OUTPUT_FILES']['smart_ad']),
            'mobile_rules_generated': os.path.exists(CONFIG['OUTPUT_FILES']['mobile_ad']),
            'china_domains_count': len(self.china_domains),
            'optimization_applied': True,
            'hit_optimization_config': CONFIG['HIT_OPTIMIZATION']
        }
        
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_readme(self):
        """增强版README生成"""
        logger.info("生成README.md（增强版）...")
        
        # 获取规则信息
        with open(CONFIG['OUTPUT_FILES']['info'], 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        version = info['version']
        
        readme_content = f"""# 广告过滤规则 - 增强版

一个自动更新的广告过滤规则集合，经过优化提高拦截命中率。

## 📊 规则统计

**版本 {version} 规则统计：**
- 总黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 中文广告域名：{info['enhanced']['china_domains_count']:,} 个
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
            # 1. 加载规则源
            self.load_sources()
            
            # 2. 下载和解析规则（增强版）
            self.download_and_parse_all()
            
            # 3. 应用白名单（增强版）
            self.apply_enhanced_whitelist()
            
            # 4. 生成规则文件（增强版）
            self.generate_files()
            
            # 5. 生成README.md（增强版）
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            # 输出统计信息
            print("\n" + "=" * 60)
            print("✅ 增强版处理完成！")
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"🇨🇳 中文域名: {len(self.china_domains):,}个")
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
    
    # 显示模式选择
    print("请选择生成模式：")
    print("1. 基础模式（快速，标准规则）")
    print("2. 增强模式（推荐，高命中率）")
    print("3. 完整模式（最全，但较慢）")
    
    choice = input("请输入选择 (1/2/3, 默认2): ").strip() or "2"
    
    if choice == "1":
        print("\n🚀 使用基础模式...")
        generator = AdBlockGenerator()
    elif choice == "3":
        print("\n🔥 使用完整模式...")
        # 完整模式配置
        CONFIG['HIT_OPTIMIZATION']['enable_smart_rules'] = True
        CONFIG['HIT_OPTIMIZATION']['enable_china_focus'] = True
        CONFIG['HIT_OPTIMIZATION']['enable_mobile_optimization'] = True
        CONFIG['HIT_OPTIMIZATION']['min_hit_score'] = 0.2  # 更低阈值
        CONFIG['MAX_WORKERS'] = 15  # 更多并发
        generator = EnhancedAdBlockGenerator()
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
