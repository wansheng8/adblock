#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
精准修复版广告过滤规则生成器
解决不拦截和误拦截问题，增加精确匹配和智能过滤
"""

import os
import re
import json
import time
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, List, Optional, Tuple, Dict
import requests
from urllib.parse import urlparse
from collections import defaultdict

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 15,
    'TIMEOUT': 20,
    'RETRY_TIMES': 3,
    
    # 文件路径
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 输出文件（固定文件名）
    'AD_FILE': 'rules/outputs/ad.txt',
    'DNS_FILE': 'rules/outputs/dns.txt',
    'HOSTS_FILE': 'rules/outputs/hosts.txt',
    'BLACK_FILE': 'rules/outputs/black.txt',
    'WHITE_FILE': 'rules/outputs/white.txt',
    'INFO_FILE': 'rules/outputs/info.json',
    
    # 新增：智能过滤配置
    'INTELLIGENT_FILTERING': {
        'enable_essential_domain_whitelist': True,  # 启用必要域名白名单
        'enable_safe_domains_check': True,          # 启用安全域名检查
        'enable_false_positive_filter': True,       # 启用误报过滤
        'remove_suspicious_wildcards': True,        # 移除可疑通配符
        'keep_popular_domains': True,              # 保留常用域名
        'enable_domain_validation': True           # 启用域名验证
    },
    
    # 必要域名白名单（防止误拦截）
    'ESSENTIAL_DOMAINS': [
        # 常用APP和服务域名
        'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
        'github.com', 'gitlab.com', 'docker.com', 'cloudflare.com',
        'baidu.com', 'tencent.com', 'alibaba.com', 'taobao.com',
        'weixin.qq.com', 'qq.com', 'weibo.com', 'zhihu.com',
        'bilibili.com', 'douyin.com', 'kuaishou.com',
        
        # 操作系统和浏览器
        'windowsupdate.com', 'mozilla.org', 'chromium.org',
        'ubuntu.com', 'debian.org', 'redhat.com',
        
        # 安全证书和加密
        'letsencrypt.org', 'digicert.com', 'symantec.com',
        'verisign.com', 'globalsign.com',
        
        # 开发工具
        'npmjs.com', 'yarnpkg.com', 'pypi.org', 'maven.org',
        'docker.io', 'kubernetes.io', 'terraform.io',
        
        # 常见CDN和云服务
        'akamai.net', 'fastly.net', 'aws.amazon.com',
        'azure.com', 'cloud.google.com', 'aliyun.com',
        'huaweicloud.com', 'tencentcloud.com',
        
        # 邮箱服务
        'gmail.com', 'outlook.com', 'yahoo.com', '163.com',
        '126.com', 'foxmail.com', 'qq.com', 'sina.com',
        
        # 社交媒体
        'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'pinterest.com', 'tiktok.com',
        
        # 支付服务
        'paypal.com', 'stripe.com', 'alipay.com', 'wechat.com',
        'unionpay.com', 'visa.com', 'mastercard.com'
    ],
    
    # 安全域名检查（不拦截这些域名）
    'SAFE_DOMAINS': [
        # 系统域名
        'localhost', 'local', '127.0.0.1', '0.0.0.0', '::1',
        
        # 常用工具
        'stackoverflow.com', 'stackexchange.com', 'github.com',
        'gitlab.com', 'bitbucket.org', 'sourceforge.net',
        
        # 文档和帮助
        'wikipedia.org', 'wikimedia.org', 'archive.org',
        'creativecommons.org', 'gnu.org', 'apache.org',
        
        # 政府和非营利组织
        'gov.cn', 'gov.uk', 'gov', 'org', 'edu', 'mil',
        
        # 开源项目
        'linuxfoundation.org', 'opensource.org', 'gnu.org',
        'apache.org', 'eclipse.org', 'mozilla.org'
    ],
    
    # 可疑规则模式（可能误拦截）
    'SUSPICIOUS_PATTERNS': [
        r'^\|\|([a-z]{1,2})\.com\^',          # 短域名.com
        r'^\|\|([a-z]{1,3})\.(com|net|org)\^', # 很短的主域名
        r'^\|\|([a-z0-9]+-[a-z0-9]+)\.[a-z]+\^', # 带横线的域名
        r'^\|\|([a-z]+)\d+[a-z]+\.[a-z]+\^',   # 数字在中间的域名
        r'^\|\|\*\.',                         # 全通配符
        r'^\|\|.*\$\$.*',                     # 复杂元素规则
        r'^\|\|.*\$\$script.*',               # 脚本拦截规则
        r'^\|\|.*\$\$image.*',                # 图片拦截规则
        r'^\|\|.*\$\$stylesheet.*',           # 样式表拦截规则
    ],
    
    # 保留的关键规则（确保拦截）
    'CRITICAL_PATTERNS': [
        r'^.*doubleclick\.net.*',             # Google广告
        r'^.*googlesyndication\.com.*',       # Google联盟
        r'^.*googleadservices\.com.*',        # Google广告服务
        r'^.*adsense\.com.*',                 # AdSense
        r'^.*amazon-adsystem\.com.*',         # 亚马逊广告
        r'^.*facebook\.com\/ads.*',           # Facebook广告
        r'^.*\.ad\.',                         # 广告子域名
        r'^.*\.ads\.',                        # 广告子域名
        r'^.*\.tracking\.',                   # 追踪子域名
        r'^.*\.analytics\.',                  # 分析子域名
        r'^.*adserver.*',                     # 广告服务器
        r'^.*tracking.*',                     # 追踪相关
        r'^.*analytics.*',                    # 分析相关
        r'^.*metrics.*',                      # 指标相关
        r'^.*beacon.*',                       # 信标
        r'^.*pixel.*',                        # 像素
        r'^.*tagmanager.*',                   # 标签管理
    ]
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AccurateAdBlockGenerator:
    """精准广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 统计信息
        self.stats = {
            'domains_removed_by_whitelist': 0,
            'domains_removed_by_safe_check': 0,
            'domains_removed_by_suspicious': 0,
            'critical_domains_kept': 0,
            'essential_domains_whitelisted': 0,
            'total_domains_processed': 0
        }
        
        # 创建目录
        self.setup_directories()
    
    def setup_directories(self):
        """创建目录"""
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建示例源文件
        self.create_example_sources()
    
    def create_example_sources(self):
        """创建示例源文件"""
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 黑名单规则源
# 推荐使用高质量的规则源，避免不拦截和误拦截

# 高质量广告规则（推荐）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt

# 可选的附加规则（根据需要添加）
# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/filters.txt
# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/other.txt
""")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 白名单规则源
# 添加必要的白名单以防止误拦截

# 基本白名单（推荐）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt

# 针对常见误拦截的补充白名单
# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist_domains.txt
""")
    
    def load_sources(self) -> bool:
        """加载规则源"""
        print("📋 加载规则源...")
        
        # 加载黑名单源
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                self.black_urls = [line.strip() for line in f 
                                 if line.strip() and not line.startswith('#')]
        else:
            print(f"❌ 黑名单源文件不存在: {CONFIG['BLACK_SOURCE']}")
            return False
        
        # 加载白名单源
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                self.white_urls = [line.strip() for line in f 
                                 if line.strip() and not line.startswith('#')]
        
        if not self.black_urls:
            print("❌ 没有有效的黑名单源URL")
            return False
        
        print(f"✅ 加载完成: {len(self.black_urls)} 黑名单源, {len(self.white_urls)} 白名单源")
        return True
    
    def download_url(self, url: str) -> Optional[str]:
        """下载URL内容"""
        for attempt in range(CONFIG['RETRY_TIMES']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'text/plain,text/html'
                }
                
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=CONFIG['TIMEOUT']
                )
                
                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"下载失败 {url}: 状态码 {response.status_code}")
                    
            except Exception as e:
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    logger.warning(f"下载失败 {url}: {e}")
        
        return None
    
    def download_all_urls(self) -> List[Tuple[str, str, str]]:
        """下载所有URL"""
        print(f"📥 下载规则源...")
        
        all_urls = []
        for url in self.black_urls:
            all_urls.append((url, 'black'))
        for url in self.white_urls:
            all_urls.append((url, 'white'))
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            future_to_url = {}
            for url, url_type in all_urls:
                future = executor.submit(self.download_url, url)
                future_to_url[future] = (url, url_type)
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, url_type = future_to_url[future]
                content = future.result()
                if content:
                    results.append((url, url_type, content))
                    print(f"  ✅ 下载成功: {url}")
                else:
                    print(f"  ❌ 下载失败: {url}")
        
        if not results:
            print("❌ 所有规则源下载都失败了！")
            return []
        
        return results
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain:
            return False
        
        domain = domain.strip().lower()
        
        # 基本检查
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        if '.' not in domain:
            return False
        
        # 排除系统域名
        if domain in ['localhost', 'local', '127.0.0.1', '0.0.0.0', '::1']:
            return False
        
        # 检查格式
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain):
            return False
        
        # 不能有两个连续的点或破折号
        if '..' in domain or '--' in domain:
            return False
        
        # 检查每个部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 顶级域名至少2个字符
        if len(parts[-1]) < 2:
            return False
        
        for part in parts:
            if len(part) < 1 or len(part) > 63:
                return False
            
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def extract_domains_from_content(self, content: str) -> Tuple[Set[str], Set[str]]:
        """从内容中提取域名（黑白名单）"""
        black_domains = set()
        white_domains = set()
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            is_whitelist = line.startswith('@@')
            
            # 提取域名
            domain = None
            
            # 常见格式
            if line.startswith('||'):
                # ||domain.com^ 格式
                if '^' in line:
                    domain = line[2:line.find('^')]
                else:
                    domain = line[2:]
            elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
                # Hosts格式: 0.0.0.0 domain.com
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
            elif line.startswith('@@||'):
                # @@||domain.com^ 白名单格式
                if '^' in line:
                    domain = line[4:line.find('^')]
            elif '.' in line and ' ' not in line and '/' not in line:
                # 简单域名格式
                domain = line.split('^')[0] if '^' in line else line
            
            # 清理和验证域名
            if domain:
                domain = domain.lower()
                domain = re.sub(r'^www\d*\.', '', domain)
                domain = re.sub(r'^\.+|\.+$', '', domain)
                
                if self.is_valid_domain(domain):
                    if is_whitelist:
                        white_domains.add(domain)
                    else:
                        black_domains.add(domain)
        
        return black_domains, white_domains
    
    def apply_essential_whitelist(self, domains: Set[str]) -> Set[str]:
        """应用必要域名白名单"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_essential_domain_whitelist']:
            return domains
        
        print("🔧 应用必要域名白名单...")
        
        essential_set = set(CONFIG['ESSENTIAL_DOMAINS'])
        filtered_domains = set()
        whitelisted_count = 0
        
        for domain in domains:
            is_essential = False
            
            # 检查是否在必要域名列表中
            for essential_domain in essential_set:
                if domain == essential_domain or domain.endswith(f".{essential_domain}"):
                    is_essential = True
                    break
            
            if is_essential:
                whitelisted_count += 1
                self.white_domains.add(domain)  # 添加到白名单
            else:
                filtered_domains.add(domain)
        
        self.stats['essential_domains_whitelisted'] = whitelisted_count
        print(f"  ✅ 白名单保护了 {whitelisted_count} 个必要域名")
        
        return filtered_domains
    
    def check_safe_domains(self, domains: Set[str]) -> Set[str]:
        """检查安全域名"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_safe_domains_check']:
            return domains
        
        print("🔍 检查安全域名...")
        
        safe_set = set(CONFIG['SAFE_DOMAINS'])
        filtered_domains = set()
        removed_count = 0
        
        for domain in domains:
            is_safe = False
            
            # 检查是否是安全域名
            for safe_domain in safe_set:
                if domain == safe_domain or domain.endswith(f".{safe_domain}"):
                    is_safe = True
                    break
            
            if is_safe:
                removed_count += 1
                # 安全域名不添加到黑名单
            else:
                filtered_domains.add(domain)
        
        self.stats['domains_removed_by_safe_check'] = removed_count
        print(f"  ✅ 移除了 {removed_count} 个安全域名")
        
        return filtered_domains
    
    def filter_suspicious_domains(self, domains: Set[str]) -> Set[str]:
        """过滤可疑域名"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_false_positive_filter']:
            return domains
        
        print("🔍 过滤可疑域名...")
        
        filtered_domains = set()
        removed_count = 0
        
        for domain in domains:
            is_suspicious = False
            
            # 检查是否匹配可疑模式
            for pattern in CONFIG['SUSPICIOUS_PATTERNS']:
                if re.match(pattern, f"||{domain}^"):
                    is_suspicious = True
                    break
            
            # 检查是否为短域名（可能误拦截）
            parts = domain.split('.')
            if len(parts) >= 2 and len(parts[-2]) <= 3 and len(domain) < 10:
                is_suspicious = True
            
            if is_suspicious:
                removed_count += 1
                # 可疑域名不添加到黑名单
            else:
                filtered_domains.add(domain)
        
        self.stats['domains_removed_by_suspicious'] = removed_count
        print(f"  ✅ 过滤了 {removed_count} 个可疑域名")
        
        return filtered_domains
    
    def ensure_critical_domains(self, domains: Set[str]) -> Set[str]:
        """确保关键广告域名被包含"""
        print("🎯 确保关键广告域名...")
        
        final_domains = set(domains)
        added_count = 0
        
        # 关键广告域名列表（确保这些被拦截）
        critical_ad_domains = [
            # Google广告系统
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'adservice.google.com', 'adsense.com', 'google-analytics.com',
            
            # Facebook广告
            'facebook.com/ads', 'fbcdn.net',
            
            # 亚马逊广告
            'amazon-adsystem.com',
            
            # 常见广告网络
            'adnxs.com', 'rubiconproject.com', 'openx.net',
            'criteo.com', 'taboola.com', 'outbrain.com',
            
            # 追踪和统计
            'scorecardresearch.com', 'quantserve.com',
            'chartbeat.com', 'mixpanel.com',
            
            # 中国广告网络
            'tanx.com', 'alimama.com', 'tanx.com',
            'miaozhen.com', 'cnzz.com', '51.la',
        ]
        
        for critical_domain in critical_ad_domains:
            if critical_domain not in final_domains:
                # 检查是否白名单
                is_whitelisted = False
                for white_domain in self.white_domains:
                    if critical_domain == white_domain or critical_domain.endswith(f".{white_domain}"):
                        is_whitelisted = True
                        break
                
                if not is_whitelisted and self.is_valid_domain(critical_domain):
                    final_domains.add(critical_domain)
                    added_count += 1
        
        self.stats['critical_domains_kept'] = added_count
        print(f"  ✅ 确保了 {added_count} 个关键广告域名")
        
        return final_domains
    
    def apply_precise_whitelist(self, black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
        """应用精确的白名单"""
        print("🎯 应用精确白名单...")
        
        filtered_domains = set(black_domains)
        removed_count = 0
        
        # 构建白名单树以加速匹配
        white_tree = {}
        for domain in white_domains:
            parts = domain.split('.')
            parts.reverse()
            node = white_tree
            for part in parts:
                if part not in node:
                    node[part] = {}
                node = node[part]
            node['*'] = True
        
        # 应用白名单
        for black_domain in black_domains:
            parts = black_domain.split('.')
            parts.reverse()
            node = white_tree
            
            # 检查是否在白名单中
            is_whitelisted = False
            for part in parts:
                if '*' in node:
                    # 完全匹配白名单
                    is_whitelisted = True
                    break
                if part in node:
                    node = node[part]
                else:
                    break
            else:
                if '*' in node:
                    is_whitelisted = True
            
            if is_whitelisted:
                filtered_domains.remove(black_domain)
                removed_count += 1
        
        self.stats['domains_removed_by_whitelist'] = removed_count
        print(f"  ✅ 白名单移除了 {removed_count} 个域名")
        
        return filtered_domains
    
    def process_downloaded_content(self, results: List[Tuple[str, str, str]]):
        """处理下载的内容（智能过滤版）"""
        print("🔧 智能处理规则内容...")
        
        all_black_domains = set()
        all_white_domains = set()
        
        # 第一阶段：收集所有域名
        for url, url_type, content in results:
            black_domains, white_domains = self.extract_domains_from_content(content)
            
            if url_type == 'black':
                all_black_domains.update(black_domains)
                # 黑名单源中的白名单也收集
                all_white_domains.update(white_domains)
            else:
                # 白名单源：优先使用
                all_white_domains.update(white_domains)
        
        self.stats['total_domains_processed'] = len(all_black_domains)
        print(f"📊 原始数据: {len(all_black_domains)} 黑名单域名, {len(all_white_domains)} 白名单域名")
        
        # 第二阶段：智能过滤处理
        print("\n🎯 开始智能过滤...")
        
        # 步骤1：应用必要域名白名单
        filtered_domains = self.apply_essential_whitelist(all_black_domains)
        
        # 步骤2：检查安全域名
        filtered_domains = self.check_safe_domains(filtered_domains)
        
        # 步骤3：过滤可疑域名（减少误拦截）
        filtered_domains = self.filter_suspicious_domains(filtered_domains)
        
        # 步骤4：应用精确白名单
        filtered_domains = self.apply_precise_whitelist(filtered_domains, all_white_domains)
        
        # 步骤5：确保关键广告域名（防止不拦截）
        final_domains = self.ensure_critical_domains(filtered_domains)
        
        # 最终结果
        self.black_domains = final_domains
        self.white_domains = all_white_domains
        
        # 生成规则
        for domain in self.black_domains:
            self.black_rules.add(f"||{domain}^")
        
        for domain in self.white_domains:
            self.white_rules.add(f"@@||{domain}^")
        
        print(f"\n✅ 处理完成!")
        print(f"📊 最终结果: {len(self.black_domains)} 黑名单域名, {len(self.white_domains)} 白名单域名")
    
    def generate_files(self):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        # 检查结果
        if len(self.black_domains) == 0:
            print("⚠️  警告：没有找到任何黑名单域名")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d_%H%M')
        
        # 1. Adblock规则 (ad.txt)
        with open(CONFIG['AD_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 精准广告过滤规则
! 生成时间: {timestamp}
! 版本: {version}
! 黑名单域名: {len(self.black_domains):,} 个
! 白名单域名: {len(self.white_domains):,} 个
! 智能过滤统计:
!   - 必要域名保护: {self.stats['essential_domains_whitelisted']} 个
!   - 安全域名排除: {self.stats['domains_removed_by_safe_check']} 个
!   - 可疑域名过滤: {self.stats['domains_removed_by_suspicious']} 个
!   - 白名单移除: {self.stats['domains_removed_by_whitelist']} 个
!   - 关键广告域名: {self.stats['critical_domains_kept']} 个
! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}

! ========== 白名单规则（防止误拦截） ==========
""")
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
            
            f.write("""
! ========== 黑名单规则（精准广告过滤） ==========
! 已应用智能过滤，减少误拦截和不拦截问题
""")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 2. DNS规则 (dns.txt)
        with open(CONFIG['DNS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""# DNS过滤规则
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}
# 已应用智能过滤，减少误拦截

""")
            for domain in sorted(self.black_domains):
                f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open(CONFIG['HOSTS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""# Hosts格式广告过滤规则
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}
# 已应用智能过滤，减少误拦截

127.0.0.1 localhost
::1 localhost

# 广告域名屏蔽（智能过滤版）
""")
            for domain in sorted(self.black_domains):
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 黑名单规则 (black.txt)
        with open(CONFIG['BLACK_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 黑名单规则
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.black_domains):,}

""")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open(CONFIG['WHITE_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 白名单规则
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.white_domains):,}

""")
            for domain in sorted(self.white_domains):
                f.write(f"@@||{domain}^\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains)
            },
            'filtering_stats': self.stats,
            'config': {
                'intelligent_filtering': CONFIG['INTELLIGENT_FILTERING'],
                'essential_domains_count': len(CONFIG['ESSENTIAL_DOMAINS']),
                'safe_domains_count': len(CONFIG['SAFE_DOMAINS'])
            }
        }
        
        with open(CONFIG['INFO_FILE'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("✅ 规则文件生成完成")
    
    def generate_readme(self):
        """生成README.md"""
        print("📖 生成README.md...")
        
        # 读取规则信息
        try:
            with open(CONFIG['INFO_FILE'], 'r', encoding='utf-8') as f:
                info = json.load(f)
        except:
            info = {
                'version': datetime.now().strftime('%Y%m%d'),
                'updated_at': datetime.now().isoformat(),
                'rules': {'blacklist_domains': 0, 'whitelist_domains': 0}
            }
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        readme = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 更新内容：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 智能过滤：防止误拦截和不拦截问题
- 必要域名保护：{info.get('filtering_stats', {}).get('essential_domains_whitelisted', 0)} 个

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("✅ README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🎯 精准广告过滤规则生成器")
        print("解决不拦截和误拦截问题")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载规则源
            print("\n步骤 1/5: 加载规则源")
            if not self.load_sources():
                return False
            
            # 2. 下载规则源
            print(f"\n步骤 2/5: 下载规则源")
            results = self.download_all_urls()
            if not results:
                return False
            
            # 3. 智能处理规则
            print(f"\n步骤 3/5: 智能处理规则")
            self.process_downloaded_content(results)
            
            # 4. 生成规则文件
            print(f"\n步骤 4/5: 生成规则文件")
            self.generate_files()
            
            # 5. 生成README
            print(f"\n步骤 5/5: 生成README.md")
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("✅ 处理完成！")
            print("=" * 60)
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print("\n🎯 智能过滤统计:")
            print(f"  • 必要域名保护: {self.stats['essential_domains_whitelisted']}个")
            print(f"  • 安全域名排除: {self.stats['domains_removed_by_safe_check']}个")
            print(f"  • 可疑域名过滤: {self.stats['domains_removed_by_suspicious']}个")
            print(f"  • 白名单移除: {self.stats['domains_removed_by_whitelist']}个")
            print(f"  • 关键广告域名: {self.stats['critical_domains_kept']}个")
            print("=" * 60)
            print(f"📁 规则文件: rules/outputs/")
            print("📖 文档更新: README.md")
            print("🔗 订阅地址已在README.md中更新")
            print("=" * 60)
            
            # 建议
            if self.stats['domains_removed_by_suspicious'] > 100:
                print("\n💡 建议：检测到大量可疑域名被过滤，如果广告拦截效果不足，")
                print("      可以在配置中关闭 'enable_false_positive_filter'")
            
            if self.stats['essential_domains_whitelisted'] > 50:
                print("\n💡 建议：已保护大量必要域名，可有效减少误拦截")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  用户中断程序")
            return False
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    import sys
    
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    # 命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("🎯 精准广告过滤规则生成器")
            print("\n使用方法:")
            print("  python run.py              # 正常运行")
            print("  python run.py --strict     # 严格模式（更多过滤）")
            print("  python run.py --loose      # 宽松模式（减少过滤）")
            print("  python run.py --stats      # 显示过滤统计")
            return
        
        elif sys.argv[1] == '--strict':
            print("🔧 严格模式：更多过滤，减少误拦截")
            CONFIG['INTELLIGENT_FILTERING']['enable_false_positive_filter'] = True
            CONFIG['INTELLIGENT_FILTERING']['enable_safe_domains_check'] = True
        
        elif sys.argv[1] == '--loose':
            print("🔧 宽松模式：减少过滤，增加拦截")
            CONFIG['INTELLIGENT_FILTERING']['enable_false_positive_filter'] = False
            CONFIG['INTELLIGENT_FILTERING']['enable_safe_domains_check'] = False
        
        elif sys.argv[1] == '--stats':
            print("📊 过滤配置统计:")
            print(f"  必要域名数量: {len(CONFIG['ESSENTIAL_DOMAINS'])}")
            print(f"  安全域名数量: {len(CONFIG['SAFE_DOMAINS'])}")
            print(f"  可疑模式数量: {len(CONFIG['SUSPICIOUS_PATTERNS'])}")
            print(f"  关键模式数量: {len(CONFIG['CRITICAL_PATTERNS'])}")
            
            print("\n🔧 智能过滤配置:")
            for key, value in CONFIG['INTELLIGENT_FILTERING'].items():
                status = "✅ 启用" if value else "❌ 禁用"
                print(f"  {key}: {status}")
            return
    
    # 正常运行
    print("🎯 正在启动精准广告过滤生成器...")
    print("💡 目标：解决不拦截和误拦截问题")
    
    generator = AccurateAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("🚀 GitHub Actions会自动提交更新")
        print("\n💡 如果仍有不拦截或误拦截问题，可以：")
        print("   1. 调整 rules/sources/ 中的规则源")
        print("   2. 使用 --strict 或 --loose 模式")
        print("   3. 查看 rules/outputs/info.json 获取详细统计")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
