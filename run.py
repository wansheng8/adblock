#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 v3.3
修复版 - 完全使用用户自定义源文件，无依赖问题
"""

import os
import sys
import re
import json
import yaml
import time
import logging
import argparse
import hashlib
import threading
from datetime import datetime
from typing import Set, List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path

# 检查并导入依赖
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("❌ 缺少依赖：requests")
    print("请运行：pip install requests urllib3 pyyaml")
    sys.exit(1)

# ============================================
# 配置管理器
# ============================================
class Config:
    """配置管理器"""
    
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self.data = self.load_config()
        self.validate_config()
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            else:
                print(f"⚠️  配置文件不存在: {self.config_path}")
                return self.get_default_config()
        except Exception as e:
            print(f"❌ 加载配置文件失败: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """获取默认配置"""
        return {
            'project': {
                'name': 'adblock-enhanced',
                'version': '3.3.0',
                'description': '智能广告过滤规则生成器',
                'author': 'wansheng8',
                'license': 'MIT'
            },
            'github': {
                'user': 'wansheng8',
                'repo': 'adblock-enhanced',
                'branch': 'main'
            },
            'performance': {
                'max_workers': 10,
                'timeout': 30,
                'retry_times': 3,
                'batch_size': 1000,
                'use_cache': False
            },
            'rules': {
                'backup_sources': {
                    'blacklist': [
                        "https://easylist.to/easylist/easylist.txt",
                        "https://easylist.to/easylist/easyprivacy.txt",
                        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
                    ],
                    'whitelist': [
                        "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt"
                    ]
                },
                'exclude_domains': [
                    'localhost', 'local', 'broadcasthost',
                    '127.0.0.1', '0.0.0.0', '::1'
                ],
                'intelligent_filtering': {
                    'enable_essential_domain_whitelist': True,
                    'enable_safe_domains_check': True,
                    'enable_false_positive_filter': True,
                    'enable_domain_validation': True
                },
                'enhanced_blocking': {
                    'analytics': {'enabled': True},
                    'banner_ads': {'enabled': True},
                    'error_monitoring': {'enabled': True},
                    'element_hiding': {'enabled': True},
                    'script_blocking': {'enabled': True}
                }
            },
            'paths': {
                'sources_dir': 'rules/sources',
                'outputs_dir': 'rules/outputs',
                'logs_dir': 'logs',
                'reports_dir': 'reports',
                'backup_dir': 'backups'
            },
            'network': {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'verify_ssl': True,
                'enable_backup_sources': True
            },
            'monitoring': {
                'log_level': 'INFO',
                'max_log_size_mb': 50,
                'log_retention_days': 30
            }
        }
    
    def validate_config(self):
        """验证配置"""
        # 确保必要的配置项存在
        required = ['github', 'performance', 'paths']
        for section in required:
            if section not in self.data:
                self.data[section] = self.get_default_config()[section]
    
    def get(self, key, default=None):
        """获取配置值"""
        keys = key.split('.')
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value if value is not None else default

# ============================================
# 域名验证器
# ============================================
class DomainValidator:
    """域名验证器"""
    
    def __init__(self, config):
        self.config = config
        self.exclude_domains = set(self.config.get('rules.exclude_domains', []))
        
        # 预编译正则表达式
        self.domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        # 常见顶级域名
        self.common_tlds = {
            'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
            'cn', 'uk', 'de', 'jp', 'fr', 'ru', 'br', 'in',
            'it', 'es', 'mx', 'kr', 'nl', 'ch', 'se', 'no',
            'dk', 'fi', 'pl', 'cz', 'hu', 'ro', 'gr', 'tr',
            'ar', 'cl', 'co', 'pe', 've', 'ec', 'bo', 'py',
            'uy', 'pa', 'cr', 'do', 'gt', 'sv', 'hn', 'ni',
            'pr', 'tt', 'jm', 'bs', 'bz', 'gy', 'sr', 'gf',
            'gp', 'mq', 'ht', 'cu', 'do', 'eu', 'asia', 'xxx',
            'xyz', 'online', 'site', 'top', 'win', 'vip', 'club',
            'shop', 'store', 'tech', 'website', 'space', 'digital',
            'news', 'blog', 'app', 'dev', 'io', 'ai', 'tv', 'me',
            'cc', 'us', 'ca', 'au', 'nz', 'sg', 'hk', 'tw', 'mo'
        }
    
    def validate_domain(self, domain):
        """验证域名有效性"""
        domain = domain.strip().lower()
        
        # 基本检查
        if not domain:
            return False, "空域名"
        
        # 长度检查
        min_len = self.config.get('rules.validation.min_domain_length', 3)
        max_len = self.config.get('rules.validation.max_domain_length', 253)
        
        if len(domain) < min_len:
            return False, f"域名太短 (min: {min_len})"
        if len(domain) > max_len:
            return False, f"域名太长 (max: {max_len})"
        
        # 检查排除列表
        if domain in self.exclude_domains:
            return False, "排除的域名"
        
        # 检查是否为IP地址
        if self._is_ip_address(domain):
            return False, "IP地址"
        
        # 正则表达式验证
        if not self.domain_pattern.match(domain):
            return False, "格式无效"
        
        # 检查TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False, "缺少TLD"
        
        tld = parts[-1]
        min_tld_len = self.config.get('rules.validation.min_tld_length', 2)
        if len(tld) < min_tld_len:
            return False, f"TLD太短 (min: {min_tld_len})"
        
        # 验证TLD（可选）
        if self.config.get('rules.validation.validate_tld', False):
            if not self._validate_tld(tld):
                return False, "无效的TLD"
        
        # 检查是否有连续的dot
        if '..' in domain:
            return False, "连续的dot"
        
        # 检查部分是否以连字符开头或结尾
        for part in parts:
            if part.startswith('-') or part.endswith('-'):
                return False, "部分以连字符开头或结尾"
            if len(part) > 63:
                return False, "部分太长"
            
            # 检查特殊字符
            if not self.config.get('rules.validation.allow_underscores', False):
                if '_' in part:
                    return False, "包含下划线"
        
        return True, "有效"
    
    def _is_ip_address(self, domain):
        """检查是否为IP地址"""
        # IPv4
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            parts = domain.split('.')
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        # IPv6简化检查
        if ':' in domain:
            return True
        
        return False
    
    def _validate_tld(self, tld):
        """验证顶级域名"""
        return tld in self.common_tlds
    
    def normalize_domain(self, domain):
        """标准化域名"""
        domain = domain.strip().lower()
        
        # 移除协议
        if '://' in domain:
            try:
                parsed = urlparse(domain)
                if parsed.netloc:
                    domain = parsed.netloc
                elif parsed.path:
                    domain = parsed.path
            except:
                pass
        
        # 移除端口
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 移除www前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 移除末尾的点
        domain = domain.rstrip('.')
        
        # 移除查询参数和路径
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return domain

# ============================================
# 网络管理器
# ============================================
class NetworkManager:
    """网络管理器"""
    
    def __init__(self, config):
        self.config = config
        self.session = self._create_session()
        self.cache = {}
        self.cache_lock = threading.Lock()
    
    def _create_session(self):
        """创建HTTP会话"""
        session = requests.Session()
        
        # 重试策略
        retry_strategy = Retry(
            total=self.config.get('performance.retry_times', 3),
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置请求头
        session.headers.update({
            'User-Agent': self.config.get('network.user_agent', 'AdBlockGenerator/3.3'),
            'Accept': 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': self.config.get('network.accept_encoding', 'gzip, deflate'),
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        
        return session
    
    def fetch_url(self, url, timeout=30):
        """获取URL内容"""
        try:
            response = self.session.get(
                url,
                timeout=timeout,
                verify=self.config.get('network.verify_ssl', True)
            )
            
            response.raise_for_status()
            
            # 检查内容是否有效
            if response.text and len(response.text) > 50:
                return response.text
            else:
                logging.warning(f"URL内容过短或为空: {url}")
                return None
                
        except requests.RequestException as e:
            logging.warning(f"获取URL失败 {url}: {e}")
            return None
    
    def fetch_multiple_urls(self, urls, max_workers=10):
        """批量获取URL"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.fetch_url, url): url
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    results[url] = content
                except Exception as e:
                    logging.error(f"批量获取失败 {url}: {e}")
                    results[url] = None
        
        return results

# ============================================
# 文件管理器
# ============================================
class FileManager:
    """文件管理器"""
    
    def __init__(self, config):
        self.config = config
        self._setup_directories()
    
    def _setup_directories(self):
        """设置目录结构"""
        directories = [
            self.config.get('paths.sources_dir'),
            self.config.get('paths.outputs_dir'),
            self.config.get('paths.logs_dir'),
            self.config.get('paths.reports_dir'),
            self.config.get('paths.backup_dir'),
        ]
        
        for directory in directories:
            if directory:
                os.makedirs(directory, exist_ok=True)
    
    def read_source_file(self, filename):
        """读取源文件"""
        try:
            sources_dir = self.config.get('paths.sources_dir', 'rules/sources')
            filepath = os.path.join(sources_dir, filename)
            
            if not os.path.exists(filepath):
                logging.warning(f"源文件不存在: {filepath}")
                return []
            
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        lines.append(line)
                return lines
                
        except Exception as e:
            logging.error(f"读取源文件失败 {filename}: {e}")
            return []
    
    def save_file(self, filename, content, subdir='outputs'):
        """保存文件"""
        try:
            if subdir == 'outputs':
                base_dir = self.config.get('paths.outputs_dir', 'rules/outputs')
            elif subdir == 'reports':
                base_dir = self.config.get('paths.reports_dir', 'reports')
            else:
                base_dir = subdir
            
            filepath = os.path.join(base_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logging.info(f"保存文件: {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"保存文件失败 {filename}: {e}")
            return False
    
    def get_file_size(self, filename):
        """获取文件大小"""
        try:
            base_dir = self.config.get('paths.outputs_dir', 'rules/outputs')
            filepath = os.path.join(base_dir, filename)
            
            if os.path.exists(filepath):
                return os.path.getsize(filepath)
            else:
                return 0
        except:
            return 0

# ============================================
# 规则处理器
# ============================================
class RuleProcessor:
    """规则处理器"""
    
    def __init__(self, config, validator):
        self.config = config
        self.validator = validator
        
        # 统计信息
        self.stats = {
            'total_processed': 0,
            'valid_domains': 0,
            'invalid_domains': 0,
            'removed_by_whitelist': 0,
            'removed_by_safe_check': 0,
            'removed_by_suspicious': 0,
            'added_by_enhancement': 0,
            'whitelist_domains': 0,
            'element_hiding_rules': 0,
            'script_blocking_rules': 0
        }
        
        # 存储
        self.black_domains = set()
        self.white_domains = set()
        self.enhanced_domains = set()
        self.element_hiding_rules = set()
        self.script_blocking_rules = set()
        
        # 加载内置规则
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """加载内置规则"""
        # 内置分析工具域名
        self.analytics_domains = {
            'google-analytics.com', 'googletagmanager.com',
            'doubleclick.net', 'googlesyndication.com',
            'googleadservices.com', 'adservice.google.com',
            'facebook.com', 'fbcdn.net', 'twitter.com',
            'yandex.ru', 'yandex.net', 'mc.yandex.ru',
            'hotjar.com', 'mouseflow.com', 'crazyegg.com',
            'sentry.io', 'bugsnag.com', 'newrelic.com',
            'matomo.org', 'piwik.org', 'statcounter.com'
        }
        
        # 内置广告网络
        self.ad_networks = {
            'adnxs.com', 'rubiconproject.com', 'criteo.com',
            'taboola.com', 'outbrain.com', 'revcontent.com',
            'amazon-adsystem.com', 'adsrvr.org', 'pubmatic.com',
            'openx.net', 'indexexchange.com', 'sonobi.com',
            'sharethrough.com', 'triplelift.com', 'mgid.com'
        }
        
        # 内置白名单域名（防止误拦截）
        self.essential_domains = {
            'google.com', 'github.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'cloudflare.com', 'baidu.com', 'tencent.com',
            'alibaba.com', 'stackoverflow.com', 'wikipedia.org',
            'gitlab.com', 'docker.com', 'npmjs.com', 'pypi.org',
            'ubuntu.com', 'debian.org', 'apache.org', 'mozilla.org'
        }
        
        # 内置元素隐藏规则
        self.builtin_element_hiding_rules = [
            '##div[class*="ad-"]',
            '##div[id*="ad-"]',
            '##div[class*="banner"]',
            '##div[id*="banner"]',
            '##div[class*="advert"]',
            '##div[id*="advert"]',
            '##div[class*="sponsor"]',
            '##div[id*="sponsor"]',
            '##div[class*="promo"]',
            '##div[id*="promo"]',
            '##iframe[src*="ad"]',
            '##iframe[src*="banner"]',
            '##img[src*="ad"]',
            '##img[alt*="广告"]',
            '##.ad-banner',
            '##.adsbygoogle',
            '##.ad-unit',
            '##.ad-container',
            '##.ad-wrapper'
        ]
        
        # 内置脚本拦截规则
        self.builtin_script_blocking_rules = [
            r'analytics\.js',
            r'ga\.js',
            r'gtm\.js',
            r'stats\.js',
            r'track\.js',
            r'beacon\.js',
            r'pixel\.js'
        ]
    
    def extract_domain_from_line(self, line):
        """从规则行中提取域名"""
        line = line.strip()
        
        # 跳过注释和空行
        if not line or line.startswith(('#', '!', '//')):
            return None, False
        
        is_whitelist = line.startswith('@@')
        if is_whitelist:
            line = line[2:]
        
        domain = None
        
        # 处理不同格式的规则
        patterns = [
            # ||domain.com^ 格式
            (r'^\|\|([^\^]+)\^', 1),
            # domain.com^ 格式
            (r'^([^\^]+)\^', 1),
            # 0.0.0.0 domain.com 格式
            (r'^0\.0\.0\.0\s+([^\s]+)', 1),
            # 127.0.0.1 domain.com 格式
            (r'^127\.0\.0\.1\s+([^\s]+)', 1),
            # :: domain.com 格式 (IPv6)
            (r'^::\s+([^\s]+)', 1),
            # 纯域名格式
            (r'^([a-zA-Z0-9.-]+)$', 1),
            # 带有通配符的格式
            (r'^\|\|([^*\^]+)\^', 1),
            # 特殊格式
            (r'^\|\|([^\^]+)\^\$?', 1),
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(group)
                break
        
        if domain:
            # 标准化域名
            domain = self.validator.normalize_domain(domain)
            
            # 验证域名
            is_valid, _ = self.validator.validate_domain(domain)
            if is_valid:
                return domain, is_whitelist
        
        return None, False
    
    def process_content(self, content, source_type='black'):
        """处理规则内容"""
        domains = set()
        lines = content.split('\n')
        
        for line in lines:
            domain, is_whitelist = self.extract_domain_from_line(line)
            if domain:
                self.stats['total_processed'] += 1
                if is_whitelist:
                    self.white_domains.add(domain)
                    self.stats['whitelist_domains'] += 1
                else:
                    domains.add(domain)
                    self.stats['valid_domains'] += 1
            else:
                self.stats['invalid_domains'] += 1
        
        return domains
    
    def apply_intelligent_filtering(self, domains, mode='normal'):
        """应用智能过滤"""
        filtered = set(domains)
        
        # 1. 应用白名单
        filtered = self._apply_whitelist(filtered)
        
        # 2. 应用必要域名白名单
        if self.config.get('rules.intelligent_filtering.enable_essential_domain_whitelist', True):
            filtered = self._apply_essential_whitelist(filtered)
        
        # 3. 安全域名检查
        if self.config.get('rules.intelligent_filtering.enable_safe_domains_check', True):
            filtered = self._filter_safe_domains(filtered)
        
        # 4. 误报过滤
        if self.config.get('rules.intelligent_filtering.enable_false_positive_filter', True):
            filtered = self._filter_false_positives(filtered)
        
        # 5. 域名验证
        if self.config.get('rules.intelligent_filtering.enable_domain_validation', True):
            filtered = self._validate_domains(filtered)
        
        # 6. 增强拦截
        if mode == 'enhanced':
            filtered = self._enhance_blocking(filtered)
        
        return filtered
    
    def _apply_whitelist(self, domains):
        """应用白名单"""
        filtered = set()
        removed = 0
        
        for domain in domains:
            is_whitelisted = False
            
            # 检查精确匹配
            if domain in self.white_domains:
                is_whitelisted = True
            else:
                # 检查子域名匹配
                for white_domain in self.white_domains:
                    if domain.endswith(f'.{white_domain}'):
                        is_whitelisted = True
                        break
            
            if not is_whitelisted:
                filtered.add(domain)
            else:
                removed += 1
        
        self.stats['removed_by_whitelist'] = removed
        return filtered
    
    def _apply_essential_whitelist(self, domains):
        """应用必要域名白名单"""
        filtered = set()
        removed = 0
        
        for domain in domains:
            is_essential = False
            
            # 检查是否为必要域名
            for essential_domain in self.essential_domains:
                if domain == essential_domain or domain.endswith(f'.{essential_domain}'):
                    is_essential = True
                    break
            
            if not is_essential:
                filtered.add(domain)
            else:
                removed += 1
                # 添加到白名单
                self.white_domains.add(domain)
        
        self.stats['removed_by_safe_check'] = removed
        return filtered
    
    def _filter_safe_domains(self, domains):
        """过滤安全域名"""
        filtered = set()
        removed = 0
        
        # 安全域名模式
        safe_patterns = [
            r'^[a-z]{1,2}\.(com|net|org)$',  # 超短域名
            r'^[a-z0-9-]+\.(gov|edu|mil|int)$',  # 政府/教育
            r'^localhost(\.[a-z]+)?$',  # localhost相关
        ]
        
        for domain in domains:
            is_safe = False
            
            for pattern in safe_patterns:
                if re.match(pattern, domain):
                    is_safe = True
                    break
            
            # 检查是否为知名开源项目
            open_source_domains = {
                'apache.org', 'mozilla.org', 'gnu.org', 'kernel.org',
                'python.org', 'nodejs.org', 'golang.org', 'rust-lang.org'
            }
            
            if any(domain == d or domain.endswith(f'.{d}') for d in open_source_domains):
                is_safe = True
            
            if not is_safe:
                filtered.add(domain)
            else:
                removed += 1
        
        self.stats['removed_by_safe_check'] += removed
        return filtered
    
    def _filter_false_positives(self, domains):
        """过滤误报"""
        filtered = set()
        removed = 0
        
        # 可疑域名模式
        suspicious_patterns = [
            r'^[a-z]{1,2}\d+[a-z]+\.[a-z]+$',  # 短域名带数字
            r'^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]+$',  # 多个连字符
            r'^\d+[a-z]+\.[a-z]+$',  # 以数字开头
        ]
        
        for domain in domains:
            is_suspicious = False
            
            for pattern in suspicious_patterns:
                if re.match(pattern, domain):
                    is_suspicious = True
                    break
            
            # 检查域名长度
            if len(domain) < 5:  # 非常短的域名
                is_suspicious = True
            
            # 检查奇怪的TLD组合
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                if len(tld) > 6:  # 非常长的TLD
                    is_suspicious = True
            
            if not is_suspicious:
                filtered.add(domain)
            else:
                removed += 1
        
        self.stats['removed_by_suspicious'] = removed
        return filtered
    
    def _validate_domains(self, domains):
        """验证域名"""
        filtered = set()
        
        for domain in domains:
            is_valid, _ = self.validator.validate_domain(domain)
            if is_valid:
                filtered.add(domain)
        
        return filtered
    
    def _enhance_blocking(self, domains):
        """增强拦截"""
        enhanced = set(domains)
        added = 0
        
        # 添加分析工具域名
        if self.config.get('rules.enhanced_blocking.analytics.enabled', True):
            for domain in self.analytics_domains:
                if domain not in enhanced:
                    is_valid, _ = self.validator.validate_domain(domain)
                    if is_valid:
                        enhanced.add(domain)
                        added += 1
        
        # 添加广告网络域名
        if self.config.get('rules.enhanced_blocking.banner_ads.enabled', True):
            for domain in self.ad_networks:
                if domain not in enhanced:
                    is_valid, _ = self.validator.validate_domain(domain)
                    if is_valid:
                        enhanced.add(domain)
                        added += 1
        
        # 生成元素隐藏规则
        if self.config.get('rules.enhanced_blocking.element_hiding.enabled', True):
            self.element_hiding_rules.update(self.builtin_element_hiding_rules)
            self.stats['element_hiding_rules'] = len(self.element_hiding_rules)
        
        # 生成脚本拦截规则
        if self.config.get('rules.enhanced_blocking.script_blocking.enabled', True):
            for pattern in self.builtin_script_blocking_rules:
                rule = f"||*{pattern}$script,important"
                self.script_blocking_rules.add(rule)
            self.stats['script_blocking_rules'] = len(self.script_blocking_rules)
        
        self.stats['added_by_enhancement'] = added
        return enhanced

# ============================================
# 主生成器
# ============================================
class AdBlockGenerator:
    """广告过滤规则生成器主类"""
    
    def __init__(self, config_path="config.yaml"):
        # 初始化组件
        self.config = Config(config_path)
        self.validator = DomainValidator(self.config)
        self.network = NetworkManager(self.config)
        self.processor = RuleProcessor(self.config, self.validator)
        self.files = FileManager(self.config)
        
        # 设置日志
        self._setup_logging()
        
        # 状态
        self.black_sources = []
        self.white_sources = []
        
        # 版本信息
        self.version = self.config.get('project.version', '3.3.0')
        self.build_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def _setup_logging(self):
        """设置日志"""
        log_level = self.config.get('monitoring.log_level', 'INFO').upper()
        log_file = self.config.get('paths.error_log', 'logs/error.log')
        
        # 创建日志目录
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # 配置日志
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def load_sources_from_files(self):
        """从文件加载规则源"""
        print("📋 从文件加载规则源...")
        
        # 读取用户自定义源文件
        black_sources = self.files.read_source_file('black.txt')
        white_sources = self.files.read_source_file('white.txt')
        
        # 检查是否有源
        if not black_sources:
            print("⚠️  黑名单源文件为空或不存在")
        else:
            print(f"📄 从 black.txt 读取了 {len(black_sources)} 个源")
        
        if not white_sources:
            print("⚠️  白名单源文件为空或不存在")
        else:
            print(f"📄 从 white.txt 读取了 {len(white_sources)} 个源")
        
        # 如果需要，添加备用源
        if not black_sources and self.config.get('network.enable_backup_sources', True):
            print("📦 使用内置备用黑名单源")
            black_sources = self.config.get('rules.backup_sources.blacklist', [])
        
        if not white_sources and self.config.get('network.enable_backup_sources', True):
            print("📦 使用内置备用白名单源")
            white_sources = self.config.get('rules.backup_sources.whitelist', [])
        
        self.black_sources = black_sources
        self.white_sources = white_sources
        
        print(f"✅ 总共加载了 {len(self.black_sources)} 个黑名单源和 {len(self.white_sources)} 个白名单源")
        return True
    
    def download_sources(self):
        """下载规则源"""
        print("📥 下载规则源...")
        
        # 合并所有URL
        all_urls = list(set(self.black_sources + self.white_sources))
        
        if not all_urls:
            print("❌ 没有可下载的源")
            return [], []
        
        print(f"🌐 开始下载 {len(all_urls)} 个源...")
        
        results = self.network.fetch_multiple_urls(
            all_urls,
            max_workers=self.config.get('performance.max_workers', 10)
        )
        
        # 分离结果
        black_content = []
        white_content = []
        
        successful_black = 0
        successful_white = 0
        
        for url in self.black_sources:
            if url in results and results[url]:
                black_content.append((url, results[url]))
                successful_black += 1
                print(f"  ✅ {url}")
            else:
                print(f"  ❌ {url}")
        
        for url in self.white_sources:
            if url in results and results[url]:
                white_content.append((url, results[url]))
                successful_white += 1
                print(f"  ✅ {url}")
            else:
                print(f"  ❌ {url}")
        
        print(f"📊 下载完成: {successful_black}/{len(self.black_sources)} 黑名单源成功, {successful_white}/{len(self.white_sources)} 白名单源成功")
        
        # 如果没有成功的源，使用内置规则
        if successful_black == 0:
            print("⚠️  所有黑名单源都失败了，使用内置规则")
            black_content = [("内置规则", self._get_builtin_rules())]
        
        return black_content, white_content
    
    def _get_builtin_rules(self):
        """获取内置规则"""
        return """
# 内置广告过滤规则
||doubleclick.net^
||googlesyndication.com^
||googleadservices.com^
||adservice.google.com^
||facebook.com^$third-party
||twitter.com^$third-party
||analytics.google.com^
||stats.g.doubleclick.net^
||adnxs.com^
||rubiconproject.com^
||criteo.com^
||taboola.com^
||outbrain.com^
||revcontent.com^
||amazon-adsystem.com^
||adsrvr.org^
||pubmatic.com^
||openx.net^
||indexexchange.com^
||sonobi.com^
||sharethrough.com^
||triplelift.com^
||mgid.com^
||zemanta.com^
||content.ad^
||adblade.com^
||adbrite.com^
||adform.com^
||adition.com^
||casalemedia.com^
||contextweb.com^
||conversantmedia.com^
||districtm.io^
||eyereturn.com^
||getclicky.com^
||imrworldwide.com^
||infolinks.com^
||innovid.com^
||ipinyou.com^
||kargo.com^
||kiosked.com^
||lijit.com^
||linksynergy.com^
||media.net^
||mediamath.com^
||meetrics.net^
||mopub.com^
||pulpix.com^
||quantserve.com^
||sovrn.com^
||spotxchange.com^
||teads.tv^
||telaria.com^
||tremorhub.com^
||truex.com^
||undertone.com^
||unruly.co^
||videologygroup.com^
||yieldmo.com^
||yieldone.com^
||yldmgrimg.net^
"""
    
    def process_sources(self, black_content, white_content, mode='normal'):
        """处理规则源"""
        print("🔧 处理规则源...")
        
        # 处理黑名单
        all_black_domains = set()
        for url, content in black_content:
            domains = self.processor.process_content(content, 'black')
            all_black_domains.update(domains)
        
        # 处理白名单
        for url, content in white_content:
            self.processor.process_content(content, 'white')
        
        print(f"📊 原始数据: {len(all_black_domains)} 黑名单域名, {len(self.processor.white_domains)} 白名单域名")
        
        # 应用过滤
        filtered_domains = self.processor.apply_intelligent_filtering(all_black_domains, mode)
        
        # 更新统计
        self.processor.black_domains = all_black_domains
        self.processor.enhanced_domains = filtered_domains
        
        print(f"✅ 处理完成: {len(filtered_domains)} 个过滤后域名")
        return filtered_domains
    
    def generate_files(self, domains, mode='normal'):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 生成各种格式的文件
        files_to_generate = [
            ('ad.txt', self._generate_adblock_rules(domains, timestamp, mode)),
            ('dns.txt', self._generate_dns_rules(domains, timestamp)),
            ('hosts.txt', self._generate_hosts_rules(domains, timestamp)),
            ('black.txt', self._generate_black_rules(domains, timestamp)),
            ('white.txt', self._generate_white_rules(timestamp)),
            ('enhanced.txt', self._generate_enhanced_rules(domains, timestamp, mode)),
            ('info.json', self._generate_info_file(domains, timestamp, mode)),
        ]
        
        success = True
        for filename, content in files_to_generate:
            if not self.files.save_file(filename, content):
                success = False
            else:
                print(f"  ✅ 生成 {filename}")
        
        if success:
            print("✅ 所有规则文件生成完成")
        
        return success
    
    def _generate_adblock_rules(self, domains, timestamp, mode):
        """生成Adblock规则"""
        lines = [
            f"! 广告过滤规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 模式: {mode}",
            f"! 域名数量: {len(domains)}",
            f"! 白名单域名: {len(self.processor.white_domains)}",
            f"! 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "!",
            "! ========== 白名单规则 =========="
        ]
        
        # 白名单规则
        for domain in sorted(self.processor.white_domains):
            lines.append(f"@@||{domain}^")
        
        # 元素隐藏规则
        if self.processor.element_hiding_rules:
            lines.extend([
                "!",
                "! ========== 元素隐藏规则 =========="
            ])
            for rule in sorted(self.processor.element_hiding_rules):
                lines.append(rule)
        
        # 脚本拦截规则
        if self.processor.script_blocking_rules:
            lines.extend([
                "!",
                "! ========== 脚本拦截规则 =========="
            ])
            for rule in sorted(self.processor.script_blocking_rules):
                lines.append(rule)
        
        lines.extend([
            "!",
            "! ========== 黑名单规则 =========="
        ])
        
        # 黑名单规则
        for domain in sorted(domains):
            lines.append(f"||{domain}^")
        
        return '\n'.join(lines)
    
    def _generate_dns_rules(self, domains, timestamp):
        """生成DNS规则"""
        lines = [
            f"# DNS过滤规则 v{self.version}",
            f"# 生成时间: {timestamp}",
            f"# 域名数量: {len(domains)}",
            f"# 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "#"
        ]
        
        for domain in sorted(domains):
            lines.append(domain)
        
        return '\n'.join(lines)
    
    def _generate_hosts_rules(self, domains, timestamp):
        """生成Hosts规则"""
        lines = [
            f"# Hosts格式广告过滤规则 v{self.version}",
            f"# 生成时间: {timestamp}",
            f"# 域名数量: {len(domains)}",
            f"# 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "#",
            "127.0.0.1 localhost",
            "::1 localhost",
            "# 广告域名屏蔽",
            ""
        ]
        
        for domain in sorted(domains):
            lines.append(f"0.0.0.0 {domain}")
        
        return '\n'.join(lines)
    
    def _generate_black_rules(self, domains, timestamp):
        """生成黑名单规则"""
        lines = [
            f"! 黑名单规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 域名数量: {len(domains)}",
            f"! 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "!"
        ]
        
        for domain in sorted(domains):
            lines.append(f"||{domain}^")
        
        return '\n'.join(lines)
    
    def _generate_white_rules(self, timestamp):
        """生成白名单规则"""
        lines = [
            f"! 白名单规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 域名数量: {len(self.processor.white_domains)}",
            f"! 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "!"
        ]
        
        for domain in sorted(self.processor.white_domains):
            lines.append(f"@@||{domain}^")
        
        return '\n'.join(lines)
    
    def _generate_enhanced_rules(self, domains, timestamp, mode):
        """生成增强规则"""
        lines = [
            f"! 增强广告过滤规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 模式: {mode}",
            f"! 增强拦截域名: {len(domains)}",
            f"! 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "!",
            "! ========== 增强拦截规则 =========="
        ]
        
        # 统计增强拦截的域名
        enhanced_count = 0
        for domain in sorted(domains):
            # 检查是否为增强拦截的域名
            if (domain in self.processor.analytics_domains or 
                domain in self.processor.ad_networks):
                lines.append(f"||{domain}^$third-party,important")
                enhanced_count += 1
        
        # 添加增强拦截统计
        lines.insert(3, f"! 增强拦截域名: {enhanced_count}")
        
        return '\n'.join(lines)
    
    def _generate_info_file(self, domains, timestamp, mode):
        """生成信息文件"""
        info = {
            'version': self.version,
            'build_date': self.build_date,
            'timestamp': timestamp,
            'mode': mode,
            'stats': self.processor.stats,
            'counts': {
                'blacklist': len(self.processor.black_domains),
                'whitelist': len(self.processor.white_domains),
                'filtered': len(domains),
                'enhanced_added': self.processor.stats['added_by_enhancement']
            },
            'github': {
                'user': self.config.get('github.user'),
                'repo': self.config.get('github.repo'),
                'branch': self.config.get('github.branch')
            },
            'sources': {
                'blacklist_count': len(self.black_sources),
                'whitelist_count': len(self.white_sources),
                'blacklist_sources': self.black_sources,
                'whitelist_sources': self.white_sources
            }
        }
        
        return json.dumps(info, indent=2, ensure_ascii=False)
    
    def generate_reports(self, domains, mode):
        """生成报告"""
        if not self.config.get('reports.generate_detailed_report', True):
            return
        
        print("📊 生成报告...")
        
        # 详细报告
        detailed_report = {
            'generated_at': datetime.now().isoformat(),
            'version': self.version,
            'mode': mode,
            'statistics': self.processor.stats,
            'domain_counts': {
                'total_blacklist': len(self.processor.black_domains),
                'total_whitelist': len(self.processor.white_domains),
                'filtered': len(domains)
            },
            'sources': {
                'blacklist': self.black_sources,
                'whitelist': self.white_sources
            },
            'top_domains': list(sorted(domains))[:50] if domains else []
        }
        
        self.files.save_file('detailed_report.json', json.dumps(detailed_report, indent=2, ensure_ascii=False), 'reports')
        print("  ✅ 生成详细报告")
    
    def generate_readme(self, domains):
        """生成README.md"""
        base_url = f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{self.config.get('github.user')}/{self.config.get('github.repo')}@{self.config.get('github.branch')}"
        
        readme = f"""# 广告过滤规则 v{self.version}

一个精准的广告过滤规则集合，自动更新维护，适用于各种广告拦截器、DNS过滤器和Hosts文件。

## 📊 统计数据

- **黑名单域名**: {len(self.processor.black_domains):,}
- **白名单域名**: {len(self.processor.white_domains):,}
- **过滤后域名**: {len(domains):,}
- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **版本**: {self.version}

## 📥 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/rules/outputs/ad.txt` | `{cdn_url}/rules/outputs/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/rules/outputs/dns.txt` | `{cdn_url}/rules/outputs/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/rules/outputs/hosts.txt` | `{cdn_url}/rules/outputs/hosts.txt` |
| 增强过滤规则 | Enhanced | `{base_url}/rules/outputs/enhanced.txt` | `{cdn_url}/rules/outputs/enhanced.txt` |
| 黑名单规则 | 黑名单 | `{base_url}/rules/outputs/black.txt` | `{cdn_url}/rules/outputs/black.txt` |
| 白名单规则 | 白名单 | `{base_url}/rules/outputs/white.txt` | `{cdn_url}/rules/outputs/white.txt` |

## 🔧 使用说明

### Adblock/uBlock Origin
1. 打开扩展设置
2. 找到"自定义规则"或"我的规则"选项
3. 添加订阅链接：`{base_url}/rules/outputs/ad.txt`

### DNS过滤
1. 将以下链接添加到DNS过滤软件：
   - `{base_url}/rules/outputs/dns.txt`

### Hosts文件
1. 下载Hosts文件：
   - `{base_url}/rules/outputs/hosts.txt`
2. 将内容添加到系统hosts文件

## 🚀 更新频率

规则每天自动更新，更新时间：北京时间 02:00

## 📝 项目信息

- **项目地址**: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}
- **许可证**: MIT License
- **作者**: {self.config.get('project.author')}

---

*最后更新: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("✅ README.md 生成完成")
    
    def run(self, mode='normal'):
        """运行生成器"""
        print("=" * 60)
        print(f"🎯 广告过滤规则生成器 v{self.version}")
        print(f"📱 模式: {mode}")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 从文件加载规则源
            print("\n步骤 1/5: 从文件加载规则源")
            if not self.load_sources_from_files():
                print("❌ 加载规则源失败")
                return False
            
            # 2. 下载规则源
            print(f"\n步骤 2/5: 下载规则源")
            black_content, white_content = self.download_sources()
            
            # 检查是否有内容
            if not black_content:
                print("❌ 没有下载到任何黑名单规则")
                return False
            
            # 3. 处理规则
            print(f"\n步骤 3/5: 处理规则")
            domains = self.process_sources(black_content, white_content, mode)
            
            if not domains:
                print("⚠️  警告：没有生成任何域名规则")
            
            # 4. 生成文件
            print(f"\n步骤 4/5: 生成规则文件")
            if not self.generate_files(domains, mode):
                print("❌ 生成规则文件失败")
                return False
            
            # 5. 生成报告和README
            print(f"\n步骤 5/5: 生成报告和README")
            self.generate_reports(domains, mode)
            self.generate_readme(domains)
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("✅ 处理完成！")
            print("=" * 60)
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.processor.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.processor.white_domains):,}个")
            print(f"📊 过滤后域名: {len(domains):,}个")
            
            # 显示文件大小
            print("\n📁 生成的文件:")
            for filename in ['ad.txt', 'dns.txt', 'hosts.txt', 'black.txt', 'white.txt', 'enhanced.txt']:
                size = self.files.get_file_size(filename)
                if size > 0:
                    size_mb = size / 1024 / 1024
                    print(f"  • {filename}: {size_mb:.2f} MB")
            
            print("=" * 60)
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  用户中断程序")
            return False
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

# ============================================
# 命令行接口
# ============================================
def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description=f'广告过滤规则生成器 v3.3',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['normal', 'strict', 'loose', 'enhanced'],
        default='normal',
        help='运行模式: normal(默认), strict(严格), loose(宽松), enhanced(增强)'
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='配置文件路径'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='详细输出'
    )
    
    parser.add_argument(
        '--test', '-t',
        action='store_true',
        help='测试模式'
    )
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 检查依赖
    if not REQUESTS_AVAILABLE:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests urllib3 pyyaml")
        return 1
    
    # 运行生成器
    generator = AdBlockGenerator(args.config)
    
    if args.test:
        # 测试模式
        print("🧪 测试模式运行中...")
        success = generator.run('normal')
    else:
        # 正常模式
        success = generator.run(args.mode)
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("🚀 GitHub Actions会自动提交更新")
        return 0
    else:
        print("\n💥 规则生成失败！")
        return 1

if __name__ == "__main__":
    sys.exit(main())
