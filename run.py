#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 v3.0
智能、高效、可配置的广告过滤解决方案
支持多种输出格式和增强拦截功能
"""

import os
import re
import json
import yaml
import time
import logging
import argparse
import hashlib
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Set, List, Optional, Tuple, Dict, Any, Generator
from collections import defaultdict, Counter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from urllib.parse import urlparse
import shutil

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置管理器
class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self.load_config()
        self.validate_config()
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
            else:
                config = self.get_default_config()
                # 保存默认配置
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
            return config
            
        except Exception as e:
            logging.error(f"加载配置失败: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'project': {
                'name': 'adblock-enhanced',
                'version': '3.0.0',
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
                'use_cache': False,
                'cache_expiry_hours': 24
            },
            'rules': {
                'exclude_domains': [
                    'localhost', 'local', 'broadcasthost',
                    '127.0.0.1', '0.0.0.0', '::1'
                ],
                'intelligent_filtering': {
                    'enable_essential_domain_whitelist': True,
                    'enable_safe_domains_check': True,
                    'enable_false_positive_filter': True,
                    'remove_suspicious_wildcards': True,
                    'keep_popular_domains': True,
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
                'logs_dir': 'logs'
            },
            'network': {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'verify_ssl': True
            }
        }
    
    def validate_config(self) -> None:
        """验证配置"""
        # 确保必要配置项存在
        required = ['github', 'performance', 'paths']
        for section in required:
            if section not in self.config:
                self.config[section] = self.get_default_config()[section]
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value if value is not None else default
    
    def save(self) -> None:
        """保存配置"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            logging.error(f"保存配置失败: {e}")


# 域名验证器
class DomainValidator:
    """域名验证器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        
        # 预编译正则表达式
        self.domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        # 排除的域名
        self.exclude_domains = set(self.config.get('rules.exclude_domains', []))
        
        # 常见顶级域名列表
        self.common_tlds = {
            # 通用顶级域名
            'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
            'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum',
            # 国家顶级域名
            'cn', 'uk', 'de', 'jp', 'fr', 'ru', 'br', 'in',
            'it', 'es', 'mx', 'kr', 'nl', 'ch', 'se', 'no',
            'dk', 'fi', 'pl', 'cz', 'hu', 'ro', 'gr', 'tr',
            'ar', 'cl', 'co', 'pe', 've', 'ec', 'bo', 'py',
            'uy', 'pa', 'cr', 'do', 'gt', 'sv', 'hn', 'ni',
            'pr', 'tt', 'jm', 'bs', 'bz', 'gy', 'sr', 'gf',
            'gp', 'mq', 'ht', 'cu', 'do', 'eu', 'asia', 'xxx',
            # 新增顶级域名
            'xyz', 'online', 'site', 'top', 'win', 'vip', 'club',
            'shop', 'store', 'tech', 'website', 'space', 'digital',
            'news', 'blog', 'app', 'dev', 'io', 'ai', 'tv', 'me',
            'cc', 'us', 'ca', 'au', 'nz', 'sg', 'hk', 'tw', 'mo'
        }
    
    def validate_domain(self, domain: str) -> Tuple[bool, str]:
        """
        验证域名有效性
        
        Args:
            domain: 域名
            
        Returns:
            (是否有效, 错误信息)
        """
        domain = domain.strip().lower()
        
        # 基本长度检查
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
            return False, "缺少顶级域名"
        
        tld = parts[-1]
        if len(tld) < 2:
            return False, "TLD太短"
        
        # 验证TLD（可选）
        if self.config.get('rules.validation.validate_tld', False):
            if not self._validate_tld(tld):
                return False, "无效的TLD"
        
        # 检查是否有连续的dot
        if '..' in domain:
            return False, "连续的dot"
        
        # 检查部分是否以连字符开头或结尾
        for part in parts:
            if not part:  # 空部分
                return False, "空的部分"
            if part.startswith('-') or part.endswith('-'):
                return False, "部分以连字符开头或结尾"
            if len(part) > 63:
                return False, "部分太长"
            
            # 检查特殊字符
            if not self.config.get('rules.validation.allow_underscores', False):
                if '_' in part:
                    return False, "包含下划线"
            
            if not self.config.get('rules.validation.allow_numbers', True):
                if any(c.isdigit() for c in part):
                    return False, "包含数字"
        
        return True, "有效"
    
    def _is_ip_address(self, domain: str) -> bool:
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
            # 简单的IPv6检查
            if ':::' in domain:
                return False
            parts = domain.split(':')
            if len(parts) > 8:
                return False
            for part in parts:
                if part and not all(c in '0123456789abcdefABCDEF' for c in part):
                    return False
            return True
        
        return False
    
    def _validate_tld(self, tld: str) -> bool:
        """验证顶级域名"""
        # 这里可以扩展更复杂的TLD验证
        # 目前只检查是否为常见TLD
        return tld in self.common_tlds
    
    def normalize_domain(self, domain: str) -> str:
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


# 网络管理器
class NetworkManager:
    """网络管理器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.session = self._create_session()
        self.cache = {}
        self.cache_lock = threading.Lock()
    
    def _create_session(self) -> requests.Session:
        """创建请求会话"""
        session = requests.Session()
        
        # 重试策略
        retry_strategy = Retry(
            total=self.config.get('performance.retry_times', 3),
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 设置请求头
        session.headers.update({
            'User-Agent': self.config.get('network.user_agent', 'AdBlockGenerator/3.0'),
            'Accept': 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': self.config.get('network.accept_encoding', 'gzip, deflate'),
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
        
        return session
    
    def fetch_url(self, url: str, use_cache: bool = True) -> Optional[str]:
        """获取URL内容"""
        # 检查缓存
        if use_cache and self.config.get('performance.use_cache', False):
            cache_key = hashlib.md5(url.encode()).hexdigest()
            
            with self.cache_lock:
                if cache_key in self.cache:
                    content, timestamp = self.cache[cache_key]
                    cache_expiry = self.config.get('performance.cache_expiry_hours', 24)
                    if time.time() - timestamp < cache_expiry * 3600:
                        return content
        
        try:
            response = self.session.get(
                url,
                timeout=self.config.get('performance.timeout', 30),
                verify=self.config.get('network.verify_ssl', True)
            )
            
            response.raise_for_status()
            content = response.text
            
            # 更新缓存
            if use_cache and self.config.get('performance.use_cache', False):
                with self.cache_lock:
                    self.cache[cache_key] = (content, time.time())
            
            return content
            
        except requests.RequestException as e:
            logging.warning(f"获取URL失败 {url}: {e}")
            return None
    
    def fetch_multiple_urls(self, urls: List[str], max_workers: int = 10) -> Dict[str, Optional[str]]:
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


# 文件管理器
class FileManager:
    """文件管理器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self._setup_directories()
    
    def _setup_directories(self) -> None:
        """设置目录结构"""
        directories = [
            self.config.get('paths.sources_dir'),
            self.config.get('paths.outputs_dir'),
            self.config.get('paths.cache_dir'),
            self.config.get('paths.logs_dir'),
            self.config.get('paths.reports_dir'),
            self.config.get('paths.backup_dir'),
        ]
        
        for directory in directories:
            if directory:
                os.makedirs(directory, exist_ok=True)
    
    def save_output(self, filename: str, content: str, compress: bool = False) -> bool:
        """保存输出文件"""
        try:
            filepath = os.path.join(
                self.config.get('paths.outputs_dir', 'rules/outputs'),
                filename
            )
            
            # 创建备份
            if os.path.exists(filepath) and self.config.get('auto_update.backup_before_update', True):
                self._create_backup(filepath)
            
            # 写入文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 压缩（如果需要）
            if compress:
                self._compress_file(filepath)
            
            logging.info(f"保存文件: {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"保存文件失败 {filename}: {e}")
            return False
    
    def _create_backup(self, filepath: str) -> None:
        """创建备份"""
        backup_dir = self.config.get('paths.backup_dir')
        if not backup_dir or not os.path.exists(backup_dir):
            return
        
        try:
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(backup_dir, f"{filename}.{timestamp}.bak")
            
            shutil.copy2(filepath, backup_path)
            
            # 清理旧备份
            self._cleanup_old_backups(filename)
            
        except Exception as e:
            logging.warning(f"创建备份失败 {filepath}: {e}")
    
    def _cleanup_old_backups(self, filename: str) -> None:
        """清理旧备份"""
        backup_dir = self.config.get('paths.backup_dir')
        if not backup_dir:
            return
        
        max_backups = self.config.get('auto_update.max_backups', 5)
        pattern = re.compile(rf"{re.escape(filename)}\.\d{{8}}_\d{{6}}\.bak")
        
        backups = []
        try:
            for file in os.listdir(backup_dir):
                if pattern.match(file):
                    filepath = os.path.join(backup_dir, file)
                    backups.append((filepath, os.path.getmtime(filepath)))
            
            # 按修改时间排序
            backups.sort(key=lambda x: x[1], reverse=True)
            
            # 删除多余的备份
            for filepath, _ in backups[max_backups:]:
                try:
                    os.remove(filepath)
                except Exception as e:
                    logging.warning(f"删除旧备份失败 {filepath}: {e}")
        except Exception as e:
            logging.warning(f"清理备份失败: {e}")
    
    def _compress_file(self, filepath: str) -> None:
        """压缩文件"""
        try:
            import gzip
            
            with open(filepath, 'rb') as f_in:
                with gzip.open(f"{filepath}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
        except Exception as e:
            logging.warning(f"压缩文件失败 {filepath}: {e}")


# 监控器
class Monitor:
    """性能监控器"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            'performance': {},
            'memory': {},
            'network': {},
            'files': {}
        }
    
    def start_monitoring(self) -> None:
        """开始监控"""
        self.start_time = time.time()
        self.metrics = {
            'performance': {},
            'memory': {},
            'network': {},
            'files': {}
        }
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """停止监控并返回结果"""
        end_time = time.time()
        
        self.metrics['performance']['total_time'] = end_time - self.start_time
        
        try:
            import psutil
            process = psutil.Process()
            self.metrics['memory']['rss_mb'] = process.memory_info().rss / 1024 / 1024
            self.metrics['memory']['vms_mb'] = process.memory_info().vms / 1024 / 1024
            self.metrics['system'] = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
            }
        except ImportError:
            # psutil不可用，跳过内存监控
            pass
        
        return self.metrics
    
    def record_metric(self, category: str, key: str, value: Any) -> None:
        """记录指标"""
        if category not in self.metrics:
            self.metrics[category] = {}
        self.metrics[category][key] = value


# 规则处理器
class RuleProcessor:
    """规则处理器"""
    
    def __init__(self, config: ConfigManager, validator: DomainValidator):
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
            'element_hiding_rules': 0,
            'script_blocking_rules': 0,
            'whitelist_domains': 0
        }
        
        # 存储
        self.black_domains = set()
        self.white_domains = set()
        self.enhanced_domains = set()
        self.element_hiding_rules = set()
        self.script_blocking_rules = set()
        
        # 加载内置规则
        self._load_builtin_rules()
    
    def _load_builtin_rules(self) -> None:
        """加载内置规则"""
        # 内置规则文件路径
        builtin_dir = os.path.join(self.config.get('paths.base_dir', '.'), 'rules', 'sources')
        
        # 内置分析工具域名
        self.analytics_domains = {
            'google-analytics.com', 'googletagmanager.com', 'google-analytics-urchin.com',
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'adservice.google.com', 'adsense.google.com', 'stats.g.doubleclick.net',
            'yandex.ru', 'yandex.net', 'mc.yandex.ru', 'yastatic.net',
            'matomo.org', 'piwik.org', 'clicky.com', 'statcounter.com',
            'hotjar.com', 'mouseflow.com', 'crazyegg.com', 'luckyorange.com',
            'sentry.io', 'bugsnag.com', 'rollbar.com', 'airbrake.io',
            'newrelic.com', 'appdynamics.com', 'datadoghq.com'
        }
        
        # 内置广告网络
        self.ad_networks = {
            'adnxs.com', 'rubiconproject.com', 'criteo.com', 'taboola.com',
            'outbrain.com', 'revcontent.com', 'amazon-adsystem.com',
            'adsrvr.org', 'pubmatic.com', 'openx.net', 'indexexchange.com',
            'sonobi.com', 'districtm.io', 'sharethrough.com', 'triplelift.com',
            'yahoo.com', 'aol.com', 'verizonmedia.com', 'mgid.com',
            'zemanta.com', 'content.ad', 'adblade.com', 'adbrite.com',
            'adform.com', 'adition.com', 'casalemedia.com', 'contextweb.com',
            'conversantmedia.com', 'districtm.io', 'eyereturn.com',
            'getclicky.com', 'imrworldwide.com', 'infolinks.com',
            'innovid.com', 'ipinyou.com', 'kargo.com', 'kiosked.com',
            'lijit.com', 'linksynergy.com', 'media.net', 'mediamath.com',
            'meetrics.net', 'mopub.com', 'pulpix.com', 'quantserve.com',
            'sovrn.com', 'spotxchange.com', 'teads.tv', 'telaria.com',
            'tremorhub.com', 'truex.com', 'undertone.com', 'unruly.co',
            'videologygroup.com', 'yieldmo.com', 'yieldone.com', 'yldmgrimg.net'
        }
        
        # 内置白名单域名（防止误拦截）
        self.essential_domains = {
            'google.com', 'github.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'cloudflare.com', 'baidu.com', 'tencent.com',
            'alibaba.com', 'taobao.com', 'weixin.qq.com', 'qq.com',
            'weibo.com', 'zhihu.com', 'bilibili.com', 'douyin.com',
            'kuaishou.com', 'stackoverflow.com', 'wikipedia.org',
            'gitlab.com', 'docker.com', 'npmjs.com', 'pypi.org',
            'ubuntu.com', 'debian.org', 'redhat.com', 'apache.org',
            'mozilla.org', 'chromium.org', 'letsencrypt.org'
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
    
    def extract_domain_from_line(self, line: str) -> Tuple[Optional[str], bool]:
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
            (r'^\|\|([^\^/\$]+)\^', 1),
            # domain.com^ 格式
            (r'^([^\^/\$]+)\^', 1),
            # 0.0.0.0 domain.com 格式
            (r'^0\.0\.0\.0\s+([^\s]+)', 1),
            # 127.0.0.1 domain.com 格式
            (r'^127\.0\.0\.1\s+([^\s]+)', 1),
            # 纯域名格式
            (r'^([a-zA-Z0-9.-]+)$', 1),
            # ||domain.com^$third-party 格式
            (r'^\|\|([^\^/\$]+)\^\$third-party', 1),
            # ||domain.com^$~third-party 格式
            (r'^\|\|([^\^/\$]+)\^\$~third-party', 1),
            # ||domain.com^$important 格式
            (r'^\|\|([^\^/\$]+)\^\$important', 1),
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
    
    def process_content(self, content: str, source_type: str = 'black') -> Set[str]:
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
    
    def apply_intelligent_filtering(self, domains: Set[str], mode: str = 'normal') -> Set[str]:
        """应用智能过滤"""
        filtered = set(domains)
        
        # 1. 应用白名单
        if self.config.get('rules.intelligent_filtering.enable_essential_domain_whitelist', True):
            filtered = self._apply_essential_whitelist(filtered)
        
        # 2. 应用用户白名单
        filtered = self._apply_user_whitelist(filtered)
        
        # 3. 安全域名检查
        if self.config.get('rules.intelligent_filtering.enable_safe_domains_check', True):
            filtered = self._filter_safe_domains(filtered)
        
        # 4. 误报过滤
        if self.config.get('rules.intelligent_filtering.enable_false_positive_filter', True):
            filtered = self._filter_false_positives(filtered)
        
        # 5. 域名验证
        if self.config.get('rules.intelligent_filtering.enable_domain_validation', True):
            filtered = self._validate_domains(filtered)
        
        # 6. 根据模式调整
        if mode == 'strict':
            # 严格模式：更多过滤
            filtered = self._apply_strict_filtering(filtered)
        elif mode == 'loose':
            # 宽松模式：减少过滤
            filtered = self._apply_loose_filtering(filtered)
        elif mode == 'enhanced':
            # 增强模式：增强拦截
            filtered = self._enhance_blocking(filtered)
        
        return filtered
    
    def _apply_essential_whitelist(self, domains: Set[str]) -> Set[str]:
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
                self.white_domains.add(domain)  # 添加到白名单
        
        self.stats['removed_by_safe_check'] += removed
        return filtered
    
    def _apply_user_whitelist(self, domains: Set[str]) -> Set[str]:
        """应用用户白名单"""
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
    
    def _filter_safe_domains(self, domains: Set[str]) -> Set[str]:
        """过滤安全域名"""
        filtered = set()
        removed = 0
        
        # 安全域名模式
        safe_patterns = [
            r'^[a-z]{1,2}\.com$',  # 超短域名
            r'^[a-z]{1,3}\.(com|net|org)$',
            r'^[a-z0-9-]+\.(gov|edu|mil)$',  # 政府/教育
            r'^[a-z0-9-]+\.(localhost|local|test)$',
        ]
        
        for domain in domains:
            is_safe = False
            
            for pattern in safe_patterns:
                if re.match(pattern, domain):
                    is_safe = True
                    break
            
            # 检查是否为常见服务域名
            common_services = {
                'github.com', 'gitlab.com', 'bitbucket.org',
                'stackoverflow.com', 'stackexchange.com',
                'wikipedia.org', 'wikimedia.org',
                'npmjs.com', 'pypi.org', 'docker.com',
                'ubuntu.com', 'debian.org', 'archlinux.org'
            }
            
            if any(domain == service or domain.endswith(f'.{service}') for service in common_services):
                is_safe = True
            
            if not is_safe:
                filtered.add(domain)
            else:
                removed += 1
        
        self.stats['removed_by_safe_check'] += removed
        return filtered
    
    def _filter_false_positives(self, domains: Set[str]) -> Set[str]:
        """过滤误报"""
        filtered = set()
        removed = 0
        
        # 可疑域名模式
        suspicious_patterns = [
            r'^[a-z]{1,2}\d+[a-z]+\.[a-z]+$',  # 短域名带数字
            r'^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]+$',  # 多个连字符
            r'^\d+[a-z]+\.[a-z]+$',  # 以数字开头
            r'^[a-z]+\d+\.[a-z]+$',  # 以字母开头但包含数字
        ]
        
        for domain in domains:
            is_suspicious = False
            
            for pattern in suspicious_patterns:
                if re.match(pattern, domain):
                    is_suspicious = True
                    break
            
            # 检查域名长度
            parts = domain.split('.')
            if len(parts) >= 2:
                second_level = parts[-2]
                if len(second_level) <= 2:  # 第二级太短
                    is_suspicious = True
            
            if not is_suspicious:
                filtered.add(domain)
            else:
                removed += 1
        
        self.stats['removed_by_suspicious'] = removed
        return filtered
    
    def _validate_domains(self, domains: Set[str]) -> Set[str]:
        """验证域名"""
        filtered = set()
        
        for domain in domains:
            is_valid, _ = self.validator.validate_domain(domain)
            if is_valid:
                filtered.add(domain)
        
        return filtered
    
    def _apply_strict_filtering(self, domains: Set[str]) -> Set[str]:
        """应用严格过滤"""
        filtered = set()
        
        # 移除所有短域名
        for domain in domains:
            if len(domain) >= 8:  # 最小长度
                filtered.add(domain)
        
        return filtered
    
    def _apply_loose_filtering(self, domains: Set[str]) -> Set[str]:
        """应用宽松过滤"""
        # 宽松模式不过滤任何域名
        return domains
    
    def _enhance_blocking(self, domains: Set[str]) -> Set[str]:
        """增强拦截"""
        enhanced = set(domains)
        added = 0
        
        # 1. 添加分析工具域名
        if self.config.get('rules.enhanced_blocking.analytics.enabled', True):
            for domain in self.analytics_domains:
                if domain not in enhanced:
                    # 验证域名
                    is_valid, _ = self.validator.validate_domain(domain)
                    if is_valid:
                        enhanced.add(domain)
                        added += 1
        
        # 2. 添加广告网络域名
        if self.config.get('rules.enhanced_blocking.banner_ads.enabled', True):
            for domain in self.ad_networks:
                if domain not in enhanced:
                    is_valid, _ = self.validator.validate_domain(domain)
                    if is_valid:
                        enhanced.add(domain)
                        added += 1
        
        # 3. 生成元素隐藏规则
        if self.config.get('rules.enhanced_blocking.element_hiding.enabled', True):
            self.element_hiding_rules.update(self.builtin_element_hiding_rules)
            self.stats['element_hiding_rules'] = len(self.element_hiding_rules)
        
        # 4. 生成脚本拦截规则
        if self.config.get('rules.enhanced_blocking.script_blocking.enabled', True):
            for pattern in self.builtin_script_blocking_rules:
                rule = f"||*{pattern}$script,important"
                self.script_blocking_rules.add(rule)
            self.stats['script_blocking_rules'] = len(self.script_blocking_rules)
        
        self.stats['added_by_enhancement'] = added
        return enhanced


# 主生成器
class AdBlockGenerator:
    """广告过滤规则生成器主类"""
    
    def __init__(self, config_path: str = "config.yaml"):
        # 初始化组件
        self.config = ConfigManager(config_path)
        self.validator = DomainValidator(self.config)
        self.processor = RuleProcessor(self.config, self.validator)
        self.network = NetworkManager(self.config)
        self.files = FileManager(self.config)
        self.monitor = Monitor()
        
        # 设置日志
        self._setup_logging()
        
        # 状态
        self.black_sources = []
        self.white_sources = []
        
        # 版本信息
        self.version = self.config.get('project.version', '3.0.0')
        self.build_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def _setup_logging(self) -> None:
        """设置日志"""
        log_level = self.config.get('monitoring.log_level', 'INFO').upper()
        log_file = self.config.get('paths.error_log', 'logs/error.log')
        
        # 创建日志目录
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
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
    
    def run(self, mode: str = 'normal') -> bool:
        """
        运行规则生成器
        
        Args:
            mode: 运行模式 (normal, strict, loose, enhanced)
            
        Returns:
            是否成功
        """
        self.logger.info(f"启动广告过滤规则生成器 v{self.version}")
        self.logger.info(f"运行模式: {mode}")
        self.monitor.start_monitoring()
        
        try:
            # 1. 加载源
            self.logger.info("步骤 1/5: 加载规则源")
            if not self._load_sources():
                return False
            
            # 2. 下载规则源
            self.logger.info("步骤 2/5: 下载规则源")
            black_content, white_content = self._download_sources()
            if not black_content:
                self.logger.error("没有下载到黑名单规则")
                return False
            
            # 3. 处理规则
            self.logger.info("步骤 3/5: 处理规则")
            domains = self._process_sources(black_content, white_content, mode)
            
            # 4. 生成输出文件
            self.logger.info("步骤 4/5: 生成输出文件")
            if not self._generate_outputs(domains, mode):
                return False
            
            # 5. 生成报告和README
            self.logger.info("步骤 5/5: 生成报告和README")
            self._generate_reports(domains, mode)
            self._generate_readme(domains)
            
            # 监控结果
            metrics = self.monitor.stop_monitoring()
            self.logger.info(f"处理完成! 耗时: {metrics['performance']['total_time']:.2f}秒")
            
            return True
            
        except Exception as e:
            self.logger.error(f"运行失败: {e}", exc_info=True)
            return False
    
    def _load_sources(self) -> bool:
        """加载规则源"""
        try:
            # 从配置加载内置源
            builtin_black = self.config.get('rules.sources.blacklist', [])
            builtin_white = self.config.get('rules.sources.whitelist', [])
            
            # 从文件加载源
            sources_dir = self.config.get('paths.sources_dir', 'rules/sources')
            black_file = os.path.join(sources_dir, 'black.txt')
            white_file = os.path.join(sources_dir, 'white.txt')
            
            file_black = []
            file_white = []
            
            # 读取黑名单源文件
            if os.path.exists(black_file):
                try:
                    with open(black_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                file_black.append(line)
                except Exception as e:
                    self.logger.warning(f"读取黑名单源文件失败: {e}")
            
            # 读取白名单源文件
            if os.path.exists(white_file):
                try:
                    with open(white_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                file_white.append(line)
                except Exception as e:
                    self.logger.warning(f"读取白名单源文件失败: {e}")
            
            # 合并源
            self.black_sources = list(set(builtin_black + file_black))
            self.white_sources = list(set(builtin_white + file_white))
            
            # 如果没有黑名单源，创建默认源文件
            if not self.black_sources:
                self.logger.info("创建默认黑名单源文件")
                self._create_default_source_files()
                # 重新加载
                return self._load_sources()
            
            self.logger.info(f"加载了 {len(self.black_sources)} 个黑名单源和 {len(self.white_sources)} 个白名单源")
            return True
            
        except Exception as e:
            self.logger.error(f"加载规则源失败: {e}")
            return False
    
    def _create_default_source_files(self) -> None:
        """创建默认源文件"""
        sources_dir = self.config.get('paths.sources_dir', 'rules/sources')
        
        # 创建黑名单源文件
        black_file = os.path.join(sources_dir, 'black.txt')
        default_black_sources = [
            "# 广告过滤规则源",
            "# 默认内置源",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/analytics.txt",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/banners.txt"
        ]
        
        with open(black_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(default_black_sources))
        
        # 创建白名单源文件
        white_file = os.path.join(sources_dir, 'white.txt')
        default_white_sources = [
            "# 白名单规则源",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt"
        ]
        
        with open(white_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(default_white_sources))
        
        self.logger.info("已创建默认源文件")
    
    def _download_sources(self) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
        """下载规则源"""
        # 合并所有URL
        all_urls = self.black_sources + self.white_sources
        
        # 下载
        results = self.network.fetch_multiple_urls(
            all_urls,
            max_workers=self.config.get('performance.max_workers', 10)
        )
        
        # 分离结果
        black_content = []
        white_content = []
        
        for url in self.black_sources:
            if url in results and results[url]:
                black_content.append((url, results[url]))
            else:
                self.logger.warning(f"黑名单源下载失败: {url}")
        
        for url in self.white_sources:
            if url in results and results[url]:
                white_content.append((url, results[url]))
            else:
                self.logger.warning(f"白名单源下载失败: {url}")
        
        self.logger.info(f"下载完成: {len(black_content)} 黑名单源, {len(white_content)} 白名单源")
        return black_content, white_content
    
    def _process_sources(self, black_content: List[Tuple[str, str]], 
                        white_content: List[Tuple[str, str]], 
                        mode: str) -> Set[str]:
        """处理规则源"""
        # 处理黑名单
        all_black_domains = set()
        for url, content in black_content:
            domains = self.processor.process_content(content, 'black')
            all_black_domains.update(domains)
        
        # 处理白名单
        for url, content in white_content:
            self.processor.process_content(content, 'white')
        
        self.logger.info(f"原始数据: {len(all_black_domains)} 黑名单域名, {len(self.processor.white_domains)} 白名单域名")
        
        # 应用智能过滤
        filtered_domains = self.processor.apply_intelligent_filtering(all_black_domains, mode)
        
        # 更新统计
        self.processor.black_domains = all_black_domains
        self.processor.enhanced_domains = filtered_domains
        
        self.logger.info(f"处理完成: {len(filtered_domains)} 个过滤后域名")
        return filtered_domains
    
    def _generate_outputs(self, domains: Set[str], mode: str) -> bool:
        """生成输出文件"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        compress = self.config.get('optimization.compress_rules', False)
        
        # 1. 生成Adblock规则
        ad_content = self._generate_adblock_rules(domains, timestamp, mode)
        if not self.files.save_output('ad.txt', ad_content, compress):
            self.logger.error("生成ad.txt失败")
            return False
        
        # 2. 生成DNS规则
        dns_content = self._generate_dns_rules(domains, timestamp)
        if not self.files.save_output('dns.txt', dns_content, compress):
            self.logger.error("生成dns.txt失败")
            return False
        
        # 3. 生成Hosts规则
        hosts_content = self._generate_hosts_rules(domains, timestamp)
        if not self.files.save_output('hosts.txt', hosts_content, compress):
            self.logger.error("生成hosts.txt失败")
            return False
        
        # 4. 生成增强规则
        enhanced_content = self._generate_enhanced_rules(domains, timestamp, mode)
        if not self.files.save_output('enhanced.txt', enhanced_content, compress):
            self.logger.error("生成enhanced.txt失败")
            return False
        
        # 5. 生成黑名单规则
        black_content = self._generate_black_rules(domains, timestamp)
        if not self.files.save_output('black.txt', black_content, compress):
            self.logger.error("生成black.txt失败")
            return False
        
        # 6. 生成白名单规则
        white_content = self._generate_white_rules(timestamp)
        if not self.files.save_output('white.txt', white_content, compress):
            self.logger.error("生成white.txt失败")
            return False
        
        # 7. 生成信息文件
        info_content = self._generate_info_file(domains, timestamp, mode)
        if not self.files.save_output('info.json', info_content):
            self.logger.error("生成info.json失败")
            return False
        
        return True
    
    def _generate_adblock_rules(self, domains: Set[str], timestamp: str, mode: str) -> str:
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
        
        # 添加白名单规则
        for domain in sorted(self.processor.white_domains):
            lines.append(f"@@||{domain}^")
        
        # 添加元素隐藏规则
        if self.processor.element_hiding_rules:
            lines.extend([
                "!",
                "! ========== 元素隐藏规则 =========="
            ])
            for rule in sorted(self.processor.element_hiding_rules):
                lines.append(rule)
        
        # 添加脚本拦截规则
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
        
        # 添加黑名单规则
        for domain in sorted(domains):
            lines.append(f"||{domain}^")
        
        return '\n'.join(lines)
    
    def _generate_dns_rules(self, domains: Set[str], timestamp: str) -> str:
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
    
    def _generate_hosts_rules(self, domains: Set[str], timestamp: str) -> str:
        """生成Hosts规则"""
        lines = [
            f"# Hosts格式广告过滤规则 v{self.version}",
            f"# 生成时间: {timestamp}",
            f"# 域名数量: {len(domains)}",
            f"# 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "#",
            "127.0.0.1 localhost",
            "::1 localhost",
            "#"
        ]
        
        for domain in sorted(domains):
            lines.append(f"0.0.0.0 {domain}")
        
        return '\n'.join(lines)
    
    def _generate_enhanced_rules(self, domains: Set[str], timestamp: str, mode: str) -> str:
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
    
    def _generate_black_rules(self, domains: Set[str], timestamp: str) -> str:
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
    
    def _generate_white_rules(self, timestamp: str) -> str:
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
    
    def _generate_info_file(self, domains: Set[str], timestamp: str, mode: str) -> str:
        """生成信息文件"""
        # 获取监控数据
        metrics = self.monitor.metrics
        
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
                'enhanced': len(self.processor.analytics_domains) + len(self.processor.ad_networks)
            },
            'sources': {
                'blacklist': len(self.black_sources),
                'whitelist': len(self.white_sources)
            },
            'github': {
                'user': self.config.get('github.user'),
                'repo': self.config.get('github.repo'),
                'branch': self.config.get('github.branch')
            },
            'metrics': metrics,
            'files': {
                'ad_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/ad.txt",
                'dns_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/dns.txt",
                'hosts_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/hosts.txt",
                'enhanced_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/enhanced.txt"
            }
        }
        
        return json.dumps(info, indent=2, ensure_ascii=False)
    
    def _generate_reports(self, domains: Set[str], mode: str) -> None:
        """生成报告"""
        if not self.config.get('reports.generate_detailed_report', True):
            return
        
        reports_dir = self.config.get('paths.reports_dir', 'reports')
        
        # 1. 详细报告
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
            'top_domains': list(sorted(domains))[:100]
        }
        
        report_file = os.path.join(reports_dir, 'detailed_report.json')
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(detailed_report, f, indent=2, ensure_ascii=False)
            self.logger.info(f"生成详细报告: {report_file}")
        except Exception as e:
            self.logger.warning(f"生成详细报告失败: {e}")
    
    def _generate_readme(self, domains: Set[str]) -> None:
        """生成README.md"""
        base_url = f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{self.config.get('github.user')}/{self.config.get('github.repo')}@{self.config.get('github.branch')}"
        
        readme_content = f"""# 广告过滤规则 v{self.version}

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
        
        try:
            with open('README.md', 'w', encoding='utf-8') as f:
                f.write(readme_content)
            self.logger.info("生成README.md成功")
        except Exception as e:
            self.logger.error(f"生成README.md失败: {e}")


# 命令行接口
def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='广告过滤规则生成器 v3.0',
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
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    # 打印启动信息
    print("=" * 60)
    print("🎯 广告过滤规则生成器 v3.0")
    print(f"📱 模式: {args.mode}")
    print("=" * 60)
    
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
        print("\n" + "=" * 60)
        print("✅ 规则生成成功！")
        print("=" * 60)
        print(f"📁 输出目录: {generator.config.get('paths.outputs_dir', 'rules/outputs')}")
        print(f"📊 黑名单域名: {len(generator.processor.black_domains):,}")
        print(f"📊 白名单域名: {len(generator.processor.white_domains):,}")
        print(f"📊 过滤后域名: {len(generator.processor.enhanced_domains):,}")
        print("📖 查看README.md获取订阅链接")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("❌ 规则生成失败！")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
