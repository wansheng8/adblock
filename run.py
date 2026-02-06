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

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urljoin
import dns.resolver
import psutil
import tldextract

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
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # 设置默认值
            defaults = {
                'project': {
                    'version': '3.0.0',
                    'name': 'adblock-enhanced'
                },
                'performance': {
                    'max_workers': 10,
                    'timeout': 30
                }
            }
            
            # 合并配置
            self._merge_dict(config, defaults)
            return config
            
        except Exception as e:
            logging.error(f"加载配置失败: {e}")
            raise
    
    def _merge_dict(self, target: Dict, source: Dict) -> None:
        """递归合并字典"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._merge_dict(target[key], value)
            elif key not in target:
                target[key] = value
    
    def validate_config(self) -> None:
        """验证配置"""
        required_sections = ['github', 'performance', 'rules', 'paths']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"缺少必要配置项: {section}")
    
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
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)


# 域名验证器
class DomainValidator:
    """域名验证器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.tld_extractor = tldextract.TLDExtract(cache_dir="/tmp/tld_cache")
        
        # 预编译正则表达式
        self.domain_pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*(\.[A-Za-z]{2,})$'
        )
        
        # 保留字
        self.reserved_words = {
            'localhost', 'local', 'broadcasthost', 'localhost.localdomain',
            'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix'
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
        
        # 检查保留字
        if domain in self.reserved_words:
            return False, "保留字域名"
        
        # 检查排除列表
        exclude_list = self.config.get('rules.exclude_domains', [])
        if domain in exclude_list:
            return False, "在排除列表中"
        
        # 正则表达式验证
        if not self.domain_pattern.match(domain):
            return False, "格式无效"
        
        # 提取TLD
        try:
            extracted = self.tld_extractor(domain)
            if not extracted.suffix:
                return False, "缺少顶级域名"
            
            # 检查TLD长度
            min_tld_len = self.config.get('rules.validation.min_tld_length', 2)
            if len(extracted.suffix) < min_tld_len:
                return False, f"TLD太短 (min: {min_tld_len})"
            
            # 验证TLD（可选）
            if self.config.get('rules.validation.validate_tld', False):
                if not self._validate_tld(extracted.suffix):
                    return False, "无效的TLD"
            
        except Exception as e:
            return False, f"TLD提取失败: {e}"
        
        # 检查允许的特殊字符
        if not self.config.get('rules.validation.allow_underscores', False):
            if '_' in domain:
                return False, "包含下划线"
        
        if not self.config.get('rules.validation.allow_hyphens', True):
            if '-' in domain:
                return False, "包含连字符"
        
        if not self.config.get('rules.validation.allow_numbers', True):
            if any(c.isdigit() for c in domain):
                return False, "包含数字"
        
        # 检查连续特殊字符
        if '..' in domain or '--' in domain:
            return False, "连续特殊字符"
        
        # 检查开头和结尾
        if domain.startswith('-') or domain.startswith('.'):
            return False, "以特殊字符开头"
        if domain.endswith('-') or domain.endswith('.'):
            return False, "以特殊字符结尾"
        
        return True, "有效"
    
    def _validate_tld(self, tld: str) -> bool:
        """验证顶级域名"""
        # 这里可以集成公共后缀列表
        # 暂时使用简单的检查
        return len(tld) >= 2 and '.' in tld
    
    def normalize_domain(self, domain: str) -> str:
        """标准化域名"""
        domain = domain.strip().lower()
        
        # 移除协议和路径
        if '://' in domain:
            domain = urlparse(domain).netloc
        
        # 移除端口
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 移除www前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 移除末尾的点
        domain = domain.rstrip('.')
        
        return domain


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
            'script_blocking_rules': 0
        }
        
        # 缓存
        self.black_domains = set()
        self.white_domains = set()
        self.enhanced_domains = set()
        self.element_hiding_rules = set()
        self.script_blocking_rules = set()
        
        # 加载内置规则
        self._load_builtin_rules()
    
    def _load_builtin_rules(self) -> None:
        """加载内置规则"""
        # 从配置加载规则
        config_dir = os.path.join(
            self.config.get('paths.base_dir', '.'),
            self.config.get('paths.custom_sources', 'rules/sources/custom')
        )
        
        if os.path.exists(config_dir):
            for file in os.listdir(config_dir):
                if file.endswith(('.txt', '.json')):
                    self._load_custom_rules(os.path.join(config_dir, file))
    
    def _load_custom_rules(self, file_path: str) -> None:
        """加载自定义规则"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 根据文件类型处理
                if file_path.endswith('.json'):
                    rules = json.loads(content)
                    # 处理JSON格式规则
                else:
                    # 处理文本格式规则
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self._process_rule_line(line)
        except Exception as e:
            logging.warning(f"加载自定义规则失败 {file_path}: {e}")
    
    def _process_rule_line(self, line: str) -> None:
        """处理单行规则"""
        # 这里实现规则解析逻辑
        pass
    
    def process_source(self, content: str, source_type: str = 'black') -> Set[str]:
        """处理规则源内容"""
        domains = set()
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')):
                continue
            
            extracted = self._extract_domain_from_rule(line)
            if extracted:
                domain, is_whitelist = extracted
                
                # 验证域名
                is_valid, _ = self.validator.validate_domain(domain)
                if is_valid:
                    if is_whitelist:
                        self.white_domains.add(domain)
                    else:
                        domains.add(domain)
                    self.stats['valid_domains'] += 1
                else:
                    self.stats['invalid_domains'] += 1
        
        return domains
    
    def _extract_domain_from_rule(self, rule: str) -> Optional[Tuple[str, bool]]:
        """从规则中提取域名"""
        rule = rule.strip()
        is_whitelist = rule.startswith('@@')
        
        if is_whitelist:
            rule = rule[2:]
        
        # 处理常见规则格式
        patterns = [
            (r'^\|\|([^\^]+)\^\$?.*$', 1),  # ||domain.com^
            (r'^([^\^]+)\^\$?.*$', 1),      # domain.com^
            (r'^0\.0\.0\.0\s+([^\s]+)$', 1),  # 0.0.0.0 domain.com
            (r'^127\.0\.0\.1\s+([^\s]+)$', 1),  # 127.0.0.1 domain.com
            (r'^([a-zA-Z0-9.-]+)$', 1),      # domain.com
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = match.group(group)
                normalized = self.validator.normalize_domain(domain)
                return normalized, is_whitelist
        
        return None
    
    def apply_intelligent_filtering(self, domains: Set[str]) -> Set[str]:
        """应用智能过滤"""
        filtered_domains = set(domains)
        
        # 1. 白名单过滤
        filtered_domains = self._apply_whitelist(filtered_domains)
        
        # 2. 安全域名检查
        if self.config.get('rules.intelligent_filtering.enable_safe_domains_check', True):
            filtered_domains = self._filter_safe_domains(filtered_domains)
        
        # 3. 误报过滤
        if self.config.get('rules.intelligent_filtering.enable_false_positive_filter', True):
            filtered_domains = self._filter_false_positives(filtered_domains)
        
        # 4. 域名验证
        if self.config.get('rules.intelligent_filtering.enable_domain_validation', True):
            filtered_domains = self._validate_domains(filtered_domains)
        
        return filtered_domains
    
    def _apply_whitelist(self, domains: Set[str]) -> Set[str]:
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
                    if domain.endswith(f".{white_domain}"):
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
        # 实现安全域名检查逻辑
        return domains
    
    def _filter_false_positives(self, domains: Set[str]) -> Set[str]:
        """过滤误报"""
        # 实现误报过滤逻辑
        return domains
    
    def _validate_domains(self, domains: Set[str]) -> Set[str]:
        """验证域名"""
        filtered = set()
        removed = 0
        
        for domain in domains:
            is_valid, _ = self.validator.validate_domain(domain)
            if is_valid:
                filtered.add(domain)
            else:
                removed += 1
        
        return filtered
    
    def enhance_blocking(self, domains: Set[str]) -> Set[str]:
        """增强拦截"""
        enhanced = set(domains)
        
        # 分析工具拦截
        if self.config.get('rules.enhanced_blocking.analytics.enabled', True):
            enhanced = self._enhance_analytics_blocking(enhanced)
        
        # 横幅广告拦截
        if self.config.get('rules.enhanced_blocking.banner_ads.enabled', True):
            enhanced = self._enhance_banner_blocking(enhanced)
        
        # 元素隐藏规则
        if self.config.get('rules.enhanced_blocking.element_hiding.enabled', True):
            self._generate_element_hiding_rules()
        
        # 脚本拦截规则
        if self.config.get('rules.enhanced_blocking.script_blocking.enabled', True):
            self._generate_script_blocking_rules()
        
        return enhanced
    
    def _enhance_analytics_blocking(self, domains: Set[str]) -> Set[str]:
        """增强分析工具拦截"""
        # 实现分析工具拦截增强
        return domains
    
    def _enhance_banner_blocking(self, domains: Set[str]) -> Set[str]:
        """增强横幅广告拦截"""
        # 实现横幅广告拦截增强
        return domains
    
    def _generate_element_hiding_rules(self) -> None:
        """生成元素隐藏规则"""
        # 实现元素隐藏规则生成
        pass
    
    def _generate_script_blocking_rules(self) -> None:
        """生成脚本拦截规则"""
        # 实现脚本拦截规则生成
        pass


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
            total=self.config.get('network.retry_times', 3),
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
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
        cache_key = hashlib.md5(url.encode()).hexdigest()
        
        if use_cache:
            with self.cache_lock:
                if cache_key in self.cache:
                    content, timestamp = self.cache[cache_key]
                    cache_expiry = self.config.get('performance.cache_expiry_hours', 24)
                    if time.time() - timestamp < cache_expiry * 3600:
                        return content
        
        try:
            response = self.session.get(
                url,
                timeout=self.config.get('network.timeout', 30),
                verify=self.config.get('network.verify_ssl', True)
            )
            
            response.raise_for_status()
            content = response.text
            
            # 更新缓存
            with self.cache_lock:
                self.cache[cache_key] = (content, time.time())
            
            return content
            
        except requests.RequestException as e:
            logging.error(f"获取URL失败 {url}: {e}")
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
                self.config.get('paths.outputs_dir'),
                filename
            )
            
            # 创建备份
            if os.path.exists(filepath):
                self._create_backup(filepath)
            
            # 写入文件
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 压缩（如果需要）
            if compress:
                self._compress_file(filepath)
            
            return True
            
        except Exception as e:
            logging.error(f"保存文件失败 {filename}: {e}")
            return False
    
    def _create_backup(self, filepath: str) -> None:
        """创建备份"""
        backup_dir = self.config.get('paths.backup_dir')
        if not backup_dir:
            return
        
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(backup_dir, f"{filename}.{timestamp}.bak")
        
        try:
            import shutil
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
        pattern = f"{filename}.*.bak"
        
        backups = []
        for file in os.listdir(backup_dir):
            if re.match(pattern, file):
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
        self.memory_start = psutil.Process().memory_info().rss
        self.metrics = {
            'performance': {},
            'memory': {},
            'network': {},
            'files': {}
        }
    
    def start_monitoring(self) -> None:
        """开始监控"""
        self.start_time = time.time()
        self.memory_start = psutil.Process().memory_info().rss
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """停止监控并返回结果"""
        end_time = time.time()
        memory_end = psutil.Process().memory_info().rss
        
        self.metrics['performance']['total_time'] = end_time - self.start_time
        self.metrics['memory']['used_mb'] = (memory_end - self.memory_start) / 1024 / 1024
        self.metrics['memory']['peak_mb'] = psutil.Process().memory_info().rss / 1024 / 1024
        
        # 获取系统信息
        self.metrics['system'] = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }
        
        return self.metrics
    
    def record_metric(self, category: str, key: str, value: Any) -> None:
        """记录指标"""
        if category not in self.metrics:
            self.metrics[category] = {}
        self.metrics[category][key] = value


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
        self.black_domains = set()
        self.white_domains = set()
        self.enhanced_domains = set()
        
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
        self.monitor.start_monitoring()
        
        try:
            # 1. 加载源
            self.logger.info("步骤 1/5: 加载规则源")
            if not self._load_sources():
                return False
            
            # 2. 下载和处理规则
            self.logger.info("步骤 2/5: 下载和处理规则")
            if not self._process_sources():
                return False
            
            # 3. 智能过滤和增强
            self.logger.info("步骤 3/5: 智能过滤和增强")
            self._apply_filters_and_enhancements(mode)
            
            # 4. 生成输出文件
            self.logger.info("步骤 4/5: 生成输出文件")
            if not self._generate_outputs():
                return False
            
            # 5. 生成报告和README
            self.logger.info("步骤 5/5: 生成报告和README")
            self._generate_reports()
            self._generate_readme()
            
            # 监控结果
            metrics = self.monitor.stop_monitoring()
            self.logger.info(f"处理完成! 耗时: {metrics['performance']['total_time']:.2f}秒")
            
            return True
            
        except Exception as e:
            self.logger.error(f"运行失败: {e}", exc_info=True)
            return False
    
    def _load_sources(self) -> bool:
        """加载规则源"""
        # 加载内置源
        black_sources = self.config.get('rules.sources.blacklist', [])
        white_sources = self.config.get('rules.sources.whitelist', [])
        
        # 加载文件源
        black_file = self.config.get('paths.black_source')
        white_file = self.config.get('paths.white_source')
        
        if os.path.exists(black_file):
            try:
                with open(black_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    black_sources.extend([line.strip() for line in lines if line.strip() and not line.startswith('#')])
            except Exception as e:
                self.logger.warning(f"加载黑名单文件失败: {e}")
        
        if os.path.exists(white_file):
            try:
                with open(white_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    white_sources.extend([line.strip() for line in lines if line.strip() and not line.startswith('#')])
            except Exception as e:
                self.logger.warning(f"加载白名单文件失败: {e}")
        
        # 去重
        self.black_sources = list(set(black_sources))
        self.white_sources = list(set(white_sources))
        
        self.logger.info(f"加载了 {len(self.black_sources)} 个黑名单源和 {len(self.white_sources)} 个白名单源")
        return True
    
    def _process_sources(self) -> bool:
        """处理规则源"""
        # 下载所有源
        all_urls = self.black_sources + self.white_sources
        results = self.network.fetch_multiple_urls(
            all_urls,
            max_workers=self.config.get('performance.max_workers', 10)
        )
        
        # 处理黑名单
        black_domains = set()
        for url in self.black_sources:
            if url in results and results[url]:
                domains = self.processor.process_source(results[url], 'black')
                black_domains.update(domains)
        
        # 处理白名单
        white_domains = set()
        for url in self.white_sources:
            if url in results and results[url]:
                domains = self.processor.process_source(results[url], 'white')
                white_domains.update(domains)
        
        self.black_domains = black_domains
        self.white_domains = white_domains
        
        self.logger.info(f"处理完成: {len(self.black_domains)} 黑名单域名, {len(self.white_domains)} 白名单域名")
        return True
    
    def _apply_filters_and_enhancements(self, mode: str) -> None:
        """应用过滤和增强"""
        # 应用智能过滤
        filtered_domains = self.processor.apply_intelligent_filtering(self.black_domains)
        
        # 根据模式调整
        if mode == 'strict':
            # 严格模式：更多过滤
            pass
        elif mode == 'loose':
            # 宽松模式：减少过滤
            pass
        elif mode == 'enhanced':
            # 增强模式：更多拦截
            filtered_domains = self.processor.enhance_blocking(filtered_domains)
        
        self.enhanced_domains = filtered_domains
        self.logger.info(f"过滤后剩余: {len(self.enhanced_domains)} 个域名")
    
    def _generate_outputs(self) -> bool:
        """生成输出文件"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 1. 生成Adblock规则
        ad_content = self._generate_adblock_rules(timestamp)
        if not self.files.save_output('ad.txt', ad_content):
            return False
        
        # 2. 生成DNS规则
        dns_content = self._generate_dns_rules(timestamp)
        if not self.files.save_output('dns.txt', dns_content):
            return False
        
        # 3. 生成Hosts规则
        hosts_content = self._generate_hosts_rules(timestamp)
        if not self.files.save_output('hosts.txt', hosts_content):
            return False
        
        # 4. 生成增强规则
        enhanced_content = self._generate_enhanced_rules(timestamp)
        if not self.files.save_output('enhanced.txt', enhanced_content):
            return False
        
        # 5. 生成信息文件
        info_content = self._generate_info_file(timestamp)
        if not self.files.save_output('info.json', info_content):
            return False
        
        return True
    
    def _generate_adblock_rules(self, timestamp: str) -> str:
        """生成Adblock规则"""
        content = [
            f"! 广告过滤规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 域名数量: {len(self.enhanced_domains)}",
            f"! 项目地址: https://github.com/{self.config.get('github.user')}/{self.config.get('github.repo')}",
            "!",
            "! ========== 白名单规则 =========="
        ]
        
        # 添加白名单规则
        for domain in sorted(self.white_domains):
            content.append(f"@@||{domain}^")
        
        content.extend([
            "!",
            "! ========== 元素隐藏规则 =========="
        ])
        
        # 添加元素隐藏规则
        for rule in sorted(self.processor.element_hiding_rules):
            content.append(rule)
        
        content.extend([
            "!",
            "! ========== 脚本拦截规则 =========="
        ])
        
        # 添加脚本拦截规则
        for rule in sorted(self.processor.script_blocking_rules):
            content.append(rule)
        
        content.extend([
            "!",
            "! ========== 黑名单规则 =========="
        ])
        
        # 添加黑名单规则
        for domain in sorted(self.enhanced_domains):
            content.append(f"||{domain}^")
        
        return '\n'.join(content)
    
    def _generate_dns_rules(self, timestamp: str) -> str:
        """生成DNS规则"""
        content = [
            f"# DNS过滤规则 v{self.version}",
            f"# 生成时间: {timestamp}",
            f"# 域名数量: {len(self.enhanced_domains)}",
            "#"
        ]
        
        for domain in sorted(self.enhanced_domains):
            content.append(domain)
        
        return '\n'.join(content)
    
    def _generate_hosts_rules(self, timestamp: str) -> str:
        """生成Hosts规则"""
        content = [
            f"# Hosts格式广告过滤规则 v{self.version}",
            f"# 生成时间: {timestamp}",
            f"# 域名数量: {len(self.enhanced_domains)}",
            "#",
            "127.0.0.1 localhost",
            "::1 localhost",
            "#"
        ]
        
        for domain in sorted(self.enhanced_domains):
            content.append(f"0.0.0.0 {domain}")
        
        return '\n'.join(content)
    
    def _generate_enhanced_rules(self, timestamp: str) -> str:
        """生成增强规则"""
        content = [
            f"! 增强广告过滤规则 v{self.version}",
            f"! 生成时间: {timestamp}",
            f"! 增强拦截域名: {len(self.processor.enhanced_domains)}",
            "!",
            "! ========== 分析工具拦截 =========="
        ]
        
        # 添加增强拦截规则
        for domain in sorted(self.processor.enhanced_domains):
            content.append(f"||{domain}^$third-party")
        
        return '\n'.join(content)
    
    def _generate_info_file(self, timestamp: str) -> str:
        """生成信息文件"""
        info = {
            'version': self.version,
            'build_date': self.build_date,
            'timestamp': timestamp,
            'stats': self.processor.stats,
            'metrics': self.monitor.metrics,
            'config': {
                'github': self.config.get('github'),
                'performance': self.config.get('performance'),
                'rules': {
                    'blacklist_count': len(self.black_domains),
                    'whitelist_count': len(self.white_domains),
                    'enhanced_count': len(self.enhanced_domains)
                }
            },
            'files': {
                'ad_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/ad.txt",
                'dns_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/dns.txt",
                'hosts_txt': f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}/rules/outputs/hosts.txt"
            }
        }
        
        return json.dumps(info, indent=2, ensure_ascii=False)
    
    def _generate_reports(self) -> None:
        """生成报告"""
        # 这里实现报告生成逻辑
        pass
    
    def _generate_readme(self) -> None:
        """生成README.md"""
        base_url = f"https://raw.githubusercontent.com/{self.config.get('github.user')}/{self.config.get('github.repo')}/{self.config.get('github.branch')}"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{self.config.get('github.user')}/{self.config.get('github.repo')}@{self.config.get('github.branch')}"
        
        readme_content = f"""# 广告过滤规则 v{self.version}

一个精准的广告过滤规则集合，自动更新维护，适用于各种广告拦截器、DNS过滤器和Hosts文件。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/rules/outputs/ad.txt` | `{cdn_url}/rules/outputs/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/rules/outputs/dns.txt` | `{cdn_url}/rules/outputs/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/rules/outputs/hosts.txt` | `{cdn_url}/rules/outputs/hosts.txt` |
| 增强过滤规则 | Enhanced | `{base_url}/rules/outputs/enhanced.txt` | `{cdn_url}/rules/outputs/enhanced.txt` |
| 隐私保护规则 | Privacy | `{base_url}/rules/outputs/privacy.txt` | `{cdn_url}/rules/outputs/privacy.txt` |

## 统计数据

- **黑名单域名**: {len(self.black_domains):,}
- **白名单域名**: {len(self.white_domains):,}
- **增强拦截域名**: {len(self.enhanced_domains):,}
- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 更新频率

规则每天自动更新，更新时间：北京时间 02:00

## 许可证

MIT License

Copyright (c) {datetime.now().year} {self.config.get('project.author')}
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)


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
        '--output', '-o',
        help='输出目录'
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
        print("✅ 规则生成成功！")
        print(f"📁 输出目录: {generator.config.get('paths.outputs_dir')}")
        print("📖 查看README.md获取订阅链接")
    else:
        print("❌ 规则生成失败！")
        sys.exit(1)


if __name__ == "__main__":
    import sys
    main()
