#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 完整版
包含补充的规则处理思路
"""

import os
import re
import json
import time
import hashlib
import concurrent.futures
from datetime import datetime, timedelta
from typing import Set, List, Tuple, Optional, Dict
import requests

# 配置信息
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 8,
    'TIMEOUT': 25,
    'RETRY': 3,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 重要域名保护
    'PROTECTED_DOMAINS': {
        'google.com', 'github.com', 'microsoft.com', 'apple.com',
        'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'weibo.com',
        'zhihu.com', 'bilibili.com', '163.com', '126.com',
        'gitee.com', 'csdn.net', 'oschina.net'
    },
    
    # 关键广告域名（必须包含）
    'CRITICAL_AD_DOMAINS': {
        'doubleclick.net',
        'google-analytics.com',
        'googlesyndication.com',
        'googleadservices.com',
        'adservice.google.com',
        'ads.google.com',
        'scorecardresearch.com',
        'outbrain.com',
        'taboola.com',
        'criteo.com'
    },
    
    # 应排除的白名单模式
    'WHITELIST_PATTERNS': [
        '@@||google.com^',
        '@@||github.com^',
        '@@||baidu.com^',
        '@@||microsoft.com^'
    ]
}

class AdvancedAdBlockGenerator:
    def __init__(self):
        # 核心数据集合
        self.all_black_domains = set()
        self.all_white_domains = set()
        self.all_black_rules = []
        self.all_white_rules = []
        self.element_hiding_rules = []
        self.url_pattern_rules = []
        
        # 最终输出
        self.final_black_domains = set()
        self.final_white_rules = []
        
        # 统计
        self.stats = {
            'total_lines': 0,
            'black_domains': 0,
            'white_domains': 0,
            'complex_rules': 0,
            'element_hiding': 0,
            'url_patterns': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源 - 完整版\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 1. AdGuard基础广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# 2. EasyList规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 3. EasyPrivacy规则\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n\n")
                f.write("# 4. 中文广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n\n")
                f.write("# 5. 元素隐藏规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n")
                f.write("https://easylist-downloads.adblockplus.org/easyprivacy.txt\n\n")
                f.write("# 6. 防跟踪规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt\n")
        
        # 白名单源
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含白名单规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 手动添加重要白名单\n")
                f.write("# 格式：@@||domain.com^\n")
                f.write("@@||google.com^\n")
                f.write("@@||github.com^\n")
                f.write("@@||baidu.com^\n")
                f.write("@@||zhihu.com^\n")
                f.write("@@||bilibili.com^\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain, */*',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(2)
                else:
                    print(f"  ❌ 下载失败 {url}: {str(e)[:100]}")
        return None
    
    def is_element_hiding_rule(self, rule: str) -> bool:
        """判断是否是元素隐藏规则"""
        rule = rule.strip()
        
        # CSS元素隐藏规则
        if rule.startswith('##'):
            return True
        
        # AdGuard元素隐藏规则
        if re.match(r'^[a-zA-Z0-9.-]+##', rule):
            return True
        
        # 包含CSS选择器的规则
        if re.search(r'#(#|@)?[\.#\[]', rule):
            return True
        
        return False
    
    def extract_url_pattern(self, rule: str) -> Optional[str]:
        """提取URL模式规则"""
        rule = rule.strip()
        
        # URL模式匹配
        patterns = [
            r'^\|\|([^\\^\$]+)\^',        # ||example.com/path^
            r'^\|([^\\|]+)\|',            # |http://example.com|
            r'^/.*/$',                     # /ads/.*/
            r'^\*://\*\.([^/]+)/\*',      # *://*.example.com/*
            r'^https?://[^\$]+',          # http://example.com
            r'^//[^\$]+',                  # //example.com
        ]
        
        for pattern in patterns:
            if re.match(pattern, rule):
                return rule
        
        return None
    
    def parse_modifier_rule(self, rule: str) -> Tuple[str, Optional[str]]:
        """解析带修饰符的规则"""
        rule = rule.strip()
        domain = None
        
        # 分离规则主体和修饰符
        if '$' in rule:
            parts = rule.split('$', 1)
            rule_part = parts[0]
            modifier_part = parts[1]
            
            # 提取域名修饰符
            domain_match = re.search(r'domain=([a-zA-Z0-9.-]+)', modifier_part)
            if domain_match:
                domain = domain_match.group(1).lower()
            
            return rule_part, domain
        
        return rule, None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        local_domains = {
            'localhost', 'local', 'broadcasthost',
            '0.0.0.0', '127.0.0.1', '::1',
            'ip6-localhost', 'ip6-loopback'
        }
        if domain in local_domains:
            return False
        
        # 排除IP地址
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # 检查域名格式
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 检查每个部分
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def normalize_domain(self, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""
        
        domain = domain.lower().strip()
        
        # 移除常见前缀
        prefixes = ['www.', '*.', 'm.', 'mobile.']
        for prefix in prefixes:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # 移除常见后缀
        suffixes = ['.', '^', '$', '|', '~']
        for suffix in suffixes:
            if domain.endswith(suffix):
                domain = domain[:-len(suffix)]
        
        # 移除端口号
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def extract_domain_from_rule(self, rule: str) -> Tuple[List[str], bool]:
        """从规则中提取域名"""
        rule = rule.strip()
        if not rule:
            return [], False
        
        # 判断是否是白名单
        is_whitelist = rule.startswith('@@')
        
        # 如果是白名单规则，移除@@前缀
        if is_whitelist:
            rule = rule[2:]
        
        # 解析修饰符规则
        rule, modifier_domain = self.parse_modifier_rule(rule)
        
        domains = []
        
        # 尝试匹配多种域名格式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',          # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)/',           # ||domain.com/
            r'^([a-zA-Z0-9.-]+)\^$',             # domain.com^
            r'^\*\.([a-zA-Z0-9.-]+)',            # *.domain.com
            r'^([a-zA-Z0-9.-]+)$',               # domain.com
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',    # 通用域名匹配
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, rule)
            for match in matches:
                if isinstance(match, tuple):
                    domain = match[0]
                else:
                    domain = match
                
                domain = self.normalize_domain(domain)
                if self.is_valid_domain(domain):
                    domains.append(domain)
        
        # 添加修饰符中的域名
        if modifier_domain:
            domain = self.normalize_domain(modifier_domain)
            if self.is_valid_domain(domain):
                domains.append(domain)
        
        # 去重
        domains = list(set(domains))
        
        return domains, is_whitelist
    
    def classify_rule(self, rule: str) -> Tuple[str, List[str], str]:
        """分类规则类型"""
        self.stats['total_lines'] += 1
        
        rule = rule.strip()
        if not rule:
            return 'empty', [], rule
        
        # 跳过注释
        if rule.startswith('!') or rule.startswith('#'):
            return 'comment', [], rule
        
        # 检查元素隐藏规则
        if self.is_element_hiding_rule(rule):
            self.stats['element_hiding'] += 1
            return 'element_hiding', [], rule
        
        # 检查URL模式规则
        url_pattern = self.extract_url_pattern(rule)
        if url_pattern:
            self.stats['url_patterns'] += 1
            return 'url_pattern', [], rule
        
        # 提取域名
        domains, is_whitelist = self.extract_domain_from_rule(rule)
        
        if domains:
            if is_whitelist:
                self.stats['white_domains'] += len(domains)
                return 'white_domain', domains, rule
            else:
                self.stats['black_domains'] += len(domains)
                return 'black_domain', domains, rule
        
        # 复杂规则
        self.stats['complex_rules'] += 1
        if is_whitelist:
            return 'white_rule', [], rule
        else:
            return 'black_rule', [], rule
    
    def process_rule(self, rule: str, source_url: str = ""):
        """处理单条规则"""
        rule_type, domains, original_rule = self.classify_rule(rule)
        
        if not original_rule or rule_type in ['empty', 'comment']:
            return
        
        if rule_type == 'element_hiding':
            self.element_hiding_rules.append(original_rule)
        elif rule_type == 'url_pattern':
            self.url_pattern_rules.append(original_rule)
        elif rule_type == 'white_domain':
            self.all_white_domains.update(domains)
            self.all_white_rules.append(original_rule)
        elif rule_type == 'black_domain':
            self.all_black_domains.update(domains)
        elif rule_type == 'white_rule':
            self.all_white_rules.append(original_rule)
        elif rule_type == 'black_rule':
            self.all_black_rules.append(original_rule)
    
    def process_url(self, url: str):
        """处理单个规则源URL"""
        print(f"  📥 处理: {url}")
        content = self.download_content(url)
        if not content:
            return
        
        lines = content.split('\n')
        domains_found = 0
        
        for line in lines:
            self.process_rule(line, url)
        
        print(f"  ✓ 完成: {len(lines)} 行")
    
    def load_and_process_sources(self):
        """加载并处理所有规则源"""
        print("🔍 加载规则源...")
        
        # 读取黑名单源
        blacklist_urls = []
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist_urls.append(line)
        
        # 读取白名单源
        whitelist_urls = []
        local_whitelist = []
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line.startswith('http'):
                            whitelist_urls.append(line)
                        else:
                            local_whitelist.append(line)
        
        print(f"  黑名单源: {len(blacklist_urls)} 个")
        print(f"  白名单源: {len(whitelist_urls)} 个")
        print(f"  本地白名单规则: {len(local_whitelist)} 条")
        
        # 处理本地白名单规则
        for rule in local_whitelist:
            self.process_rule(rule, "local_whitelist")
        
        # 并行处理所有URL
        all_urls = blacklist_urls + whitelist_urls
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url in all_urls:
                future = executor.submit(self.process_url, url)
                futures.append(future)
            
            # 等待所有任务完成
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=35)
                    completed += 1
                    print(f"  ✅ [{completed}/{len(all_urls)}] 处理完成")
                except Exception as e:
                    print(f"  ❌ 处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.all_black_domains):,} 个")
        print(f"   白名单域名: {len(self.all_white_domains):,} 个")
        print(f"   黑名单规则: {len(self.all_black_rules):,} 条")
        print(f"   白名单规则: {len(self.all_white_rules):,} 条")
        print(f"   元素隐藏规则: {len(self.element_hiding_rules):,} 条")
        print(f"   URL模式规则: {len(self.url_pattern_rules):,} 条")
    
    def enhance_critical_domains(self):
        """增强关键广告域名"""
        print("🛡️  增强关键广告域名...")
        
        added = 0
        for domain in CONFIG['CRITICAL_AD_DOMAINS']:
            if domain not in self.all_white_domains:
                self.all_black_domains.add(domain)
                added += 1
        
        if added > 0:
            print(f"  添加 {added} 个关键广告域名")
    
    def apply_whitelist(self):
        """应用白名单"""
        print("🔄 应用白名单...")
        
        # 最终黑名单 = 所有黑名单 - 所有白名单
        self.final_black_domains = self.all_black_domains.copy()
        self.final_white_rules = self.all_white_rules.copy()
        
        original_count = len(self.final_black_domains)
        
        # 移除完全匹配的白名单域名
        domains_to_remove = set()
        for domain in self.final_black_domains:
            if domain in self.all_white_domains:
                domains_to_remove.add(domain)
        
        # 保护重要域名
        for protected in CONFIG['PROTECTED_DOMAINS']:
            if protected in domains_to_remove:
                domains_to_remove.remove(protected)
                print(f"  🛡️  保护重要域名: {protected}")
        
        self.final_black_domains -= domains_to_remove
        
        removed = original_count - len(self.final_black_domains)
        print(f"  移除 {removed} 个白名单域名")
        print(f"  最终黑名单域名: {len(self.final_black_domains):,} 个")
    
    def generate_files(self):
        """生成所有规则文件"""
        print("📁 生成规则文件...")
        
        # 获取北京时间
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # 生成ad.txt
        self.generate_adblock_file(version, timestamp)
        
        # 生成dns.txt
        self.generate_dns_file(version, timestamp)
        
        # 生成hosts.txt
        self.generate_hosts_file(version, timestamp)
        
        # 生成black.txt
        self.generate_blacklist_file(version, timestamp)
        
        # 生成white.txt
        self.generate_whitelist_file(version, timestamp)
        
        # 生成info.json
        self.generate_info_file(version, timestamp)
        
        # 生成补充文件
        self.generate_supplementary_files(version, timestamp)
    
    def generate_adblock_file(self, version: str, timestamp: str):
        """生成AdBlock格式规则文件"""
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 完整版 v{version}\n")
            f.write(f"! 更新时间: {timestamp} (北京时间)\n")
            f.write(f"! 黑名单域名: {len(self.final_black_domains):,} 个\n")
            f.write(f"! 白名单规则: {len(set(self.final_white_rules)):,} 条\n")
            f.write(f"! 元素隐藏规则: {len(self.element_hiding_rules):,} 条\n")
            f.write(f"! URL模式规则: {len(self.url_pattern_rules):,} 条\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.final_white_rules:
                f.write("! ====== 白名单规则 ======\n")
                unique_white_rules = sorted(set(self.final_white_rules))
                for rule in unique_white_rules:
                    f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单域名规则
            f.write("! ====== 域名黑名单 ======\n")
            for domain in sorted(self.final_black_domains):
                f.write(f"||{domain}^\n")
            
            # 复杂黑名单规则
            if self.all_black_rules:
                f.write("\n! ====== 复杂规则 ======\n")
                unique_black_rules = sorted(set(self.all_black_rules))
                for rule in unique_black_rules:
                    f.write(f"{rule}\n")
            
            # URL模式规则
            if self.url_pattern_rules:
                f.write("\n! ====== URL模式规则 ======\n")
                unique_url_rules = sorted(set(self.url_pattern_rules))
                for rule in unique_url_rules:
                    f.write(f"{rule}\n")
    
    def generate_dns_file(self, version: str, timestamp: str):
        """生成DNS格式规则文件"""
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            
            # 分组写入
            domains = sorted(self.final_black_domains)
            batch_size = 1000
            
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                if i > 0:
                    f.write("\n")
                for domain in batch:
                    f.write(f"{domain}\n")
    
    def generate_hosts_file(self, version: str, timestamp: str):
        """生成Hosts格式规则文件"""
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            f.write("# 本地域名\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n\n")
            
            # 分批写入
            batch_size = 500
            domains = sorted(self.final_black_domains)
            
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                f.write(f"# 第 {i//batch_size + 1} 组 ({len(batch)}个域名)\n")
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("\n")
    
    def generate_blacklist_file(self, version: str, timestamp: str):
        """生成纯黑名单文件"""
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 黑名单规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write("#\n\n")
            
            for domain in sorted(self.final_black_domains):
                f.write(f"||{domain}^\n")
    
    def generate_whitelist_file(self, version: str, timestamp: str):
        """生成纯白名单文件"""
        unique_white_rules = sorted(set(self.final_white_rules))
        
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 规则数量: {len(unique_white_rules):,} 条\n")
            f.write("#\n\n")
            
            # 域名白名单
            domain_whitelist = [r for r in unique_white_rules if r.startswith('@@||') and r.endswith('^')]
            if domain_whitelist:
                f.write("# 域名白名单\n")
                for rule in domain_whitelist:
                    f.write(f"{rule}\n")
                f.write("\n")
            
            # 其他白名单规则
            other_whitelist = [r for r in unique_white_rules if r not in domain_whitelist]
            if other_whitelist:
                f.write("# 其他白名单规则\n")
                for rule in other_whitelist:
                    f.write(f"{rule}\n")
    
    def generate_info_file(self, version: str, timestamp: str):
        """生成信息文件"""
        info = {
            'version': version,
            'updated_at': timestamp,
            'timezone': 'Asia/Shanghai (UTC+8)',
            'statistics': {
                'total_lines_processed': self.stats['total_lines'],
                'blacklist_domains': self.stats['black_domains'],
                'whitelist_domains': self.stats['white_domains'],
                'complex_rules': self.stats['complex_rules'],
                'element_hiding_rules': self.stats['element_hiding'],
                'url_pattern_rules': self.stats['url_patterns'],
                'final_blacklist_domains': len(self.final_black_domains),
                'final_whitelist_rules': len(set(self.final_white_rules))
            },
            'files': {
                'ad.txt': 'AdBlock完整规则',
                'dns.txt': 'DNS过滤规则',
                'hosts.txt': 'Hosts格式规则',
                'black.txt': '纯黑名单',
                'white.txt': '纯白名单'
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_supplementary_files(self, version: str, timestamp: str):
        """生成补充文件"""
        # 1. 生成元素隐藏规则文件
        if self.element_hiding_rules:
            with open('rules/outputs/element_hiding.txt', 'w', encoding='utf-8') as f:
                f.write(f"# 元素隐藏规则 v{version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write(f"# 规则数量: {len(self.element_hiding_rules):,} 条\n")
                f.write("#\n\n")
                
                unique_rules = sorted(set(self.element_hiding_rules))
                for rule in unique_rules:
                    f.write(f"{rule}\n")
        
        # 2. 生成关键域名列表
        with open('rules/outputs/critical_domains.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 关键广告域名 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write("#\n\n")
            
            for domain in sorted(CONFIG['CRITICAL_AD_DOMAINS']):
                f.write(f"{domain}\n")
        
        # 3. 生成简化版DNS规则（用于内存有限的设备）
        if len(self.final_black_domains) > 5000:
            top_domains = sorted(self.final_black_domains)[:5000]
            with open('rules/outputs/dns_light.txt', 'w', encoding='utf-8') as f:
                f.write(f"# 轻量DNS规则 v{version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write(f"# 域名数量: {len(top_domains):,} 个\n")
                f.write("#\n\n")
                
                for domain in top_domains:
                    f.write(f"{domain}\n")
    
    def generate_readme(self):
        """生成README.md文件"""
        print("📖 生成README.md...")
        
        # 读取规则信息
        with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        # 生成订阅链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        # 生成README内容
        readme = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于AdGuard、uBlock Origin、AdBlock Plus、AdGuard Home、Pi-hole等。

---

## 订阅地址

| 规则类型 | 规则说明 | 原始链接 | 加速链接 |
|:---------|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| **白名单规则** | 排除误拦域名 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |
| **轻量DNS规则** | 适用于内存有限的设备 | `{base_url}/dns_light.txt` | `{cdn_url}/dns_light.txt` |

**版本 {info['version']} 统计：**
- 黑名单域名：{info['statistics']['final_blacklist_domains']:,} 个
- 白名单规则：{info['statistics']['final_whitelist_rules']:,} 条
- 元素隐藏规则：{info['statistics']['element_hiding_rules']:,} 条

---

## 最新更新时间

**{info['updated_at']}** (北京时间)

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
    
    def get_beijing_time(self) -> datetime:
        """获取北京时间"""
        try:
            from datetime import timezone
            utc_now = datetime.now(timezone.utc)
            beijing_time = utc_now + timedelta(hours=8)
            return beijing_time
        except:
            return datetime.now()
    
    def run_quality_check(self):
        """运行质量检查"""
        print("🔍 运行质量检查...")
        
        # 检查关键广告域名是否包含
        missing_critical = []
        for domain in CONFIG['CRITICAL_AD_DOMAINS']:
            if domain not in self.final_black_domains:
                missing_critical.append(domain)
        
        if missing_critical:
            print(f"⚠️  警告: 缺失 {len(missing_critical)} 个关键广告域名")
            for domain in missing_critical[:5]:
                print(f"   - {domain}")
        
        # 检查白名单是否过度
        if len(self.final_white_rules) > 1000:
            print(f"⚠️  警告: 白名单规则过多 ({len(self.final_white_rules)} 条)")
        
        # 检查域名重复
        if len(self.final_black_domains) < self.stats['black_domains'] * 0.5:
            print("⚠️  警告: 可能过多域名被白名单移除")
        
        print("✅ 质量检查完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 高级广告过滤规则生成器")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载并处理规则源
            self.load_and_process_sources()
            
            # 2. 增强关键广告域名
            self.enhance_critical_domains()
            
            # 3. 应用白名单
            self.apply_whitelist()
            
            # 4. 运行质量检查
            self.run_quality_check()
            
            # 5. 生成所有文件
            self.generate_files()
            
            # 6. 生成README
            self.generate_readme()
            
            # 统计信息
            end_time = time.time()
            elapsed = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 最终黑名单域名: {len(self.final_black_domains):,}个")
            print(f"📊 白名单规则: {len(set(self.final_white_rules)):,}条")
            print("📁 生成的规则文件:")
            print("  - rules/outputs/ad.txt")
            print("  - rules/outputs/dns.txt")
            print("  - rules/outputs/hosts.txt")
            print("  - rules/outputs/black.txt")
            print("  - rules/outputs/white.txt")
            print("  - rules/outputs/element_hiding.txt (可选)")
            print("  - rules/outputs/dns_light.txt (可选)")
            print("📖 使用说明: README.md")
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
    
    # 运行生成器
    generator = AdvancedAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
        print("🔬 建议运行测试脚本检查规则质量")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
