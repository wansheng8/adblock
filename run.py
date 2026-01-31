#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 结构化流程版
流程：采集 → 分类 → 去重 → 生成
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime, timedelta
from typing import Set, List, Tuple, Dict, Optional
import requests

# 配置信息
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 8,
    'TIMEOUT': 20,
    'RETRY': 3,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 关键广告域名（必须拦截）
    'CRITICAL_BLACK_DOMAINS': {
        'doubleclick.net',
        'google-analytics.com',
        'googlesyndication.com',
        'googleadservices.com',
        'adservice.google.com',
        'ads.google.com',
        'scorecardresearch.com',
        'outbrain.com',
        'taboola.com',
        'criteo.com',
        'adnxs.com',
        'amazon-adsystem.com',
        'facebook.net',
        'ads.facebook.com',
        'analytics.google.com'
    },
    
    # 必须放行的域名（真正的白名单）
    'CRITICAL_WHITE_DOMAINS': {
        'google.com',
        'github.com',
        'microsoft.com',
        'apple.com',
        'baidu.com',
        'qq.com',
        'zhihu.com',
        'bilibili.com'
    }
}

class StructuredAdBlockGenerator:
    def __init__(self):
        # 阶段1：采集的数据
        self.raw_black_rules = []    # 原始黑名单规则
        self.raw_white_rules = []    # 原始白名单规则
        
        # 阶段2：分类后的数据
        self.classified_black_domains = set()  # 分类出的黑名单域名
        self.classified_white_domains = set()  # 分类出的白名单域名
        self.classified_complex_black = []     # 分类出的复杂黑名单规则
        self.classified_complex_white = []     # 分类出的复杂白名单规则
        
        # 阶段3：去重后的数据
        self.unique_black_domains = set()      # 去重后的黑名单域名
        self.unique_white_domains = set()      # 去重后的白名单域名
        self.unique_complex_black = []         # 去重后的复杂黑名单
        self.unique_complex_white = []         # 去重后的复杂白名单
        
        # 阶段4：最终输出数据
        self.final_black_domains = set()       # 最终黑名单域名
        self.final_white_rules = []            # 最终白名单规则
        
        # 统计信息
        self.statistics = {
            'total_urls': 0,
            'total_lines': 0,
            'black_domains_found': 0,
            'white_domains_found': 0,
            'complex_rules_found': 0,
            'duplicates_removed': 0,
            'processing_time': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    # ========== 阶段1：采集 ==========
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 主要广告规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# EasyList规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 中文规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n")
        
        # 白名单源
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含白名单规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 手动添加的白名单\n")
                f.write("@@||google.com^\n")
                f.write("@@||github.com^\n")
                f.write("@@||baidu.com^\n")
                f.write("@@||qq.com^\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain, */*'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(1)
                else:
                    print(f"  ❌ 下载失败: {url}")
        return None
    
    def collect_rules_from_url(self, url: str, is_whitelist_source: bool = False):
        """从单个URL采集规则"""
        print(f"  📥 采集: {url}")
        content = self.download_content(url)
        if not content:
            return
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            self.statistics['total_lines'] += 1
            
            if is_whitelist_source:
                self.raw_white_rules.append(line)
            else:
                self.raw_black_rules.append(line)
        
        print(f"  ✓ 采集完成: {len(lines)} 行")
    
    def collect_all_sources(self):
        """采集所有规则源"""
        print("=" * 60)
        print("📥 阶段1: 采集黑/白名单源")
        print("=" * 60)
        
        # 读取黑名单源URL
        blacklist_urls = []
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist_urls.append((line, False))
        
        # 读取白名单源URL
        whitelist_urls = []
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line.startswith('http'):
                            whitelist_urls.append((line, True))
                        else:
                            # 直接添加到原始白名单规则
                            self.raw_white_rules.append(line)
        
        all_urls = blacklist_urls + whitelist_urls
        self.statistics['total_urls'] = len(all_urls)
        
        if not all_urls:
            print("  ⚠️ 未找到规则源URL")
            return
        
        print(f"  发现 {len(blacklist_urls)} 个黑名单源")
        print(f"  发现 {len(whitelist_urls)} 个白名单源")
        
        # 并行采集
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url, is_whitelist in all_urls:
                future = executor.submit(self.collect_rules_from_url, url, is_whitelist)
                futures.append(future)
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=30)
                    completed += 1
                    print(f"  ✅ [{completed}/{len(all_urls)}] 采集完成")
                except Exception as e:
                    print(f"  ❌ 采集失败: {e}")
        
        print(f"✅ 采集完成:")
        print(f"   原始黑名单规则: {len(self.raw_black_rules):,} 条")
        print(f"   原始白名单规则: {len(self.raw_white_rules):,} 条")
    
    # ========== 阶段2：分类 ==========
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        local_domains = {'localhost', 'local', 'broadcasthost', '0.0.0.0', '127.0.0.1', '::1'}
        if domain in local_domains:
            return False
        
        # 排除IP地址
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # 检查域名格式
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def extract_domain_from_rule(self, rule: str) -> Tuple[Optional[str], bool]:
        """从规则中提取域名"""
        rule = rule.strip()
        if not rule:
            return None, False
        
        # 判断是否是白名单规则
        is_whitelist = rule.startswith('@@')
        
        # 如果是白名单规则，移除@@前缀
        if is_whitelist:
            rule = rule[2:]
        
        # 匹配常见的域名格式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',     # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)/',      # ||domain.com/
            r'^([a-zA-Z0-9.-]+)\^$',        # domain.com^
            r'^([a-zA-Z0-9.-]+)$',          # domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',       # *.domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = match.group(1).lower().strip()
                
                # 移除www前缀
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, is_whitelist
    
    def classify_rule(self, rule: str, is_from_whitelist: bool):
        """分类单条规则"""
        domain, extracted_is_whitelist = self.extract_domain_from_rule(rule)
        
        # 确定规则类型
        is_whitelist_rule = is_from_whitelist or extracted_is_whitelist
        
        if domain:
            # 域名规则
            if is_whitelist_rule:
                self.classified_white_domains.add(domain)
                self.statistics['white_domains_found'] += 1
            else:
                self.classified_black_domains.add(domain)
                self.statistics['black_domains_found'] += 1
        else:
            # 复杂规则
            if is_whitelist_rule:
                self.classified_complex_white.append(rule)
                self.statistics['complex_rules_found'] += 1
            else:
                if len(rule) > 3:
                    self.classified_complex_black.append(rule)
                    self.statistics['complex_rules_found'] += 1
    
    def classify_all_rules(self):
        """分类所有规则"""
        print("\n" + "=" * 60)
        print("🔍 阶段2: 分类黑/白名单")
        print("=" * 60)
        
        print("  分类黑名单规则...")
        for rule in self.raw_black_rules:
            self.classify_rule(rule, False)
        
        print("  分类白名单规则...")
        for rule in self.raw_white_rules:
            self.classify_rule(rule, True)
        
        print(f"✅ 分类完成:")
        print(f"   分类出的黑名单域名: {len(self.classified_black_domains):,} 个")
        print(f"   分类出的白名单域名: {len(self.classified_white_domains):,} 个")
        print(f"   复杂黑名单规则: {len(self.classified_complex_black):,} 条")
        print(f"   复杂白名单规则: {len(self.classified_complex_white):,} 条")
    
    # ========== 阶段3：去重 ==========
    
    def deduplicate_data(self):
        """去重所有数据"""
        print("\n" + "=" * 60)
        print("✨ 阶段3: 黑/白名单去重")
        print("=" * 60)
        
        # 去重黑名单域名
        original_black_count = len(self.classified_black_domains)
        self.unique_black_domains = self.classified_black_domains.copy()
        black_duplicates = original_black_count - len(self.unique_black_domains)
        
        # 去重白名单域名
        original_white_count = len(self.classified_white_domains)
        self.unique_white_domains = self.classified_white_domains.copy()
        white_duplicates = original_white_count - len(self.unique_white_domains)
        
        # 去重复杂规则
        original_complex_black = len(self.classified_complex_black)
        self.unique_complex_black = list(set(self.classified_complex_black))
        complex_black_duplicates = original_complex_black - len(self.unique_complex_black)
        
        original_complex_white = len(self.classified_complex_white)
        self.unique_complex_white = list(set(self.classified_complex_white))
        complex_white_duplicates = original_complex_white - len(self.unique_complex_white)
        
        total_duplicates = (black_duplicates + white_duplicates + 
                           complex_black_duplicates + complex_white_duplicates)
        
        self.statistics['duplicates_removed'] = total_duplicates
        
        print(f"✅ 去重完成:")
        print(f"   黑名单域名去重: {black_duplicates} 个重复")
        print(f"   白名单域名去重: {white_duplicates} 个重复")
        print(f"   复杂黑名单去重: {complex_black_duplicates} 条重复")
        print(f"   复杂白名单去重: {complex_white_duplicates} 条重复")
        print(f"   总计移除重复: {total_duplicates:,} 条")
        print(f"   唯一黑名单域名: {len(self.unique_black_domains):,} 个")
        print(f"   唯一白名单域名: {len(self.unique_white_domains):,} 个")
    
    # ========== 阶段4：生成 ==========
    
    def apply_whitelist_logic(self):
        """应用白名单逻辑"""
        print("\n" + "=" * 60)
        print("⚙️  阶段4: 应用白名单逻辑")
        print("=" * 60)
        
        # 最终黑名单 = 唯一黑名单 - 白名单域名
        self.final_black_domains = self.unique_black_domains.copy()
        
        # 移除白名单域名（只移除完全匹配）
        domains_to_remove = set()
        for black_domain in self.final_black_domains:
            if black_domain in self.unique_white_domains:
                domains_to_remove.add(black_domain)
        
        self.final_black_domains -= domains_to_remove
        
        # 确保关键广告域名不被移除
        for critical_domain in CONFIG['CRITICAL_BLACK_DOMAINS']:
            if critical_domain not in self.final_black_domains:
                self.final_black_domains.add(critical_domain)
        
        # 确保真正的白名单域名被保留
        for white_domain in CONFIG['CRITICAL_WHITE_DOMAINS']:
            if white_domain in self.final_black_domains:
                self.final_black_domains.remove(white_domain)
            if white_domain not in self.unique_white_domains:
                self.unique_white_domains.add(white_domain)
        
        # 准备最终白名单规则
        for domain in self.unique_white_domains:
            self.final_white_rules.append(f"@@||{domain}^")
        self.final_white_rules.extend(self.unique_complex_white)
        
        print(f"✅ 白名单逻辑应用完成:")
        print(f"   移除 {len(domains_to_remove)} 个白名单域名")
        print(f"   最终黑名单域名: {len(self.final_black_domains):,} 个")
        print(f"   最终白名单规则: {len(self.final_white_rules):,} 条")
    
    def generate_file_by_type(self, file_type: str, version: str, timestamp: str):
        """根据类型生成文件"""
        print(f"  📄 生成 {file_type}.txt...")
        
        if file_type == 'ad':
            # AdBlock格式
            with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
                f.write(f"! 广告过滤规则 - {version}\n")
                f.write(f"! 更新时间: {timestamp}\n")
                f.write(f"! 黑名单域名: {len(self.final_black_domains):,} 个\n")
                f.write(f"! 白名单规则: {len(self.final_white_rules):,} 条\n")
                f.write("!\n\n")
                
                # 白名单规则
                if self.final_white_rules:
                    f.write("! ====== 白名单规则 ======\n")
                    for rule in sorted(set(self.final_white_rules)):
                        f.write(f"{rule}\n")
                    f.write("\n")
                
                # 黑名单域名规则
                f.write("! ====== 域名黑名单 ======\n")
                for domain in sorted(self.final_black_domains):
                    f.write(f"||{domain}^\n")
                
                # 复杂黑名单规则
                if self.unique_complex_black:
                    f.write("\n! ====== 复杂规则 ======\n")
                    for rule in sorted(set(self.unique_complex_black)):
                        f.write(f"{rule}\n")
        
        elif file_type == 'dns':
            # DNS格式
            with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
                f.write(f"# DNS广告过滤规则 - {version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
                f.write("#\n\n")
                
                # 关键域名在前
                critical_domains = []
                other_domains = []
                
                for domain in sorted(self.final_black_domains):
                    if domain in CONFIG['CRITICAL_BLACK_DOMAINS']:
                        critical_domains.append(domain)
                    else:
                        other_domains.append(domain)
                
                if critical_domains:
                    f.write("# 关键广告域名\n")
                    for domain in critical_domains:
                        f.write(f"{domain}\n")
                    f.write("\n")
                
                f.write("# 其他广告域名\n")
                for domain in other_domains:
                    f.write(f"{domain}\n")
        
        elif file_type == 'hosts':
            # Hosts格式
            with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
                f.write(f"# Hosts广告过滤规则 - {version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
                f.write("#\n\n")
                f.write("127.0.0.1 localhost\n")
                f.write("::1 localhost\n")
                f.write("#\n")
                f.write("# 广告域名\n\n")
                
                # 分批写入
                batch_size = 1000
                domains = sorted(self.final_black_domains)
                for i in range(0, len(domains), batch_size):
                    batch = domains[i:i+batch_size]
                    f.write(f"# 域名 {i+1}-{i+len(batch)}\n")
                    for domain in batch:
                        f.write(f"0.0.0.0 {domain}\n")
                    f.write("\n")
        
        elif file_type == 'black':
            # 纯黑名单
            with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
                f.write(f"# 黑名单规则 - {version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write("#\n\n")
                for domain in sorted(self.final_black_domains):
                    f.write(f"||{domain}^\n")
        
        elif file_type == 'white':
            # 纯白名单
            with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
                f.write(f"# 白名单规则 - {version}\n")
                f.write(f"# 更新时间: {timestamp}\n")
                f.write(f"# 规则数量: {len(set(self.final_white_rules)):,} 条\n")
                f.write("#\n\n")
                
                unique_rules = sorted(set(self.final_white_rules))
                domain_rules = [r for r in unique_rules if r.startswith('@@||')]
                other_rules = [r for r in unique_rules if r not in domain_rules]
                
                if domain_rules:
                    f.write("# 域名白名单\n")
                    for rule in domain_rules:
                        f.write(f"{rule}\n")
                    f.write("\n")
                
                if other_rules:
                    f.write("# 其他白名单规则\n")
                    for rule in other_rules:
                        f.write(f"{rule}\n")
        
        elif file_type == 'info':
            # 规则信息
            info = {
                'version': version,
                'updated_at': timestamp,
                'timezone': 'Asia/Shanghai (UTC+8)',
                'statistics': {
                    'total_urls': self.statistics['total_urls'],
                    'total_lines': self.statistics['total_lines'],
                    'black_domains_found': self.statistics['black_domains_found'],
                    'white_domains_found': self.statistics['white_domains_found'],
                    'complex_rules_found': self.statistics['complex_rules_found'],
                    'duplicates_removed': self.statistics['duplicates_removed'],
                    'final_blacklist_domains': len(self.final_black_domains),
                    'final_whitelist_rules': len(set(self.final_white_rules))
                }
            }
            
            with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
                json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_all_files(self):
        """生成所有文件"""
        print("\n" + "=" * 60)
        print("🚀 阶段5: 生成规则文件")
        print("=" * 60)
        
        # 获取时间
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d')
        
        # 生成各种类型的文件
        file_types = ['ad', 'dns', 'hosts', 'black', 'white', 'info']
        
        for file_type in file_types:
            self.generate_file_by_type(file_type, version, timestamp)
        
        print(f"✅ 文件生成完成:")
        for file_type in file_types:
            if file_type == 'ad':
                print(f"   ad.txt - AdBlock格式 ({len(self.final_black_domains):,}个域名)")
            elif file_type == 'dns':
                print(f"   dns.txt - DNS格式 ({len(self.final_black_domains):,}个域名)")
            elif file_type == 'hosts':
                print(f"   hosts.txt - Hosts格式 ({len(self.final_black_domains):,}个域名)")
            elif file_type == 'black':
                print(f"   black.txt - 黑名单规则")
            elif file_type == 'white':
                print(f"   white.txt - 白名单规则 ({len(set(self.final_white_rules)):,}条)")
            elif file_type == 'info':
                print(f"   info.json - 规则信息")
    
    def generate_readme(self):
        """生成README.md"""
        print("\n" + "=" * 60)
        print("📖 生成README.md")
        print("=" * 60)
        
        with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        readme = f"""# 广告过滤规则

一个结构化生成的广告过滤规则集合，适用于AdGuard、uBlock Origin、AdBlock Plus等。

---

## 订阅地址

| 规则类型 | 规则说明 | 原始链接 | 加速链接 |
|:---------|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| **白名单规则** | 排除误拦域名 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 统计：**
- 黑名单域名：{info['statistics']['final_blacklist_domains']:,} 个
- 白名单规则：{info['statistics']['final_whitelist_rules']:,} 条

---

## 最新更新时间

**{info['updated_at']}** (北京时间)

*规则每天自动更新*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("✅ README.md生成完成")
    
    def run_validation(self):
        """运行验证检查"""
        print("\n" + "=" * 60)
        print("🔍 验证检查")
        print("=" * 60)
        
        # 检查关键广告域名
        missing_critical = []
        for domain in CONFIG['CRITICAL_BLACK_DOMAINS']:
            if domain not in self.final_black_domains:
                missing_critical.append(domain)
        
        if missing_critical:
            print(f"⚠️  警告: 缺失 {len(missing_critical)} 个关键广告域名")
            for domain in missing_critical[:3]:
                print(f"   - {domain}")
        else:
            print("✅ 所有关键广告域名已包含")
        
        # 检查白名单数量
        white_count = len(set(self.final_white_rules))
        if white_count > 1000:
            print(f"⚠️  警告: 白名单规则过多 ({white_count} 条)")
        else:
            print(f"✅ 白名单数量合理 ({white_count} 条)")
        
        # 检查黑名单数量
        black_count = len(self.final_black_domains)
        if black_count < 10000:
            print(f"⚠️  警告: 黑名单域名过少 ({black_count:,} 个)")
        else:
            print(f"✅ 黑名单数量合理 ({black_count:,} 个)")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器 - 结构化流程")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 阶段1: 采集
            self.collect_all_sources()
            
            # 阶段2: 分类
            self.classify_all_rules()
            
            # 阶段3: 去重
            self.deduplicate_data()
            
            # 阶段4: 应用白名单逻辑
            self.apply_whitelist_logic()
            
            # 阶段5: 生成文件
            self.generate_all_files()
            
            # 生成README
            self.generate_readme()
            
            # 验证检查
            self.run_validation()
            
            # 统计
            end_time = time.time()
            elapsed = end_time - start_time
            self.statistics['processing_time'] = elapsed
            
            print("\n" + "=" * 60)
            print("🎉 流程完成！")
            print(f"⏱️  总耗时: {elapsed:.1f}秒")
            print(f"📊 最终统计:")
            print(f"   黑名单域名: {len(self.final_black_domains):,} 个")
            print(f"   白名单规则: {len(set(self.final_white_rules)):,} 条")
            print("📁 文件位置: rules/outputs/")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    generator = StructuredAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
