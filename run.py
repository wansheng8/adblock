#!/usr/bin/env python3
"""
广告过滤规则集合器 - 主程序
自动从多个源收集、合并和优化广告过滤规则
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import List, Set, Dict
from urllib.parse import urlparse
import hashlib
import re

class AdBlockRuleAggregator:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.sources_dir = self.base_dir / "rules" / "sources"
        self.outputs_dir = self.base_dir / "rules" / "outputs"
        
        # 确保目录存在
        self.sources_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化统计信息
        self.stats = {
            "total_rules": 0,
            "adblock_rules": 0,
            "dns_rules": 0,
            "hosts_rules": 0,
            "black_rules": 0,
            "white_rules": 0,
            "sources_count": 0,
            "last_updated": "",
            "rule_types": {
                "element_hiding": 0,
                "url_blocking": 0,
                "popup_blocking": 0,
                "analytics_blocking": 0,
                "malware_blocking": 0,
                "annoyance_blocking": 0
            }
        }
        
        # 规则缓存
        self.adblock_rules = set()
        self.dns_rules = set()
        self.hosts_rules = set()
        self.black_rules = set()
        self.white_rules = set()

    def load_sources(self, source_type: str) -> List[str]:
        """加载规则源"""
        source_file = self.sources_dir / f"{source_type}.txt"
        sources = []
        
        if source_file.exists():
            with open(source_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        sources.append(line)
        
        return sources

    def download_rules(self, url: str) -> List[str]:
        """下载规则"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # 处理不同编码
            response.encoding = response.apparent_encoding
            
            rules = []
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith('!'):
                    rules.append(line)
            
            return rules
            
        except Exception as e:
            print(f"下载失败 {url}: {e}")
            return []

    def classify_rule(self, rule: str) -> str:
        """分类规则类型"""
        # Adblock规则
        if any(rule.startswith(prefix) for prefix in ['||', '|', '||', '##', '#@#', '#?##']):
            return 'adblock'
        
        # DNS规则 (域名规则)
        elif re.match(r'^[a-zA-Z0-9.*-]+$', rule) and '.' in rule:
            return 'dns'
        
        # Hosts规则
        elif re.match(r'^\s*\d+\.\d+\.\d+\.\d+\s+', rule):
            return 'hosts'
        
        # 白名单规则
        elif rule.startswith('@@'):
            return 'white'
        
        # 黑名单规则
        else:
            return 'black'

    def analyze_rule_type(self, rule: str) -> str:
        """分析规则的具体类型"""
        rule_lower = rule.lower()
        
        # 元素隐藏规则
        if rule.startswith('##') or rule.startswith('#@#') or rule.startswith('#?##'):
            return 'element_hiding'
        
        # 弹窗拦截
        elif 'popup' in rule_lower or '$popup' in rule:
            return 'popup_blocking'
        
        # 分析工具拦截
        elif any(word in rule_lower for word in ['analytics', 'google-analytics', 'gtag', 'ga.js']):
            return 'analytics_blocking'
        
        # 恶意软件拦截
        elif any(word in rule_lower for word in ['malware', 'phishing', 'scam', 'malicious']):
            return 'malware_blocking'
        
        # 恼人内容拦截
        elif any(word in rule_lower for word in ['annoyance', 'cookie', 'gdpr', 'consent']):
            return 'annoyance_blocking'
        
        # URL拦截
        else:
            return 'url_blocking'

    def process_rule(self, rule: str, source_type: str):
        """处理单个规则"""
        if not rule or len(rule) > 2000:  # 避免超长规则
            return
        
        # 去重
        rule_hash = hashlib.md5(rule.encode()).hexdigest()
        
        # 分类规则
        rule_class = self.classify_rule(rule)
        rule_type = self.analyze_rule_type(rule)
        
        # 根据来源类型和规则类型分类存储
        if source_type == 'white':
            self.white_rules.add(rule)
            self.stats['rule_types'][rule_type] += 1
        else:
            if rule_class == 'adblock':
                self.adblock_rules.add(rule)
            elif rule_class == 'dns':
                self.dns_rules.add(rule)
            elif rule_class == 'hosts':
                self.hosts_rules.add(rule)
            else:
                self.black_rules.add(rule)
            
            # 更新统计
            self.stats['rule_types'][rule_type] += 1

    def optimize_rules(self):
        """优化规则集合"""
        # 移除被白名单覆盖的规则
        white_patterns = set()
        for white_rule in self.white_rules:
            if white_rule.startswith('@@'):
                pattern = white_rule[2:]  # 移除@@前缀
                white_patterns.add(pattern)
        
        # 过滤掉被白名单覆盖的黑名单规则
        filtered_adblock = set()
        for rule in self.adblock_rules:
            if not any(pattern in rule for pattern in white_patterns):
                filtered_adblock.add(rule)
        
        filtered_dns = set()
        for rule in self.dns_rules:
            if not any(pattern in rule for pattern in white_patterns):
                filtered_dns.add(rule)
        
        filtered_hosts = set()
        for rule in self.hosts_rules:
            if not any(pattern in rule for pattern in white_patterns):
                filtered_hosts.add(rule)
        
        # 应用优化后的规则集
        self.adblock_rules = filtered_adblock
        self.dns_rules = filtered_dns
        self.hosts_rules = filtered_hosts

    def save_rules(self):
        """保存规则到文件"""
        # 更新时间
        self.stats['last_updated'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 保存Adblock规则
        adblock_file = self.outputs_dir / "ad.txt"
        with open(adblock_file, 'w', encoding='utf-8') as f:
            f.write("! 广告过滤规则 - 生成时间: {}\n".format(self.stats['last_updated']))
            f.write("! 包含: 元素隐藏规则, 横幅广告拦截, 弹窗广告拦截, 分析工具拦截等\n")
            f.write("! 规则数量: {}\n".format(len(self.adblock_rules)))
            f.write("! 项目地址: https://github.com/wansheng8/adblock\n\n")
            
            for rule in sorted(self.adblock_rules):
                f.write(rule + '\n')
        
        # 保存DNS规则
        dns_file = self.outputs_dir / "dns.txt"
        with open(dns_file, 'w', encoding='utf-8') as f:
            f.write("# DNS过滤规则\n")
            f.write("# 生成时间: {}\n".format(self.stats['last_updated']))
            f.write("# 规则数量: {}\n\n".format(len(self.dns_rules)))
            
            for rule in sorted(self.dns_rules):
                f.write(rule + '\n')
        
        # 保存Hosts规则
        hosts_file = self.outputs_dir / "hosts.txt"
        with open(hosts_file, 'w', encoding='utf-8') as f:
            f.write("# Hosts广告过滤规则\n")
            f.write("# 生成时间: {}\n".format(self.stats['last_updated']))
            f.write("# 规则数量: {}\n\n".format(len(self.hosts_rules)))
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            
            for rule in sorted(self.hosts_rules):
                f.write("0.0.0.0 " + rule.split()[-1] + '\n')
        
        # 保存黑名单规则
        black_file = self.outputs_dir / "black.txt"
        with open(black_file, 'w', encoding='utf-8') as f:
            f.write("# 通用黑名单规则\n")
            f.write("# 生成时间: {}\n".format(self.stats['last_updated']))
            f.write("# 规则数量: {}\n\n".format(len(self.black_rules)))
            
            for rule in sorted(self.black_rules):
                f.write(rule + '\n')
        
        # 保存白名单规则
        white_file = self.outputs_dir / "white.txt"
        with open(white_file, 'w', encoding='utf-8') as f:
            f.write("# 白名单/例外规则\n")
            f.write("# 生成时间: {}\n".format(self.stats['last_updated']))
            f.write("# 规则数量: {}\n\n".format(len(self.white_rules)))
            
            for rule in sorted(self.white_rules):
                f.write(rule + '\n')
        
        # 更新统计信息
        self.stats.update({
            'adblock_rules': len(self.adblock_rules),
            'dns_rules': len(self.dns_rules),
            'hosts_rules': len(self.hosts_rules),
            'black_rules': len(self.black_rules),
            'white_rules': len(self.white_rules),
            'total_rules': len(self.adblock_rules) + len(self.dns_rules) + 
                          len(self.hosts_rules) + len(self.black_rules)
        })
        
        # 保存信息文件
        info_file = self.outputs_dir / "info.json"
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2, ensure_ascii=False)

    def generate_readme(self):
        """生成README.md文件"""
        # 读取规则源
        black_sources = self.load_sources('black')
        white_sources = self.load_sources('white')
        
        # 读取统计信息
        info_file = self.outputs_dir / "info.json"
        if info_file.exists():
            with open(info_file, 'r', encoding='utf-8') as f:
                stats = json.load(f)
        else:
            stats = self.stats
        
        # 构建订阅链接表格
        subscription_table = "| 规则类型 | 订阅链接 | 规则数量 |\n"
        subscription_table += "|----------|----------|----------|\n"
        
        # GitHub Raw 链接基础URL
        base_url = "https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/"
        
        subscription_table += f"| Adblock规则 | [{base_url}ad.txt]({base_url}ad.txt) | {stats['adblock_rules']} |\n"
        subscription_table += f"| DNS规则 | [{base_url}dns.txt]({base_url}dns.txt) | {stats['dns_rules']} |\n"
        subscription_table += f"| Hosts规则 | [{base_url}hosts.txt]({base_url}hosts.txt) | {stats['hosts_rules']} |\n"
        subscription_table += f"| 黑名单规则 | [{base_url}black.txt]({base_url}black.txt) | {stats['black_rules']} |\n"
        subscription_table += f"| 白名单规则 | [{base_url}white.txt]({base_url}white.txt) | {stats['white_rules']} |\n"
        
        # 规则类型统计
        rule_types_table = "| 规则类型 | 数量 | 占比 |\n"
        rule_types_table += "|----------|------|------|\n"
        
        total = stats['total_rules']
        for rule_type, count in stats['rule_types'].items():
            if count > 0:
                percentage = (count / total * 100) if total > 0 else 0
                rule_types_table += f"| {rule_type.replace('_', ' ').title()} | {count} | {percentage:.1f}% |\n"
        
        # 生成README内容
        readme_content = f"""# AdBlock Rules Collection 🛡️

精准超级智能的广告过滤规则集合器，自动收集、合并和优化来自多个源的广告过滤规则。

## 📋 订阅链接

{subscription_table}

## 📊 规则统计

{rule_types_table}

## 🕒 最新更新时间

**{stats['last_updated']}** (UTC+8)

> ⚠️ 注意：这些规则可能会阻止网站的正常功能，使用时请根据需要调整
> 
> 🔄 规则每天自动更新，确保最新的广告过滤效果
> 
> 📚 项目地址：https://github.com/wansheng8/adblock
"""

        # 保存README.md
        readme_file = self.base_dir / "README.md"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_content)

    def run(self):
        """主运行函数"""
        print("开始收集广告过滤规则...")
        
        # 加载规则源
        black_sources = self.load_sources('black')
        white_sources = self.load_sources('white')
        
        print(f"找到 {len(black_sources)} 个黑名单源，{len(white_sources)} 个白名单源")
        
        # 处理黑名单规则源
        for i, url in enumerate(black_sources, 1):
            print(f"处理黑名单源 {i}/{len(black_sources)}: {url}")
            rules = self.download_rules(url)
            for rule in rules:
                self.process_rule(rule, 'black')
        
        # 处理白名单规则源
        for i, url in enumerate(white_sources, 1):
            print(f"处理白名单源 {i}/{len(white_sources)}: {url}")
            rules = self.download_rules(url)
            for rule in rules:
                self.process_rule(rule, 'white')
        
        # 优化规则
        print("优化规则集合...")
        self.optimize_rules()
        
        # 保存规则
        print("保存规则文件...")
        self.save_rules()
        
        # 生成README
        print("生成README.md...")
        self.generate_readme()
        
        print(f"完成！")
        print(f"生成规则统计:")
        print(f"  - Adblock规则: {len(self.adblock_rules)}")
        print(f"  - DNS规则: {len(self.dns_rules)}")
        print(f"  - Hosts规则: {len(self.hosts_rules)}")
        print(f"  - 黑名单规则: {len(self.black_rules)}")
        print(f"  - 白名单规则: {len(self.white_rules)}")

def main():
    aggregator = AdBlockRuleAggregator()
    aggregator.run()

if __name__ == "__main__":
    main()
