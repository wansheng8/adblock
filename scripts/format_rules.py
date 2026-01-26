#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 完整语法版
处理三层规则文件：DNS、Hosts、浏览器规则
支持完整语法处理
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import json


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
        # 规则分类
        self.rule_categories = {
            "whitelist": "白名单规则",
            "domain_block": "域名阻断规则",
            "exact_domain": "精确域名规则",
            "cname_block": "CNAME拦截规则",
            "element_hiding": "元素隐藏规则",
            "advanced": "高级规则",
            "category": "分类规则",
            "response_policy": "响应策略规则",
            "hosts": "Hosts格式规则",
            "other": "其他规则"
        }
    
    def format_dns_file(self) -> dict:
        """格式化DNS规则文件"""
        filepath = self.base_dir / 'dist/dns.txt'
        if not filepath.exists():
            return {'count': 0, 'errors': 0, 'warnings': 0}
        
        print("📄 格式化DNS规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"  原始规则: {len(rule_lines)} 条")
        
        # 清理和验证规则
        cleaned_rules = []
        errors = []
        warnings = []
        
        for rule in rule_lines:
            if self.is_valid_dns_rule(rule):
                cleaned_rules.append(rule)
            else:
                errors.append(rule)
        
        # 去重排序
        unique_rules = sorted(set(cleaned_rules))
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        # 添加统计信息
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 📊 DNS规则统计")
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 总计规则: {len(unique_rules)} 条")
        formatted_lines.append(f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"# 清理后: {len(unique_rules)} 条 (移除 {len(rule_lines) - len(unique_rules)} 条重复/无效)")
        
        if errors:
            formatted_lines.append(f"# 移除无效规则: {len(errors)} 条")
            for rule in errors[:3]:
                formatted_lines.append(f"# • 无效: {rule[:50]}...")
        
        formatted_lines.append("# ==================================================")
        formatted_lines.append("")
        
        # 添加规则
        formatted_lines.extend(unique_rules)
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ DNS规则格式化完成: {len(unique_rules)} 条规则")
        if errors:
            print(f"⚠️  移除 {len(errors)} 条无效DNS规则")
        
        return {
            'count': len(unique_rules),
            'errors': len(errors),
            'warnings': len(warnings)
        }
    
    def format_hosts_file(self) -> dict:
        """格式化Hosts规则文件"""
        filepath = self.base_dir / 'dist/hosts.txt'
        if not filepath.exists():
            return {'count': 0, 'errors': 0, 'warnings': 0}
        
        print("📄 格式化Hosts规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"  原始规则: {len(rule_lines)} 条")
        
        # 清理和验证规则
        cleaned_rules = []
        errors = []
        warnings = []
        
        for rule in rule_lines:
            if self.is_valid_hosts_rule(rule):
                cleaned_rules.append(rule)
            else:
                errors.append(rule)
            
            # 检查127.0.0.1警告
            if rule.startswith('127.0.0.1'):
                warnings.append(rule)
        
        # 转换127.0.0.1为0.0.0.0
        converted_rules = []
        for rule in cleaned_rules:
            if rule.startswith('127.0.0.1'):
                domain = rule.split()[1]
                converted_rules.append(f"0.0.0.0 {domain}")
            else:
                converted_rules.append(rule)
        
        # 去重排序
        unique_rules = sorted(set(converted_rules))
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        # 添加统计信息
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 📊 Hosts规则统计")
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 总计规则: {len(unique_rules)} 条")
        formatted_lines.append(f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"# 清理后: {len(unique_rules)} 条 (移除 {len(rule_lines) - len(unique_rules)} 条重复/无效)")
        
        if errors:
            formatted_lines.append(f"# 移除无效规则: {len(errors)} 条")
        
        if warnings:
            formatted_lines.append(f"# 转换127.0.0.1规则: {len(warnings)} 条")
        
        formatted_lines.append("# ==================================================")
        formatted_lines.append("")
        
        # 添加规则
        formatted_lines.extend(unique_rules)
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ Hosts规则格式化完成: {len(unique_rules)} 条规则")
        if errors:
            print(f"⚠️  移除 {len(errors)} 条无效Hosts规则")
        if warnings:
            print(f"⚠️  转换 {len(warnings)} 条127.0.0.1规则为0.0.0.0")
        
        return {
            'count': len(unique_rules),
            'errors': len(errors),
            'warnings': len(warnings)
        }
    
    def format_browser_file(self) -> dict:
        """格式化浏览器规则文件"""
        filepath = self.base_dir / 'dist/filter.txt'
        if not filepath.exists():
            return {'count': 0, 'errors': 0, 'warnings': 0}
        
        print("📄 格式化浏览器规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"  原始规则: {len(rule_lines)} 条")
        
        # 分类规则
        categorized_rules = defaultdict(list)
        errors = []
        warnings = []
        
        for rule in rule_lines:
            rule_type = self.classify_browser_rule(rule)
            if rule_type:
                categorized_rules[rule_type].append(rule)
            else:
                errors.append(rule)
            
            # 检查警告
            if self.has_warnings(rule):
                warnings.append(rule)
        
        # 清理每个类别
        cleaned_categories = {}
        total_valid = 0
        
        for category, rules in categorized_rules.items():
            cleaned_rules = []
            for rule in rules:
                if self.is_valid_browser_rule(rule):
                    cleaned_rules.append(rule)
            
            unique_rules = sorted(set(cleaned_rules))
            cleaned_categories[category] = unique_rules
            total_valid += len(unique_rules)
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        # 添加统计信息
        formatted_lines.append("! ==================================================")
        formatted_lines.append(f"! 📊 浏览器规则统计")
        formatted_lines.append("! ==================================================")
        formatted_lines.append(f"! 总计规则: {total_valid} 条")
        formatted_lines.append(f"! 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"! 清理后: {total_valid} 条 (移除 {len(rule_lines) - total_valid} 条无效)")
        
        for category, rules in cleaned_categories.items():
            if rules:
                category_name = self.rule_categories.get(category, category)
                formatted_lines.append(f"! • {category_name}: {len(rules)} 条")
        
        formatted_lines.append("! ==================================================")
        formatted_lines.append("")
        
        # 按类别添加规则（固定顺序）
        display_order = [
            "whitelist",
            "domain_block",
            "exact_domain",
            "cname_block",
            "category",
            "response_policy",
            "advanced",
            "element_hiding",
            "hosts",
            "other"
        ]
        
        for category in display_order:
            if category in cleaned_categories and cleaned_categories[category]:
                rules = cleaned_categories[category]
                category_name = self.rule_categories.get(category, category)
                
                formatted_lines.append(f"! {'='*50}")
                formatted_lines.append(f"! 🎯 {category_name} ({len(rules)}条)")
                formatted_lines.append(f"! {'='*50}")
                formatted_lines.append("")
                formatted_lines.extend(rules)
                formatted_lines.append("")
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ 浏览器规则格式化完成: {total_valid} 条规则")
        
        # 显示分类统计
        for category in display_order:
            if category in cleaned_categories and cleaned_categories[category]:
                category_name = self.rule_categories.get(category, category)
                print(f"  ├── {category_name}: {len(cleaned_categories[category])} 条")
        
        return {
            'count': total_valid,
            'errors': len(errors),
            'warnings': len(warnings),
            'categories': {cat: len(rules) for cat, rules in cleaned_categories.items()}
        }
    
    def classify_browser_rule(self, rule: str) -> str:
        """分类浏览器规则"""
        if rule.startswith('@@'):
            return "whitelist"
        elif rule.startswith('||') and rule.endswith('^'):
            if '$dnstype=CNAME' in rule:
                return "cname_block"
            elif '$category=' in rule:
                return "category"
            elif '$responsepolicy=' in rule:
                return "response_policy"
            elif '$' in rule:
                return "advanced"
            else:
                return "domain_block"
        elif rule.startswith('||') and '^$' in rule:
            return "exact_domain"
        elif rule.startswith('##'):
            return "element_hiding"
        elif rule.startswith(('0.0.0.0', '127.0.0.1')):
            return "hosts"
        elif '$' in rule:
            return "advanced"
        else:
            # 尝试匹配纯域名
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
                return "domain_block"
            return "other"
    
    def is_valid_dns_rule(self, rule: str) -> bool:
        """验证DNS规则"""
        if not rule:
            return False
        
        # 必须是纯域名
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return False
        
        # 禁止通配符
        if '*' in rule:
            return False
        
        # 禁止特殊符号
        if any(c in rule for c in ['^', '|', '$', '@', '#', '/', '!']):
            return False
        
        # 域名长度检查
        if len(rule) > 253:
            return False
        
        # 标签长度检查
        labels = rule.split('.')
        for label in labels:
            if len(label) > 63:
                return False
            if not label:
                return False
        
        return True
    
    def is_valid_hosts_rule(self, rule: str) -> bool:
        """验证Hosts规则"""
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            return False
        
        domain = match.group(2)
        return self.is_valid_dns_rule(domain)
    
    def is_valid_browser_rule(self, rule: str) -> bool:
        """验证浏览器规则"""
        if not rule:
            return False
        
        # 长度检查
        if len(rule) > 2000:
            return False
        
        # 禁止空字符
        if '\x00' in rule:
            return False
        
        # 检查基本格式
        if rule.startswith('@@'):
            # 白名单规则
            match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                domain = match.group(1)
                return self.is_valid_dns_rule(domain)
            return True
        
        elif rule.startswith('||'):
            # 域名阻断规则
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                domain = match.group(1)
                if not self.is_valid_dns_rule(domain):
                    return False
            
            # 检查修饰符
            if '$' in rule:
                parts = rule.split('$')
                if len(parts) > 1:
                    modifiers = parts[1]
                    # 验证修饰符格式
                    if not re.match(r'^[a-zA-Z0-9,_=\-]+$', modifiers):
                        return False
            
            return True
        
        elif rule.startswith('##'):
            # 元素隐藏规则
            selector = rule[2:]
            if not selector:
                return False
            if len(selector) > 500:
                return False
            return True
        
        # 其他格式
        return True
    
    def has_warnings(self, rule: str) -> bool:
        """检查规则是否有警告"""
        # 通配符警告
        if '*' in rule and not rule.startswith('##'):
            return True
        
        # 正则表达式警告
        if rule.startswith('/') and rule.endswith('/'):
            return True
        
        # 过长的规则
        if len(rule) > 1000:
            return True
        
        return False
    
    def optimize_rules(self):
        """优化规则"""
        print("⚡ 优化规则...")
        
        optimizations = {
            'dns_merged': 0,
            'hosts_merged': 0,
            'browser_merged': 0
        }
        
        # 优化DNS规则
        dns_file = self.base_dir / 'dist/dns.txt'
        if dns_file.exists():
            with open(dns_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            rule_lines = [line for line in lines if line and not line.startswith('#')]
            
            # 提取根域名
            root_domains = set()
            for domain in rule_lines:
                parts = domain.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                    root_domains.add(root_domain)
            
            optimizations['dns_merged'] = len(rule_lines) - len(root_domains)
            print(f"  ├── DNS规则: 可合并为 {len(root_domains)} 个根域名 (减少 {optimizations['dns_merged']} 条)")
        
        # 优化浏览器规则
        browser_file = self.base_dir / 'dist/filter.txt'
        if browser_file.exists():
            with open(browser_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            domain_rules = [line for line in lines if line.startswith('||') and '^' in line]
            
            # 提取域名
            domains = []
            for rule in domain_rules:
                match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
                if match:
                    domains.append(match.group(1))
            
            # 统计重复域名
            domain_counts = Counter(domains)
            duplicate_domains = {domain: count for domain, count in domain_counts.items() if count > 1}
            
            if duplicate_domains:
                optimizations['browser_merged'] = sum(count - 1 for count in duplicate_domains.values())
                print(f"  ├── 浏览器规则: 发现 {len(duplicate_domains)} 个重复域名 (减少 {optimizations['browser_merged']} 条)")
        
        print("  └── 优化完成")
        return optimizations
    
    def generate_statistics(self):
        """生成统计报告"""
        files = [
            ('dns.txt', 'DNS规则'),
            ('hosts.txt', 'Hosts规则'),
            ('filter.txt', '浏览器规则')
        ]
        
        stats = {}
        file_sizes = {}
        
        for filename, description in files:
            filepath = self.base_dir / 'dist' / filename
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 统计规则行数
                lines = content.split('\n')
                if filename == 'filter.txt':
                    rule_lines = [line for line in lines if line.strip() and not line.startswith('!')]
                else:
                    rule_lines = [line for line in lines if line.strip() and not line.startswith('#')]
                
                stats[description] = len(rule_lines)
                file_sizes[description] = filepath.stat().st_size
        
        # 生成统计报告
        report = {
            "timestamp": self.now.strftime('%Y-%m-%d %H:%M:%S'),
            "statistics": stats,
            "file_sizes_bytes": file_sizes,
            "syntax_features": [
                "whitelist_support",
                "exact_domain_matching",
                "subdomain_wildcard",
                "cname_blocking",
                "category_based_rules",
                "response_policy"
            ]
        }
        
        report_file = self.base_dir / 'dist/format_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 规则统计:")
        for desc, count in stats.items():
            size_kb = file_sizes[desc] / 1024
            print(f"  ├── {desc}: {count} 条 ({size_kb:.1f} KB)")
        
        total_rules = sum(stats.values())
        total_size = sum(file_sizes.values()) / 1024
        print(f"  └── 总计: {total_rules} 条 ({total_size:.1f} KB)")
        
        print(f"📁 统计报告已保存: {report_file}")
    
    def run(self):
        """执行格式化流程"""
        print("=" * 60)
        print("🔄 规则格式化工具 - 完整语法版")
        print("=" * 60)
        
        # 检查dist目录
        dist_dir = self.base_dir / 'dist'
        if not dist_dir.exists():
            print("❌ dist目录不存在")
            return
        
        results = {}
        
        # 1. 格式化DNS规则
        print("\n📄 步骤1: 格式化DNS规则")
        results['dns'] = self.format_dns_file()
        
        # 2. 格式化Hosts规则
        print("\n📄 步骤2: 格式化Hosts规则")
        results['hosts'] = self.format_hosts_file()
        
        # 3. 格式化浏览器规则
        print("\n📄 步骤3: 格式化浏览器规则")
        results['browser'] = self.format_browser_file()
        
        # 4. 优化规则
        print("\n⚡ 步骤4: 优化规则")
        optimizations = self.optimize_rules()
        
        # 5. 生成统计
        print("\n📊 步骤5: 生成统计报告")
        self.generate_statistics()
        
        print("\n" + "=" * 60)
        print("✅ 格式化完成!")
        print("🎯 完整语法规则文件:")
        print("  • dns.txt: 纯域名，用于DNS/AdGuard Home")
        print("  • hosts.txt: 0.0.0.0 + 域名，用于系统hosts")
        print("  • filter.txt: 完整AdBlock语法，支持所有高级功能")
        print("=" * 60)
        
        return results


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
