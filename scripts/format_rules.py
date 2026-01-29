#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - Adblock语法版
处理三层规则文件：DNS、Hosts、浏览器规则
支持Adblock语法
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import json


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
        # Adblock规则分类
        self.rule_categories = {
            "whitelist": "白名单规则",
            "domain_block": "域名阻断规则",
            "element_hiding": "元素隐藏规则",
            "modifier": "修饰符规则",
            "hosts": "Hosts格式规则",
            "regex": "正则表达式规则",
            "comment": "注释",
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
        
        # 验证规则
        cleaned_rules = []
        errors = []
        
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
        formatted_lines.append(f"# 📊 DNS规则统计 - Adblock语法版")
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 总计规则: {len(unique_rules)} 条")
        formatted_lines.append(f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"# 清理后: {len(unique_rules)} 条 (移除 {len(rule_lines) - len(unique_rules)} 条重复/无效)")
        
        if errors:
            formatted_lines.append(f"# 移除无效规则: {len(errors)} 条")
        
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
            'warnings': 0
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
        
        # 验证规则
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
        formatted_lines.append(f"# 📊 Hosts规则统计 - Adblock语法版")
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
            rule_type = self.classify_adblock_rule(rule)
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
                if self.is_valid_adblock_rule(rule):
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
        formatted_lines.append(f"! 📊 浏览器规则统计 - Adblock语法版")
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
        
        # 按类别添加规则
        display_order = [
            "whitelist",
            "domain_block",
            "element_hiding",
            "modifier",
            "hosts",
            "regex",
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
    
    def classify_adblock_rule(self, rule: str) -> str:
        """分类Adblock规则"""
        if rule.startswith('@@'):
            return "whitelist"
        elif rule.startswith('||') and '^' in rule:
            return "domain_block"
        elif rule.startswith('##'):
            return "element_hiding"
        elif '$' in rule:
            return "modifier"
        elif rule.startswith(('0.0.0.0', '127.0.0.1')):
            return "hosts"
        elif rule.startswith('/') and rule.endswith('/'):
            return "regex"
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return "domain_block"
        else:
            return "other"
    
    def is_valid_dns_rule(self, rule: str) -> bool:
        """验证DNS规则"""
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
    
    def is_valid_adblock_rule(self, rule: str) -> bool:
        """验证Adblock规则"""
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
            
            return True
        
        elif rule.startswith('##'):
            # 元素隐藏规则
            selector = rule[2:]
            if not selector:
                return False
            if len(selector) > 500:
                return False
            return True
        
        elif rule.startswith(('0.0.0.0', '127.0.0.1')):
            # Hosts规则
            return self.is_valid_hosts_rule(rule)
        
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
    
    def generate_statistics(self):
        """生成统计报告"""
        files = [
            ('dns.txt', 'DNS规则'),
            ('hosts.txt', 'Hosts规则'),
            ('filter.txt', '浏览器规则'),
            ('dns_results.json', 'DNS检测结果')
        ]
        
        stats = {}
        file_sizes = {}
        
        for filename, description in files:
            filepath = self.base_dir / 'dist' / filename
            if filepath.exists():
                file_sizes[description] = filepath.stat().st_size
                
                if filename != 'dns_results.json':
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 统计规则行数
                    lines = content.split('\n')
                    if filename == 'filter.txt':
                        rule_lines = [line for line in lines if line.strip() and not line.startswith('!')]
                    else:
                        rule_lines = [line for line in lines if line.strip() and not line.startswith('#')]
                    
                    stats[description] = len(rule_lines)
        
        # 读取DNS检测结果
        dns_file = self.base_dir / 'dist' / 'dns_results.json'
        dns_stats = {}
        if dns_file.exists():
            with open(dns_file, 'r', encoding='utf-8') as f:
                dns_data = json.load(f)
                dns_stats = dns_data.get('statistics', {})
        
        # 生成统计报告
        report = {
            "timestamp": self.now.strftime('%Y-%m-%d %H:%M:%S'),
            "rule_statistics": stats,
            "file_sizes_bytes": file_sizes,
            "dns_statistics": dns_stats,
            "syntax_version": "adblock_1.0",
            "notes": "Adblock语法规则，所有域名已通过DNS可达性检测"
        }
        
        report_file = self.base_dir / 'dist/format_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 规则统计:")
        for desc, count in stats.items():
            size_kb = file_sizes.get(desc, 0) / 1024
            print(f"  ├── {desc}: {count} 条 ({size_kb:.1f} KB)")
        
        if dns_stats:
            total = dns_stats.get('total_tested', 0)
            valid = dns_stats.get('valid_count', 0)
            rate = dns_stats.get('success_rate', 0) * 100
            print(f"  ├── DNS检测: {valid}/{total} 可达 ({rate:.1f}%)")
        
        total_rules = sum(stats.values())
        total_size = sum(file_sizes.values()) / 1024
        print(f"  └── 总计: {total_rules} 条 ({total_size:.1f} KB)")
        
        print(f"📁 统计报告已保存: {report_file}")
    
    def run(self):
        """执行格式化流程"""
        print("=" * 60)
        print("🔄 规则格式化工具 - Adblock语法版")
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
        
        # 4. 生成统计
        print("\n📊 步骤4: 生成统计报告")
        self.generate_statistics()
        
        print("\n" + "=" * 60)
        print("✅ 格式化完成!")
        print("🎯 Adblock语法规则文件:")
        print("  • dns.txt: 纯域名，用于DNS/AdGuard Home")
        print("  • hosts.txt: 0.0.0.0 + 域名，用于系统hosts")
        print("  • filter.txt: 完整Adblock语法，用于浏览器扩展")
        print("  • 所有域名已通过DNS可达性检测")
        print("=" * 60)
        
        return results


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
