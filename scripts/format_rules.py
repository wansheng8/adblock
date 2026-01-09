#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 新语法版
处理三层规则文件：DNS、Hosts、浏览器规则
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
    def format_dns_file(self) -> int:
        """格式化DNS规则文件"""
        filepath = self.base_dir / 'dist/dns.txt'
        if not filepath.exists():
            print("❌ dns.txt 文件不存在")
            return 0
        
        print("📄 格式化DNS规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 分离头部和规则
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
        invalid_rules = []
        
        for rule in rule_lines:
            if self.is_valid_dns_rule(rule):
                cleaned_rules.append(rule)
            else:
                invalid_rules.append(rule)
        
        # 去重排序
        unique_rules = sorted(set(cleaned_rules))
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        # 确保有空行分隔
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        # 添加统计信息
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 📊 DNS规则统计")
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 总计规则: {len(unique_rules)} 条")
        formatted_lines.append(f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"# 清理后: {len(unique_rules)} 条 (移除 {len(rule_lines) - len(unique_rules)} 条重复/无效)")
        
        if invalid_rules:
            formatted_lines.append(f"# 移除无效规则: {len(invalid_rules)} 条")
            for rule in invalid_rules[:5]:
                formatted_lines.append(f"# • 无效: {rule[:50]}...")
        
        formatted_lines.append("# ==================================================")
        formatted_lines.append("")
        
        # 添加规则
        formatted_lines.extend(unique_rules)
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ DNS规则格式化完成: {len(unique_rules)} 条规则")
        if invalid_rules:
            print(f"⚠️  移除 {len(invalid_rules)} 条无效DNS规则")
        
        return len(unique_rules)
    
    def format_hosts_file(self) -> int:
        """格式化Hosts规则文件"""
        filepath = self.base_dir / 'dist/hosts.txt'
        if not filepath.exists():
            print("❌ hosts.txt 文件不存在")
            return 0
        
        print("📄 格式化Hosts规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 分离头部和规则
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
        invalid_rules = []
        
        for rule in rule_lines:
            if self.is_valid_hosts_rule(rule):
                cleaned_rules.append(rule)
            else:
                invalid_rules.append(rule)
        
        # 去重排序
        unique_rules = sorted(set(cleaned_rules))
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        # 确保有空行分隔
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        # 添加统计信息
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 📊 Hosts规则统计")
        formatted_lines.append("# ==================================================")
        formatted_lines.append(f"# 总计规则: {len(unique_rules)} 条")
        formatted_lines.append(f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append(f"# 清理后: {len(unique_rules)} 条 (移除 {len(rule_lines) - len(unique_rules)} 条重复/无效)")
        
        if invalid_rules:
            formatted_lines.append(f"# 移除无效规则: {len(invalid_rules)} 条")
        
        formatted_lines.append("# ==================================================")
        formatted_lines.append("")
        
        # 添加规则
        formatted_lines.extend(unique_rules)
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ Hosts规则格式化完成: {len(unique_rules)} 条规则")
        if invalid_rules:
            print(f"⚠️  移除 {len(invalid_rules)} 条无效Hosts规则")
        
        return len(unique_rules)
    
    def format_browser_file(self) -> int:
        """格式化浏览器规则文件"""
        filepath = self.base_dir / 'dist/filter.txt'
        if not filepath.exists():
            print("❌ filter.txt 文件不存在")
            return 0
        
        print("📄 格式化浏览器规则...")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 分离头部和规则
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
        rule_categories = {
            "域名阻断规则": [],
            "元素隐藏规则": [],
            "白名单规则": [],
            "高级规则": [],
            "其他规则": []
        }
        
        for rule in rule_lines:
            category = self.classify_browser_rule(rule)
            if category in rule_categories:
                rule_categories[category].append(rule)
            else:
                rule_categories["其他规则"].append(rule)
        
        # 清理和验证每个类别的规则
        cleaned_categories = {}
        total_valid = 0
        
        for category, rules in rule_categories.items():
            if rules:
                cleaned_rules = []
                for rule in rules:
                    if self.is_valid_browser_rule(rule):
                        cleaned_rules.append(rule)
                
                # 去重排序
                unique_rules = sorted(set(cleaned_rules))
                cleaned_categories[category] = unique_rules
                total_valid += len(unique_rules)
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        # 确保有空行分隔
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
                formatted_lines.append(f"! • {category}: {len(rules)} 条")
        
        formatted_lines.append("! ==================================================")
        formatted_lines.append("")
        
        # 按类别添加规则
        for category, rules in cleaned_categories.items():
            if rules:
                formatted_lines.append(f"! {'='*50}")
                formatted_lines.append(f"! 🎯 {category} ({len(rules)}条)")
                formatted_lines.append(f"! {'='*50}")
                formatted_lines.append("")
                formatted_lines.extend(rules)
                formatted_lines.append("")
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ 浏览器规则格式化完成: {total_valid} 条规则")
        
        # 显示分类统计
        for category, rules in cleaned_categories.items():
            if rules:
                print(f"  ├── {category}: {len(rules)} 条")
        
        return total_valid
    
    def classify_browser_rule(self, rule: str) -> str:
        """分类浏览器规则"""
        if rule.startswith('||') and rule.endswith('^') and '$' not in rule:
            return "域名阻断规则"
        elif rule.startswith('##'):
            return "元素隐藏规则"
        elif rule.startswith('@@'):
            return "白名单规则"
        elif '$' in rule:
            return "高级规则"
        else:
            return "其他规则"
    
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
        # 必须是 0.0.0.0 + 域名格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            return False
        
        # 验证域名部分
        domain = match.group(1)
        return self.is_valid_dns_rule(domain)
    
    def is_valid_browser_rule(self, rule: str) -> bool:
        """验证浏览器规则"""
        # 空规则
        if not rule:
            return False
        
        # 长度检查
        if len(rule) > 1000:
            return False
        
        # 禁止空字符
        if '\x00' in rule:
            return False
        
        # 域名阻断规则
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            return self.is_valid_dns_rule(domain)
        
        # 元素隐藏规则
        elif rule.startswith('##'):
            selector = rule[2:]
            if not selector:
                return False
            if len(selector) > 200:
                return False
            if '*' in selector:  # 禁止通配符
                return False
            return True
        
        # 白名单规则
        elif rule.startswith('@@||') and rule.endswith('^'):
            domain = rule[4:-1]
            return self.is_valid_dns_rule(domain)
        
        # 高级规则（带修饰符）
        elif '$' in rule:
            parts = rule.split('$')
            if len(parts) != 2:
                return False
            
            base_rule, modifiers = parts
            # 验证基础规则
            if base_rule.startswith('||') and base_rule.endswith('^'):
                domain = base_rule[2:-1]
                if not self.is_valid_dns_rule(domain):
                    return False
            
            # 验证修饰符
            if not re.match(r'^[a-z,=0-9_-]+$', modifiers):
                return False
            
            return True
        
        # 其他格式（谨慎处理）
        else:
            # 检查是否包含通配符
            if '*' in rule:
                return False
            # 检查长度
            if len(rule) > 500:
                return False
            return True
    
    def optimize_rules(self):
        """优化规则（合并相似规则）"""
        print("⚡ 优化规则...")
        
        # 1. 优化DNS规则（提取根域名）
        dns_file = self.base_dir / 'dist/dns.txt'
        if dns_file.exists():
            with open(dns_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            rule_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            
            # 提取根域名
            root_domains = set()
            for domain in rule_lines:
                parts = domain.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                    root_domains.add(root_domain)
            
            # 如果根域名数量明显少于原始域名，考虑使用根域名
            if len(root_domains) < len(rule_lines) * 0.5:
                print(f"  ├── DNS规则: 可合并为 {len(root_domains)} 个根域名")
        
        # 2. 优化浏览器规则（合并相似域名规则）
        browser_file = self.base_dir / 'dist/filter.txt'
        if browser_file.exists():
            with open(browser_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            domain_rules = [line.strip() for line in lines if line.strip().startswith('||') and line.strip().endswith('^')]
            
            # 提取域名
            domains = []
            for rule in domain_rules:
                domain = rule[2:-1]
                domains.append(domain)
            
            # 统计重复域名
            from collections import Counter
            domain_counts = Counter(domains)
            duplicate_domains = {domain: count for domain, count in domain_counts.items() if count > 1}
            
            if duplicate_domains:
                print(f"  ├── 浏览器规则: 发现 {len(duplicate_domains)} 个重复域名")
        
        print("  └── 优化完成")
    
    def generate_statistics(self):
        """生成统计报告"""
        import json
        
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
                rule_lines = [line for line in lines if line.strip() and not line.startswith(('!', '#'))]
                
                stats[description] = len(rule_lines)
                file_sizes[description] = filepath.stat().st_size
        
        # 生成统计报告
        report = {
            "timestamp": self.now.strftime('%Y-%m-%d %H:%M:%S'),
            "statistics": stats,
            "file_sizes_bytes": file_sizes,
            "notes": "新语法规则：DNS/Hosts只放域名，浏览器才用复杂语法"
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
        print("🔄 规则格式化工具 - 新语法版")
        print("=" * 60)
        
        # 检查dist目录
        dist_dir = self.base_dir / 'dist'
        if not dist_dir.exists():
            print("❌ dist目录不存在")
            return
        
        # 1. 格式化DNS规则
        print("\n📄 步骤1: 格式化DNS规则")
        dns_count = self.format_dns_file()
        
        # 2. 格式化Hosts规则
        print("\n📄 步骤2: 格式化Hosts规则")
        hosts_count = self.format_hosts_file()
        
        # 3. 格式化浏览器规则
        print("\n📄 步骤3: 格式化浏览器规则")
        browser_count = self.format_browser_file()
        
        # 4. 优化规则
        print("\n⚡ 步骤4: 优化规则")
        self.optimize_rules()
        
        # 5. 生成统计
        print("\n📊 步骤5: 生成统计报告")
        self.generate_statistics()
        
        print("\n" + "=" * 60)
        print("✅ 格式化完成!")
        print("🎯 新语法规则文件:")
        print("  • dns.txt: 纯域名，用于DNS/AdGuard Home")
        print("  • hosts.txt: 0.0.0.0 + 域名，用于系统hosts")
        print("  • filter.txt: 浏览器规则，用于uBlock Origin")
        print("=" * 60)


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
