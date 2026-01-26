#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 增强语法版
支持白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import json


class EnhancedRuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
        # 规则类型定义
        self.rule_types = {
            "whitelist": "白名单规则 (@@)",
            "exact_domain": "精确域名规则",
            "wildcard": "子域/通配规则 (||domain^)",
            "cname": "CNAME拦截规则 ($cname)",
            "element_hiding": "元素隐藏规则 (##)",
            "category": "分类规则 ($category=)",
            "response_policy": "响应策略规则 ($important, $redirect, etc.)",
            "advanced": "高级规则",
            "other": "其他规则"
        }
        
        # 响应策略分类
        self.response_policies = [
            "$important", "$redirect", "$removeparam", "$csp",
            "$header", "$badfilter", "$denyallow", "$document",
            "$generichide", "$specifichide"
        ]
        
        # 分类标签
        self.categories = [
            "ad", "tracking", "malware", "phishing", "social",
            "porn", "annoyance", "cookie", "privacy", "security"
        ]
    
    def classify_browser_rule(self, rule: str) -> Tuple[str, Dict[str, any]]:
        """分类浏览器规则，返回类型和额外信息"""
        rule = rule.strip()
        
        if not rule or rule.startswith('!'):
            return "comment", {}
        
        # 1. 白名单规则
        if rule.startswith('@@'):
            if rule.startswith('@@||') and rule.endswith('^'):
                return "whitelist", {"subtype": "domain_whitelist"}
            elif rule.startswith('@@||'):
                return "whitelist", {"subtype": "partial_whitelist"}
            elif rule.startswith('@@/'):
                return "whitelist", {"subtype": "regex_whitelist"}
            else:
                return "whitelist", {"subtype": "generic_whitelist"}
        
        # 2. 子域/通配规则
        elif rule.startswith('||') and rule.endswith('^'):
            return "wildcard", {"subtype": "domain_wildcard"}
        
        # 3. CNAME拦截规则
        elif '$cname' in rule.lower():
            return "cname", {"subtype": "cname_intercept"}
        
        # 4. 分类规则
        elif any(f'$category={cat}' in rule.lower() for cat in self.categories):
            return "category", {"subtype": "category_based"}
        
        # 5. 响应策略规则
        elif any(policy in rule for policy in self.response_policies):
            return "response_policy", {"subtype": "policy_based"}
        
        # 6. 元素隐藏规则
        elif rule.startswith('##'):
            return "element_hiding", {"subtype": "css_selector"}
        
        # 7. 精确域名规则 (纯域名，没有特殊符号)
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return "exact_domain", {"subtype": "exact_match"}
        
        # 8. 高级规则 (带修饰符但未分类)
        elif '$' in rule:
            return "advanced", {"subtype": "modifier_rule"}
        
        # 9. 其他规则
        else:
            return "other", {"subtype": "unknown"}
    
    def format_dns_file(self) -> Dict[str, any]:
        """格式化DNS规则文件"""
        filepath = self.base_dir / 'dist/dns.txt'
        if not filepath.exists():
            return {"total": 0, "valid": 0, "invalid": 0, "domains": [], "stats": {}}
        
        print("📄 格式化DNS规则文件...")
        
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
        
        # 验证和分类域名
        valid_domains = []
        invalid_domains = []
        
        for domain in rule_lines:
            if self.validate_domain(domain):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)
        
        # 统计域名类型
        domain_stats = Counter()
        for domain in valid_domains:
            if domain.startswith('*.'):
                domain_stats['wildcard'] += 1
            elif '.' in domain and domain.count('.') >= 2:
                domain_stats['subdomain'] += 1
            else:
                domain_stats['root_domain'] += 1
        
        # 去重排序
        unique_domains = sorted(set(valid_domains))
        
        # 重建文件内容
        new_header = header_lines.copy()
        if new_header and new_header[-1].strip():
            new_header.append("")
        
        # 添加增强统计信息
        new_header.extend([
            "# ==================================================",
            f"# 📊 DNS规则统计 - 增强版",
            "# ==================================================",
            f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# 总计规则: {len(unique_domains)} 条",
            f"# 原始规则: {len(rule_lines)} 条",
            f"# 去重数量: {len(rule_lines) - len(unique_domains)} 条",
            f"# 根域名: {domain_stats['root_domain']} 条",
            f"# 子域名: {domain_stats['subdomain']} 条",
            f"# 通配符: {domain_stats['wildcard']} 条",
            f"# 无效规则: {len(invalid_domains)} 条",
            "# ==================================================",
            ""
        ])
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_header + unique_domains))
        
        print(f"✅ DNS规则格式化完成: {len(unique_domains)} 条有效域名")
        
        return {
            "total": len(rule_lines),
            "valid": len(unique_domains),
            "invalid": len(invalid_domains),
            "domains": unique_domains,
            "stats": dict(domain_stats)
        }
    
    def format_hosts_file(self) -> Dict[str, any]:
        """格式化Hosts规则文件"""
        filepath = self.base_dir / 'dist/hosts.txt'
        if not filepath.exists():
            return {"total": 0, "valid": 0, "invalid": 0, "rules": [], "stats": {}}
        
        print("📄 格式化Hosts规则文件...")
        
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
        valid_rules = []
        invalid_rules = []
        
        for rule in rule_lines:
            if self.validate_hosts_rule(rule):
                valid_rules.append(rule)
            else:
                invalid_rules.append(rule)
        
        # 统计IP类型
        ip_stats = Counter()
        for rule in valid_rules:
            if rule.startswith('0.0.0.0'):
                ip_stats['ipv4'] += 1
            elif rule.startswith('::'):
                ip_stats['ipv6'] += 1
            elif rule.startswith('127.0.0.1'):
                ip_stats['localhost'] += 1
            else:
                ip_stats['other'] += 1
        
        # 去重排序
        unique_rules = sorted(set(valid_rules))
        
        # 重建文件内容
        new_header = header_lines.copy()
        if new_header and new_header[-1].strip():
            new_header.append("")
        
        # 添加增强统计信息
        new_header.extend([
            "# ==================================================",
            f"# 📊 Hosts规则统计 - 增强版",
            "# ==================================================",
            f"# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# 总计规则: {len(unique_rules)} 条",
            f"# 原始规则: {len(rule_lines)} 条",
            f"# 去重数量: {len(rule_lines) - len(unique_rules)} 条",
            f"# IPv4规则 (0.0.0.0): {ip_stats['ipv4']} 条",
            f"# IPv6规则 (::): {ip_stats['ipv6']} 条",
            f"# 本地规则 (127.0.0.1): {ip_stats['localhost']} 条",
            f"# 无效规则: {len(invalid_rules)} 条",
            "# 说明: 推荐使用0.0.0.0进行广告拦截",
            "# ==================================================",
            ""
        ])
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_header + unique_rules))
        
        print(f"✅ Hosts规则格式化完成: {len(unique_rules)} 条有效规则")
        
        return {
            "total": len(rule_lines),
            "valid": len(unique_rules),
            "invalid": len(invalid_rules),
            "rules": unique_rules,
            "stats": dict(ip_stats)
        }
    
    def format_browser_file(self) -> Dict[str, any]:
        """格式化浏览器规则文件"""
        filepath = self.base_dir / 'dist/filter.txt'
        if not filepath.exists():
            return {"total": 0, "valid": 0, "invalid": 0, "rules": [], "stats": {}}
        
        print("📄 格式化浏览器规则文件...")
        
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
        
        # 分类和验证规则
        categorized_rules = defaultdict(list)
        invalid_rules = []
        rule_details = []
        
        for rule in rule_lines:
            rule_type, subtype_info = self.classify_browser_rule(rule)
            
            if rule_type == "other":
                invalid_rules.append(rule)
            else:
                categorized_rules[rule_type].append(rule)
                rule_details.append({
                    "rule": rule,
                    "type": rule_type,
                    "subtype": subtype_info.get("subtype", "unknown")
                })
        
        # 验证规则语法
        valid_rules = []
        for rule in rule_lines:
            is_valid, error_msg = self.validate_browser_rule(rule)
            if is_valid:
                valid_rules.append(rule)
            else:
                if rule not in invalid_rules:
                    invalid_rules.append(rule)
        
        # 按优先级排序分类
        priority_order = [
            "whitelist",    # 白名单优先
            "cname",        # CNAME拦截次之
            "response_policy", # 响应策略
            "category",     # 分类规则
            "wildcard",     # 通配规则
            "exact_domain", # 精确域名
            "element_hiding", # 元素隐藏
            "advanced",     # 高级规则
            "other"         # 其他规则
        ]
        
        # 去重和排序每个类别
        for rule_type in categorized_rules:
            categorized_rules[rule_type] = sorted(set(categorized_rules[rule_type]))
        
        # 重建文件内容
        new_header = header_lines.copy()
        if new_header and new_header[-1].strip():
            new_header.append("")
        
        # 添加增强统计信息
        stats_lines = [
            "! ==================================================",
            f"! 📊 浏览器规则统计 - 增强版",
            "! ==================================================",
            f"! 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}",
            f"! 总计规则: {len(valid_rules)} 条",
            f"! 原始规则: {len(rule_lines)} 条",
            f"! 去重数量: {len(rule_lines) - len(valid_rules)} 条",
            f"! 无效规则: {len(invalid_rules)} 条",
            "! ",
            "! 📋 规则类型分布:",
        ]
        
        for rule_type in priority_order:
            if rule_type in categorized_rules and categorized_rules[rule_type]:
                count = len(categorized_rules[rule_type])
                stats_lines.append(f"!   • {self.rule_types.get(rule_type, rule_type)}: {count} 条")
        
        stats_lines.extend([
            "! ",
            "! 🎯 增强语法支持:",
            "!   • 白名单 (@@开头) - 允许特定内容",
            "!   • 精确域名 - 纯域名格式",
            "!   • 子域/通配 (||domain^) - 拦截域名及其子域",
            "!   • CNAME拦截 ($cname) - 拦截CNAME重定向",
            "!   • 分类规则 ($category=) - 按分类过滤",
            "!   • 响应策略 ($important等) - 指定拦截行为",
            "!   • 元素隐藏 (##) - 隐藏页面元素",
            "! ==================================================",
            ""
        ])
        
        new_header.extend(stats_lines)
        
        # 按类别添加规则
        formatted_rules = []
        for rule_type in priority_order:
            if rule_type in categorized_rules and categorized_rules[rule_type]:
                formatted_rules.append(f"! {'='*50}")
                formatted_rules.append(f"! 🎯 {self.rule_types.get(rule_type, rule_type)}")
                formatted_rules.append(f"! {'='*50}")
                formatted_rules.append("")
                formatted_rules.extend(categorized_rules[rule_type])
                formatted_rules.append("")
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(new_header + formatted_rules))
        
        # 统计信息
        stats = {}
        for rule_type in priority_order:
            if rule_type in categorized_rules:
                stats[rule_type] = len(categorized_rules[rule_type])
        
        print(f"✅ 浏览器规则格式化完成: {len(valid_rules)} 条有效规则")
        for rule_type, count in stats.items():
            if count > 0:
                print(f"  ├── {self.rule_types.get(rule_type, rule_type)}: {count} 条")
        
        return {
            "total": len(rule_lines),
            "valid": len(valid_rules),
            "invalid": len(invalid_rules),
            "rules": valid_rules,
            "stats": stats,
            "details": rule_details
        }
    
    def validate_domain(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain:
            return False
        
        # 允许通配符域名
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # 基本域名格式
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        # 允许特殊域名
        if domain in ['localhost', 'local']:
            return True
        
        # 允许IP地址
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return True
        
        return bool(re.match(pattern, domain))
    
    def validate_hosts_rule(self, rule: str) -> bool:
        """验证Hosts规则"""
        # 支持多种格式
        patterns = [
            r'^0\.0\.0\.0\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            r'^127\.0\.0\.1\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            r'^::\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            r'^::1\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ]
        
        return any(re.match(pattern, rule) for pattern in patterns)
    
    def validate_browser_rule(self, rule: str) -> Tuple[bool, str]:
        """验证浏览器规则"""
        if not rule:
            return False, "空规则"
        
        # 长度限制
        if len(rule) > 2000:
            return False, "规则过长"
        
        # 禁止空字符
        if '\x00' in rule:
            return False, "包含空字符"
        
        # 分类验证
        rule_type, _ = self.classify_browser_rule(rule)
        
        if rule_type == "other":
            return False, "无法识别的规则类型"
        
        return True, ""
    
    def optimize_rules(self):
        """优化规则集合"""
        print("⚡ 执行规则优化...")
        
        # DNS规则优化
        dns_file = self.base_dir / 'dist/dns.txt'
        if dns_file.exists():
            with open(dns_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            rule_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            
            # 提取根域名
            root_domains = set()
            all_domains = set()
            
            for domain in rule_lines:
                all_domains.add(domain)
                parts = domain.split('.')
                if len(parts) >= 2:
                    root = '.'.join(parts[-2:])
                    root_domains.add(root)
            
            # 优化建议
            if len(root_domains) < len(all_domains) * 0.7:
                print(f"  ├── DNS规则: 可合并为 {len(root_domains)} 个根域名 (优化 {len(all_domains) - len(root_domains)} 条)")
        
        # 浏览器规则优化
        browser_file = self.base_dir / 'dist/filter.txt'
        if browser_file.exists():
            with open(browser_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            rule_lines = [line.strip() for line in lines if line.strip() and not line.startswith('!')]
            
            # 查找重复域名规则
            domain_rules = [line for line in rule_lines if re.match(r'^\|\|', line)]
            domains = []
            for rule in domain_rules:
                match = re.match(r'^\|\|([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)\^', rule)
                if match:
                    domains.append(match.group(1))
            
            # 统计重复
            from collections import Counter
            domain_counts = Counter(domains)
            duplicates = {domain: count for domain, count in domain_counts.items() if count > 1}
            
            if duplicates:
                print(f"  ├── 浏览器规则: 发现 {len(duplicates)} 个重复域名规则")
        
        print("  └── 优化分析完成")
    
    def generate_enhanced_statistics(self):
        """生成增强统计报告"""
        import json
        
        # 收集各文件数据
        files_data = {}
        
        # DNS文件
        dns_file = self.base_dir / 'dist/dns.txt'
        if dns_file.exists():
            with open(dns_file, 'r', encoding='utf-8') as f:
                dns_rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            files_data['dns'] = {
                "count": len(dns_rules),
                "size": dns_file.stat().st_size
            }
        
        # Hosts文件
        hosts_file = self.base_dir / 'dist/hosts.txt'
        if hosts_file.exists():
            with open(hosts_file, 'r', encoding='utf-8') as f:
                hosts_rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            files_data['hosts'] = {
                "count": len(hosts_rules),
                "size": hosts_file.stat().st_size
            }
        
        # 浏览器规则文件
        filter_file = self.base_dir / 'dist/filter.txt'
        if filter_file.exists():
            with open(filter_file, 'r', encoding='utf-8') as f:
                filter_rules = [line.strip() for line in f if line.strip() and not line.startswith('!')]
            files_data['filter'] = {
                "count": len(filter_rules),
                "size": filter_file.stat().st_size
            }
        
        # 生成详细报告
        report = {
            "timestamp": self.now.strftime('%Y-%m-%d %H:%M:%S'),
            "files": files_data,
            "summary": {
                "total_rules": sum(data["count"] for data in files_data.values()),
                "total_size": sum(data["size"] for data in files_data.values()),
                "average_rule_length": 0
            },
            "syntax_info": {
                "version": "2.0-enhanced",
                "supported_types": list(self.rule_types.values()),
                "response_policies": self.response_policies,
                "categories": self.categories
            }
        }
        
        # 保存报告
        report_file = self.base_dir / 'dist/enhanced_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # 打印统计
        print(f"\n📊 增强规则统计:")
        for file_type, data in files_data.items():
            size_kb = data['size'] / 1024
            print(f"  ├── {file_type.upper()}规则: {data['count']} 条 ({size_kb:.1f} KB)")
        
        total_rules = sum(data["count"] for data in files_data.values())
        total_size = sum(data["size"] for data in files_data.values()) / 1024
        print(f"  └── 总计: {total_rules} 条 ({total_size:.1f} KB)")
        
        print(f"📁 增强报告已保存: {report_file}")
    
    def run(self):
        """执行格式化流程"""
        print("=" * 60)
        print("🔄 增强规则格式化工具 v2.0")
        print("支持：白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略")
        print("=" * 60)
        
        # 检查dist目录
        dist_dir = self.base_dir / 'dist'
        if not dist_dir.exists():
            print("❌ dist目录不存在")
            return
        
        # 1. 格式化DNS规则
        print("\n📄 步骤1: 格式化DNS规则")
        dns_result = self.format_dns_file()
        
        # 2. 格式化Hosts规则
        print("\n📄 步骤2: 格式化Hosts规则")
        hosts_result = self.format_hosts_file()
        
        # 3. 格式化浏览器规则
        print("\n📄 步骤3: 格式化浏览器规则")
        browser_result = self.format_browser_file()
        
        # 4. 规则优化
        print("\n⚡ 步骤4: 规则优化分析")
        self.optimize_rules()
        
        # 5. 生成增强统计
        print("\n📊 步骤5: 生成增强统计报告")
        self.generate_enhanced_statistics()
        
        print("\n" + "=" * 60)
        print("✅ 增强格式化完成!")
        print("🎯 生成文件:")
        print("  • dns.txt - DNS规则 (纯域名)")
        print("  • hosts.txt - Hosts规则 (0.0.0.0 + 域名)")
        print("  • filter.txt - 浏览器规则 (完整语法)")
        print("  • enhanced_report.json - 增强统计报告")
        print("\n⚡ 支持语法:")
        print("  • 白名单 (@@开头)")
        print("  • 精确域名")
        print("  • 子域/通配 (||开头 ^结尾)")
        print("  • CNAME拦截 ($cname)")
        print("  • 分类规则 ($category=)")
        print("  • 响应策略 ($important, $redirect等)")
        print("=" * 60)


if __name__ == "__main__":
    formatter = EnhancedRuleFormatter()
    formatter.run()
