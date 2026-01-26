#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - 增强语法版
验证增强语法规则：白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略
"""

import re
import sys
import json
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
from typing import Tuple


class EnhancedRuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # 规则语法定义
        self.syntax_patterns = {
            "whitelist": {
                "patterns": [
                    r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$',
                    r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^\$.*$',
                    r'^@@/[^/]+/$'  # 正则表达式白名单
                ],
                "description": "白名单规则 (@@开头)"
            },
            "exact_domain": {
                "patterns": [
                    r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                ],
                "description": "精确域名规则"
            },
            "wildcard": {
                "patterns": [
                    r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$',
                    r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^\$.*$'
                ],
                "description": "子域/通配规则 (||开头 ^结尾)"
            },
            "cname": {
                "patterns": [
                    r'.*\$\$?cname(?:=[^,\s]+)?',
                    r'.*\$.*cname.*'
                ],
                "description": "CNAME拦截规则 ($cname)"
            },
            "element_hiding": {
                "patterns": [
                    r'^##.+$',
                    r'^#@#.+$',
                    r'^#\?#.+$'
                ],
                "description": "元素隐藏规则 (##, #@#, #?#)"
            },
            "category": {
                "patterns": [
                    r'.*\$\$?category=[^,\s]+'
                ],
                "description": "分类规则 ($category=)"
            },
            "response_policy": {
                "patterns": [
                    r'.*\$\$?important$',
                    r'.*\$\$?redirect(?:=[^,\s]+)?',
                    r'.*\$\$?removeparam=[^,\s]+',
                    r'.*\$\$?csp=[^,\s]+',
                    r'.*\$\$?header=[^,\s]+',
                    r'.*\$\$?badfilter',
                    r'.*\$\$?denyallow=[^,\s]+',
                    r'.*\$\$?document',
                    r'.*\$\$?generichide',
                    r'.*\$\$?specifichide'
                ],
                "description": "响应策略规则"
            }
        }
        
        # 分类定义
        self.categories = [
            "ad", "tracking", "malware", "phishing", "social",
            "porn", "annoyance", "cookie", "privacy", "security"
        ]
    
    def validate_dns_file(self) -> dict:
        """验证DNS规则文件"""
        filepath = self.base_dir / 'dist/dns.txt'
        if not filepath.exists():
            return {'total': 0, 'valid': 0, 'invalid': 0, 'errors': [], 'warnings': []}
        
        print("🔍 验证DNS规则文件...")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        total_rules = 0
        valid_rules = 0
        errors = []
        warnings = []
        domain_types = Counter()
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('#'):
                continue
            
            total_rules += 1
            
            # 验证规则
            is_valid, error_msg, rule_type = self.validate_dns_rule(line)
            
            if is_valid:
                valid_rules += 1
                domain_types[rule_type] += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': error_msg
                })
            
            # 检查通配符
            if line.startswith('*.'):
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '包含通配符域名'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5],
            'domain_types': dict(domain_types)
        }
    
    def validate_hosts_file(self) -> dict:
        """验证Hosts规则文件"""
        filepath = self.base_dir / 'dist/hosts.txt'
        if not filepath.exists():
            return {'total': 0, 'valid': 0, 'invalid': 0, 'errors': [], 'warnings': []}
        
        print("🔍 验证Hosts规则文件...")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        total_rules = 0
        valid_rules = 0
        errors = []
        warnings = []
        ip_types = Counter()
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('#'):
                continue
            
            total_rules += 1
            
            # 验证规则
            is_valid, error_msg, ip_type = self.validate_hosts_rule(line)
            
            if is_valid:
                valid_rules += 1
                ip_types[ip_type] += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': error_msg
                })
            
            # 检查是否使用127.0.0.1
            if line.startswith('127.0.0.1'):
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '建议使用0.0.0.0而非127.0.0.1进行广告拦截'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5],
            'ip_types': dict(ip_types)
        }
    
    def validate_browser_file(self) -> dict:
        """验证浏览器规则文件"""
        filepath = self.base_dir / 'dist/filter.txt'
        if not filepath.exists():
            return {'total': 0, 'valid': 0, 'invalid': 0, 'errors': [], 'warnings': []}
        
        print("🔍 验证浏览器规则文件...")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        total_rules = 0
        valid_rules = 0
        errors = []
        warnings = []
        syntax_types = Counter()
        category_usage = Counter()
        response_policies = Counter()
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('!'):
                continue
            
            total_rules += 1
            
            # 验证规则
            is_valid, error_msg, rule_info = self.validate_browser_rule(line)
            
            if is_valid:
                valid_rules += 1
                syntax_types[rule_info['type']] += 1
                
                # 统计分类使用
                if rule_info.get('categories'):
                    for cat in rule_info['categories']:
                        category_usage[cat] += 1
                
                # 统计响应策略
                if rule_info.get('response_policy'):
                    response_policies[rule_info['response_policy']] += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': error_msg
                })
            
            # 检查警告
            if '*' in line:
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '规则包含通配符*'
                })
            
            # 检查复杂正则
            if line.startswith('/') and line.endswith('/'):
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '规则使用正则表达式，可能影响性能'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5],
            'syntax_types': dict(syntax_types),
            'category_usage': dict(category_usage),
            'response_policies': dict(response_policies)
        }
    
    def validate_dns_rule(self, rule: str) -> Tuple[bool, str, str]:
        """验证DNS规则"""
        # 必须是纯域名或通配符域名
        if rule.startswith('*.'):
            domain = rule[2:]
            rule_type = "wildcard"
        else:
            domain = rule
            rule_type = "exact_domain"
        
        # 验证域名格式
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return False, "无效的域名格式", rule_type
        
        # 禁止特殊符号
        if any(c in domain for c in ['^', '|', '$', '@', '#', '/']):
            return False, "域名包含特殊符号", rule_type
        
        # 域名长度检查
        if len(domain) > 253:
            return False, "域名过长", rule_type
        
        # 标签长度检查
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return False, "域名标签过长", rule_type
            if not label:
                return False, "域名标签为空", rule_type
        
        return True, "", rule_type
    
    def validate_hosts_rule(self, rule: str) -> Tuple[bool, str, str]:
        """验证Hosts规则"""
        # 支持多种格式
        patterns = [
            (r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', "ipv4"),
            (r'^127\.0\.0\.1\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', "localhost"),
            (r'^::\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', "ipv6"),
            (r'^::1\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', "localhost_ipv6")
        ]
        
        for pattern, ip_type in patterns:
            match = re.match(pattern, rule)
            if match:
                # 验证域名部分
                domain = match.group(1)
                if self.validate_dns_rule(domain)[0]:
                    return True, "", ip_type
                else:
                    return False, "无效的域名格式", ip_type
        
        return False, "无效的Hosts规则格式", "unknown"
    
    def validate_browser_rule(self, rule: str) -> Tuple[bool, str, dict]:
        """验证浏览器规则 - 增强版"""
        # 长度检查
        if len(rule) > 2000:
            return False, "规则过长", {}
        
        # 禁止空字符
        if '\x00' in rule:
            return False, "包含空字符", {}
        
        # 识别规则类型
        rule_info = {
            'type': 'unknown',
            'categories': [],
            'response_policy': '',
            'cname_target': ''
        }
        
        # 检查各种语法类型
        for syntax_type, syntax_info in self.syntax_patterns.items():
            for pattern in syntax_info['patterns']:
                if re.search(pattern, rule, re.IGNORECASE):
                    rule_info['type'] = syntax_type
                    break
            
            if rule_info['type'] != 'unknown':
                break
        
        # 如果无法识别类型，检查是否是简单域名规则
        if rule_info['type'] == 'unknown':
            # 检查是否是纯域名
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
                rule_info['type'] = 'exact_domain'
            else:
                return False, "无法识别的规则类型", rule_info
        
        # 提取额外信息
        # 提取分类
        category_match = re.search(r'\$category=([^,\s]+)', rule, re.IGNORECASE)
        if category_match:
            categories = category_match.group(1).split('|')
            rule_info['categories'] = [cat.strip() for cat in categories]
            
            # 验证分类
            for cat in rule_info['categories']:
                if cat not in self.categories:
                    return False, f"未知的分类: {cat}", rule_info
        
        # 提取响应策略
        response_policies = ['important', 'redirect', 'removeparam', 'csp', 
                           'header', 'badfilter', 'denyallow', 'document',
                           'generichide', 'specifichide']
        
        for policy in response_policies:
            if f'${policy}' in rule.lower():
                rule_info['response_policy'] = policy
                break
        
        # 提取CNAME目标
        cname_match = re.search(r'\$cname=([^,\s]+)', rule, re.IGNORECASE)
        if cname_match:
            rule_info['cname_target'] = cname_match.group(1)
        
        return True, "", rule_info
    
    def run_enhanced_validation(self):
        """执行增强验证"""
        print("=" * 60)
        print("🔍 增强规则验证器 v2.0")
        print("支持：白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略")
        print("=" * 60)
        
        # 验证各层规则文件
        results = {
            "dns": self.validate_dns_file(),
            "hosts": self.validate_hosts_file(),
            "browser": self.validate_browser_file()
        }
        
        # 生成总体报告
        total_rules = sum(r['total'] for r in results.values())
        total_valid = sum(r['valid'] for r in results.values())
        total_invalid = sum(r['invalid'] for r in results.values())
        
        # 打印验证结果
        print("\n📊 增强验证结果:")
        print("-" * 60)
        
        for file_type, result in results.items():
            if result['total'] > 0:
                validity_rate = (result['valid'] / result['total']) * 100
                print(f"\n📄 {file_type.upper()}规则:")
                print(f"  ├── 总计规则: {result['total']:,} 条")
                print(f"  ├── 有效规则: {result['valid']:,} 条")
                print(f"  ├── 无效规则: {result['invalid']:,} 条")
                print(f"  └── 有效性: {validity_rate:.1f}%")
                
                # 显示详细统计
                if file_type == 'dns' and 'domain_types' in result:
                    print(f"    📋 域名类型分布:")
                    for domain_type, count in result['domain_types'].items():
                        print(f"      • {domain_type}: {count} 条")
                
                elif file_type == 'hosts' and 'ip_types' in result:
                    print(f"    📋 IP类型分布:")
                    for ip_type, count in result['ip_types'].items():
                        print(f"      • {ip_type}: {count} 条")
                
                elif file_type == 'browser' and 'syntax_types' in result:
                    print(f"    📋 语法类型分布:")
                    for syntax_type, count in result['syntax_types'].items():
                        desc = self.syntax_patterns.get(syntax_type, {}).get('description', syntax_type)
                        print(f"      • {desc}: {count} 条")
                    
                    if 'category_usage' in result and result['category_usage']:
                        print(f"    🏷️  分类使用情况:")
                        for category, count in result['category_usage'].items():
                            print(f"      • {category}: {count} 条")
                    
                    if 'response_policies' in result and result['response_policies']:
                        print(f"    ⚡ 响应策略使用:")
                        for policy, count in result['response_policies'].items():
                            print(f"      • {policy}: {count} 条")
                
                if result['errors']:
                    print(f"    ⚠️  发现 {len(result['errors'])} 个错误:")
                    for i, error in enumerate(result['errors'][:3], 1):
                        print(f"      {i}. 第{error['line']}行: {error['rule']}")
                        print(f"          错误: {error['message']}")
                
                if result['warnings']:
                    print(f"    💡 发现 {len(result['warnings'])} 个警告:")
                    for i, warning in enumerate(result['warnings'][:2], 1):
                        print(f"      {i}. 第{warning['line']}行: {warning['rule']}")
                        print(f"          警告: {warning['message']}")
        
        print("\n📈 总体统计:")
        print("-" * 60)
        print(f"总计规则: {total_rules:,} 条")
        print(f"有效规则: {total_valid:,} 条")
        print(f"无效规则: {total_invalid:,} 条")
        
        if total_rules > 0:
            overall_validity = (total_valid / total_rules) * 100
            print(f"总体有效性: {overall_validity:.1f}%")
        
        # 生成详细报告
        report = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "validation_results": results,
            "summary": {
                "total_rules": total_rules,
                "valid_rules": total_valid,
                "invalid_rules": total_invalid,
                "validity_rate": overall_validity if total_rules > 0 else 0
            },
            "syntax_support": {
                syntax_type: syntax_info['description']
                for syntax_type, syntax_info in self.syntax_patterns.items()
            },
            "categories": self.categories
        }
        
        # 保存报告
        report_file = self.base_dir / 'dist/enhanced_validation_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📁 增强验证报告已保存: {report_file}")
        
        # 返回退出码
        if total_valid == 0:
            print("❌ 错误: 没有有效规则")
            return 2
        elif overall_validity < 95:  # 要求95%以上的有效性
            print("⚠️  警告: 规则有效性低于95%")
            return 1
        else:
            print("✅ 验证完成（通过增强验证）")
            return 0
    
    def check_syntax_compliance(self):
        """检查语法合规性"""
        print("=" * 60)
        print("📋 语法合规性检查")
        print("=" * 60)
        
        # 检查浏览器规则文件
        filter_file = self.base_dir / 'dist/filter.txt'
        if not filter_file.exists():
            print("❌ filter.txt 文件不存在")
            return 1
        
        with open(filter_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        rule_lines = [line.strip() for line in lines if line.strip() and not line.startswith('!')]
        
        print(f"📄 检查 {len(rule_lines)} 条浏览器规则...")
        
        compliance_stats = Counter()
        compliance_issues = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('!'):
                continue
            
            # 检查语法合规性
            issues = []
            
            # 检查是否有未分类的高级规则
            if '$' in line and not any(f'${policy}' in line.lower() for policy in 
                                     ['important', 'redirect', 'removeparam', 'csp', 'header', 
                                      'badfilter', 'denyallow', 'document', 'generichide', 
                                      'specifichide', 'cname', 'category']):
                issues.append("未分类的高级修饰符")
            
            # 检查通配符使用
            if '*' in line and not line.startswith('||') and not line.startswith('@@'):
                issues.append("不推荐的通配符使用")
            
            # 检查复杂的正则表达式
            if line.startswith('/') and line.endswith('/') and len(line) > 50:
                issues.append("复杂的正则表达式可能影响性能")
            
            # 检查过长的规则
            if len(line) > 500:
                issues.append("规则过长")
            
            # 记录结果
            if issues:
                compliance_issues.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'issues': issues
                })
                for issue in issues:
                    compliance_stats[issue] += 1
            else:
                compliance_stats['合规'] += 1
        
        # 打印结果
        print(f"📊 合规性统计:")
        for issue, count in compliance_stats.items():
            print(f"  ├── {issue}: {count} 条")
        
        if compliance_issues:
            print(f"\n⚠️  发现 {len(compliance_issues)} 条规则有合规性问题:")
            for i, issue in enumerate(compliance_issues[:5], 1):
                print(f"  {i}. 第{issue['line']}行: {issue['rule']}")
                for problem in issue['issues']:
                    print(f"      • {problem}")
        
        # 生成合规性报告
        compliance_report = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "total_rules": len(rule_lines),
            "compliance_stats": dict(compliance_stats),
            "compliance_rate": (compliance_stats['合规'] / len(rule_lines) * 100) if len(rule_lines) > 0 else 0,
            "issues": compliance_issues[:20]
        }
        
        report_file = self.base_dir / 'dist/compliance_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(compliance_report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📁 合规性报告已保存: {report_file}")
        
        if compliance_stats['合规'] == len(rule_lines):
            print("✅ 所有规则语法合规")
            return 0
        else:
            print(f"⚠️  {len(compliance_issues)} 条规则需要优化")
            return 1


def main():
    validator = EnhancedRuleValidator()
    
    # 解析命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == '--compliance':
            exit_code = validator.check_syntax_compliance()
        elif sys.argv[1] == '--simple':
            print("简单验证模式暂不支持增强语法")
            sys.exit(1)
        else:
            exit_code = validator.run_enhanced_validation()
    else:
        exit_code = validator.run_enhanced_validation()
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
