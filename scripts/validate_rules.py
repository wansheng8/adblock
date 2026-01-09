#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - 新语法版
根据三层规则语法进行严格验证
"""

import re
import sys
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime


class RuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.validation_errors = []
        self.validation_warnings = []
        self.rule_types = defaultdict(int)
    
    def validate_dns_rule(self, rule):
        """验证DNS规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return True, "comment", []
        
        errors = []
        warnings = []
        
        # 1. 必须是纯域名
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            errors.append("必须是纯域名格式")
        
        # 2. 禁止通配符
        if '*' in rule:
            errors.append("禁止使用通配符 *")
        
        # 3. 禁止特殊符号
        special_chars = ['^', '|', '$', '@', '#', '/', '!']
        for char in special_chars:
            if char in rule:
                errors.append(f"禁止使用特殊符号 '{char}'")
                break
        
        # 4. 域名长度检查
        if len(rule) > 253:
            errors.append("域名过长（超过253字符）")
        
        # 5. 标签长度检查
        labels = rule.split('.')
        for label in labels:
            if len(label) > 63:
                errors.append(f"标签 '{label}' 过长（超过63字符）")
            if not label:
                errors.append("域名标签不能为空")
        
        # 6. 检查常见问题
        if rule.startswith('.'):
            warnings.append("域名以点开头")
        if rule.endswith('.'):
            warnings.append("域名以点结尾")
        if '..' in rule:
            errors.append("域名包含连续点")
        
        if errors:
            return False, "dns_invalid", errors + warnings
        elif warnings:
            return True, "dns_valid_warning", warnings
        else:
            return True, "dns_valid", []
    
    def validate_hosts_rule(self, rule):
        """验证Hosts规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return True, "comment", []
        
        errors = []
        warnings = []
        
        # 1. 必须是 0.0.0.0 + 域名格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            errors.append("必须是 '0.0.0.0 域名' 格式")
            return False, "hosts_invalid", errors
        
        domain = match.group(1)
        
        # 2. 验证域名部分
        is_valid, domain_type, messages = self.validate_dns_rule(domain)
        if not is_valid:
            errors.extend([f"域名部分: {msg}" for msg in messages if '错误' in msg or '禁止' in msg])
            warnings.extend([f"域名部分: {msg}" for msg in messages if '警告' in msg or '建议' in msg])
        
        # 3. 检查使用127.0.0.1
        if rule.startswith('127.0.0.1'):
            warnings.append("建议使用0.0.0.0而非127.0.0.1（兼容性更好）")
        
        if errors:
            return False, "hosts_invalid", errors + warnings
        elif warnings:
            return True, "hosts_valid_warning", warnings
        else:
            return True, "hosts_valid", []
    
    def validate_browser_rule(self, rule):
        """验证浏览器规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return True, "comment", []
        
        errors = []
        warnings = []
        
        # 1. 域名阻断规则
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            is_valid, domain_type, messages = self.validate_dns_rule(domain)
            if not is_valid:
                errors.extend([f"域名部分: {msg}" for msg in messages])
            else:
                self.rule_types["域名阻断规则"] += 1
                return True, "domain_block", warnings
        
        # 2. 元素隐藏规则
        elif rule.startswith('##'):
            selector = rule[2:]
            
            # 长度检查
            if len(selector) > 200:
                warnings.append("CSS选择器过长")
            
            # 禁止通配符
            if '*' in selector:
                errors.append("CSS选择器中禁止使用通配符 *")
            
            # 简单的有效性检查
            if not selector:
                errors.append("CSS选择器不能为空")
            
            if errors:
                return False, "element_hiding_invalid", errors + warnings
            else:
                self.rule_types["元素隐藏规则"] += 1
                return True, "element_hiding", warnings
        
        # 3. 白名单规则
        elif rule.startswith('@@||') and rule.endswith('^'):
            domain = rule[4:-1]
            is_valid, domain_type, messages = self.validate_dns_rule(domain)
            if not is_valid:
                errors.extend([f"域名部分: {msg}" for msg in messages])
            else:
                self.rule_types["白名单规则"] += 1
                return True, "whitelist", warnings
        
        # 4. 高级规则（带修饰符）
        elif '$' in rule:
            parts = rule.split('$')
            if len(parts) != 2:
                errors.append("修饰符格式错误")
            else:
                base_rule, modifiers = parts
                
                # 验证基础规则
                if base_rule:
                    # 检查是否是域名规则
                    if base_rule.startswith('||') and base_rule.endswith('^'):
                        domain = base_rule[2:-1]
                        is_valid, domain_type, messages = self.validate_dns_rule(domain)
                        if not is_valid:
                            errors.extend([f"基础规则: {msg}" for msg in messages])
                
                # 验证修饰符
                if not re.match(r'^[a-z,=0-9_-]+$', modifiers):
                    errors.append("修饰符包含非法字符")
                
                # 检查是否包含通配符
                if '*' in rule:
                    errors.append("高级规则中禁止使用通配符 *")
            
            if errors:
                return False, "advanced_invalid", errors + warnings
            else:
                self.rule_types["高级规则"] += 1
                return True, "advanced", warnings
        
        # 5. 未知格式
        else:
            # 尝试提取域名
            domain = self.extract_domain(rule)
            if domain:
                warnings.append(f"可能是DNS规则，建议改为纯域名格式: {domain}")
                return False, "unknown_format", errors + warnings
            else:
                errors.append("未知规则格式")
                return False, "unknown_invalid", errors + warnings
    
    def extract_domain(self, rule):
        """从规则中提取域名"""
        # 尝试匹配各种格式中的域名
        patterns = [
            r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$',  # 纯域名
            r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$',  # Hosts
            r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^',  # 域名阻断
            r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^',  # 白名单
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                return match.group(1)
        
        return None
    
    def validate_file(self, file_path, rule_type="auto"):
        """验证整个文件"""
        path = Path(file_path)
        if not path.exists():
            print(f"❌ 文件不存在: {file_path}")
            return {'total': 0, 'valid': 0, 'errors': [], 'warnings': []}
        
        print(f"🔍 验证文件: {path.name}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        total_rules = 0
        valid_rules = 0
        invalid_details = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n')
            
            # 统计非空行
            if line.strip():
                total_rules += 1
                
                # 根据文件类型选择验证方法
                if rule_type == "dns" or path.name == "dns.txt":
                    is_valid, rule_category, messages = self.validate_dns_rule(line)
                elif rule_type == "hosts" or path.name == "hosts.txt":
                    is_valid, rule_category, messages = self.validate_hosts_rule(line)
                elif rule_type == "browser" or path.name in ["filter.txt", "blacklist.txt"]:
                    is_valid, rule_category, messages = self.validate_browser_rule(line)
                else:
                    # 自动检测
                    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                        is_valid, rule_category, messages = self.validate_dns_rule(line)
                    elif line.startswith('0.0.0.0'):
                        is_valid, rule_category, messages = self.validate_hosts_rule(line)
                    else:
                        is_valid, rule_category, messages = self.validate_browser_rule(line)
                
                if is_valid:
                    valid_rules += 1
                else:
                    error_messages = [m for m in messages if '错误' in m or '禁止' in m or '不能' in m or '必须' in m]
                    if error_messages:
                        invalid_details.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'errors': error_messages,
                            'warnings': [m for m in messages if m not in error_messages]
                        })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'details': invalid_details[:20],  # 只保留前20个错误详情
            'rule_types': dict(self.rule_types)
        }
    
    def generate_comprehensive_report(self):
        """生成综合验证报告"""
        print("=" * 60)
        print("🔍 综合规则验证 - 新语法版")
        print("=" * 60)
        
        reports = {}
        
        # 验证各层规则文件
        files_to_check = [
            ("dns.txt", "DNS规则"),
            ("hosts.txt", "Hosts规则"),
            ("filter.txt", "浏览器规则"),
            ("whitelist.txt", "白名单规则")
        ]
        
        for filename, description in files_to_check:
            filepath = self.base_dir / 'dist' / filename
            if filepath.exists():
                print(f"\n📄 验证{description}...")
                reports[filename] = self.validate_file(filepath)
                self.rule_types.clear()  # 重置统计
            else:
                print(f"\n📄 {description}文件不存在: {filename}")
                reports[filename] = {'total': 0, 'valid': 0, 'invalid': 0}
        
        # 生成总体报告
        total_rules = sum(r['total'] for r in reports.values())
        total_valid = sum(r['valid'] for r in reports.values())
        
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'files': reports,
            'summary': {
                'total_rules': total_rules,
                'valid_rules': total_valid,
                'invalid_rules': total_rules - total_valid,
                'validity_rate': (total_valid / total_rules * 100) if total_rules > 0 else 0
            },
            'recommendations': self.generate_recommendations(reports)
        }
        
        # 打印报告
        self.print_report(report)
        
        # 保存报告
        self.save_report(report)
        
        # 返回退出码
        validity_threshold = 90  # 严格标准：90%有效性
        validity_rate = report['summary']['validity_rate']
        
        if validity_rate < validity_threshold:
            print(f"⚠️  警告: 规则有效性低于{validity_threshold}% ({validity_rate:.1f}%)")
            return 1
        elif total_valid == 0:
            print("❌ 错误: 没有有效规则")
            return 2
        else:
            print("✅ 验证完成（通过严格验证）")
            return 0
    
    def generate_recommendations(self, reports):
        """生成改进建议"""
        recommendations = []
        
        for filename, stats in reports.items():
            if stats['invalid'] > 0:
                recommendations.append({
                    'file': filename,
                    'issue': f"发现 {stats['invalid']} 条无效规则",
                    'suggestion': "运行 cleanup_rules.py 脚本清理无效规则"
                })
        
        # 语法建议
        recommendations.extend([
            {
                'file': '所有文件',
                'issue': '通配符使用',
                'suggestion': '避免在规则中使用通配符 *，改用具体域名'
            },
            {
                'file': '所有文件',
                'issue': '正则表达式',
                'suggestion': '避免使用正则表达式规则，改用精确匹配'
            },
            {
                'file': 'DNS/Hosts规则',
                'issue': '特殊符号',
                'suggestion': '只使用纯域名，不要包含 ^ $ | @ # 等符号'
            }
        ])
        
        return recommendations
    
    def print_report(self, report):
        """打印验证报告"""
        print("\n📊 综合验证报告")
        print("=" * 60)
        
        for filename, stats in report['files'].items():
            if stats['total'] > 0:
                validity_rate = (stats['valid'] / stats['total']) * 100
                print(f"\n📄 {filename}:")
                print(f"  ├── 总计规则: {stats['total']:,} 条")
                print(f"  ├── 有效规则: {stats['valid']:,} 条")
                print(f"  ├── 无效规则: {stats['invalid']:,} 条")
                print(f"  └── 有效性: {validity_rate:.1f}%")
                
                if stats.get('details'):
                    print(f"    ⚠️  发现 {len(stats['details'])} 个问题:")
                    for i, detail in enumerate(stats['details'][:3], 1):
                        print(f"      {i}. 第{detail['line']}行: {detail['rule']}")
                        if detail['errors']:
                            print(f"         错误: {', '.join(detail['errors'][:2])}")
        
        print("\n📈 总体统计:")
        print(f"  ├── 总计规则: {report['summary']['total_rules']:,} 条")
        print(f"  ├── 有效规则: {report['summary']['valid_rules']:,} 条")
        print(f"  ├── 无效规则: {report['summary']['invalid_rules']:,} 条")
        print(f"  └── 总体有效性: {report['summary']['validity_rate']:.1f}%")
        
        if report['recommendations']:
            print("\n💡 改进建议:")
            for rec in report['recommendations'][:5]:
                print(f"  • {rec['file']}: {rec['suggestion']}")
        
        print("\n🎯 新语法验证标准:")
        print("  • DNS规则: 纯域名，无特殊符号")
        print("  • Hosts规则: 0.0.0.0 + 域名")
        print("  • 浏览器规则: ||domain^  ##selector  @@||domain^")
        print("  • 严格禁止: 通配符(*)、正则表达式、过度匹配")
        print("=" * 60)
    
    def save_report(self, report):
        """保存报告为JSON文件"""
        report_file = self.base_dir / 'dist/validation_report.json'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📊 验证报告已保存: {report_file}")


def main():
    validator = RuleValidator()
    exit_code = validator.generate_comprehensive_report()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
