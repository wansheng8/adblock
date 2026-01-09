#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - 新语法版
验证三层规则文件的语法正确性
"""

import re
import sys
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Tuple  # 添加这个导入


class RuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
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
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('#'):
                continue
            
            total_rules += 1
            
            # 验证规则
            if self.validate_dns_rule(line):
                valid_rules += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '无效的DNS规则格式'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings
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
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('#'):
                continue
            
            total_rules += 1
            
            # 验证规则
            if self.validate_hosts_rule(line):
                valid_rules += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '无效的Hosts规则格式'
                })
            
            # 检查是否使用127.0.0.1
            if line.startswith('127.0.0.1'):
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '建议使用0.0.0.0而非127.0.0.1'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5]
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
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n').strip()
            
            if not line or line.startswith('!'):
                continue
            
            total_rules += 1
            
            # 验证规则
            is_valid, error_msg = self.validate_browser_rule(line)
            if is_valid:
                valid_rules += 1
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': error_msg
                })
            
            # 检查警告（通配符等）
            if '*' in line:
                warnings.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '规则包含通配符*'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5]
        }
    
    def validate_dns_rule(self, rule: str) -> bool:
        """验证DNS规则"""
        # 必须是纯域名
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return False
        
        # 禁止通配符
        if '*' in rule:
            return False
        
        # 禁止特殊符号
        if any(c in rule for c in ['^', '|', '$', '@', '#', '/']):
            return False
        
        return True
    
    def validate_hosts_rule(self, rule: str) -> bool:
        """验证Hosts规则"""
        # 必须是 0.0.0.0 + 域名格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            return False
        
        # 验证域名部分
        domain = match.group(1)
        return self.validate_dns_rule(domain)
    
    def validate_browser_rule(self, rule: str) -> Tuple[bool, str]:
        """验证浏览器规则"""
        # 长度检查
        if len(rule) > 1000:
            return False, "规则过长"
        
        # 域名阻断规则
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            if not self.validate_dns_rule(domain):
                return False, "无效的域名格式"
            return True, ""
        
        # 元素隐藏规则
        elif rule.startswith('##'):
            selector = rule[2:]
            if not selector:
                return False, "CSS选择器不能为空"
            if len(selector) > 200:
                return False, "CSS选择器过长"
            return True, ""
        
        # 白名单规则
        elif rule.startswith('@@||') and rule.endswith('^'):
            domain = rule[4:-1]
            if not self.validate_dns_rule(domain):
                return False, "无效的域名格式"
            return True, ""
        
        # 高级规则（带修饰符）
        elif '$' in rule:
            parts = rule.split('$')
            if len(parts) != 2:
                return False, "修饰符格式错误"
            
            base_rule, modifiers = parts
            
            # 验证基础规则
            if base_rule.startswith('||') and base_rule.endswith('^'):
                domain = base_rule[2:-1]
                if not self.validate_dns_rule(domain):
                    return False, "无效的域名格式"
            
            # 验证修饰符
            if not re.match(r'^[a-z,=0-9_-]+$', modifiers):
                return False, "无效的修饰符格式"
            
            return True, ""
        
        # 其他格式
        else:
            return False, "未知的规则格式"
    
    def run_comprehensive_validation(self):
        """执行综合验证"""
        print("=" * 60)
        print("🔍 综合规则验证 - 新语法版")
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
        print("\n📊 验证结果:")
        print("-" * 60)
        
        for file_type, result in results.items():
            if result['total'] > 0:
                validity_rate = (result['valid'] / result['total']) * 100
                print(f"\n📄 {file_type.upper()}规则:")
                print(f"  ├── 总计规则: {result['total']:,} 条")
                print(f"  ├── 有效规则: {result['valid']:,} 条")
                print(f"  ├── 无效规则: {result['invalid']:,} 条")
                print(f"  └── 有效性: {validity_rate:.1f}%")
                
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
            }
        }
        
        # 保存报告
        report_file = self.base_dir / 'dist/validation_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📁 验证报告已保存: {report_file}")
        
        # 返回退出码
        if total_valid == 0:
            print("❌ 错误: 没有有效规则")
            return 2
        elif overall_validity < 90:  # 要求90%以上的有效性
            print("⚠️  警告: 规则有效性低于90%")
            return 1
        else:
            print("✅ 验证完成（通过严格验证）")
            return 0
    
    def run_simple_validation(self):
        """简单验证（仅检查文件是否存在和基本格式）"""
        print("=" * 60)
        print("🔍 简单规则验证")
        print("=" * 60)
        
        required_files = [
            ('dns.txt', 'DNS规则文件'),
            ('hosts.txt', 'Hosts规则文件'),
            ('filter.txt', '浏览器规则文件')
        ]
        
        all_exist = True
        
        for filename, description in required_files:
            filepath = self.base_dir / 'dist' / filename
            if filepath.exists():
                file_size = filepath.stat().st_size
                print(f"✅ {description}: 存在 ({file_size:,} 字节)")
            else:
                print(f"❌ {description}: 不存在")
                all_exist = False
        
        if all_exist:
            print("\n✅ 所有规则文件都存在")
            return 0
        else:
            print("\n❌ 缺少必要的规则文件")
            return 1


def main():
    validator = RuleValidator()
    
    # 如果提供了参数，运行简单验证
    if len(sys.argv) > 1 and sys.argv[1] == '--simple':
        exit_code = validator.run_simple_validation()
    else:
        exit_code = validator.run_comprehensive_validation()
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
