#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - Adblock语法版
验证三层规则文件的语法正确性，支持Adblock语法
"""

import re
import sys
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Tuple, Dict, Any, List


class RuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Adblock语法模式
        self.adblock_patterns = {
            'whitelist': re.compile(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^'),
            'domain_block': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^'),
            'element_hiding': re.compile(r'^##'),
            'hosts_rule': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'),
            'modifier_rule': re.compile(r'.*\$.+'),
            'regex_rule': re.compile(r'^/.*/$'),
            'simple_domain': re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        }
    
    def classify_rule(self, rule: str) -> Dict[str, Any]:
        """分类Adblock规则类型"""
        rule = rule.strip()
        
        if not rule or rule.startswith(('!', '#', '[')):
            return {'type': 'comment', 'valid': True}
        
        result = {
            'type': 'unknown',
            'valid': False,
            'domain': '',
            'adblock_syntax': False,
            'raw_rule': rule
        }
        
        # 1. 白名单规则
        if rule.startswith('@@'):
            result['type'] = 'whitelist'
            result['adblock_syntax'] = True
            
            match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                result['domain'] = match.group(1)
                result['valid'] = True
            
            return result
        
        # 2. 域名阻断规则
        if rule.startswith('||') and '^' in rule:
            result['type'] = 'domain_block'
            result['adblock_syntax'] = True
            
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                result['domain'] = match.group(1)
                result['valid'] = True
            
            return result
        
        # 3. 元素隐藏规则
        if rule.startswith('##'):
            result['type'] = 'element_hiding'
            result['adblock_syntax'] = True
            result['valid'] = True if len(rule) > 2 else False
            return result
        
        # 4. Hosts规则
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            result['type'] = 'hosts_rule'
            result['domain'] = match.group(2)
            result['valid'] = True
            return result
        
        # 5. 带修饰符的规则
        if '$' in rule:
            result['type'] = 'modifier_rule'
            result['adblock_syntax'] = True
            
            # 提取域名
            base_part = rule.split('$')[0]
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', base_part)
            if match:
                result['domain'] = match.group(1)
            
            result['valid'] = True
            return result
        
        # 6. 正则表达式规则
        if rule.startswith('/') and rule.endswith('/'):
            result['type'] = 'regex_rule'
            result['adblock_syntax'] = True
            result['valid'] = True
            return result
        
        # 7. 纯域名规则
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            result['type'] = 'simple_domain'
            result['domain'] = rule
            result['valid'] = True
            return result
        
        # 8. 其他Adblock格式
        if re.match(r'^\|\|', rule) or re.match(r'^@@', rule) or '^' in rule:
            result['type'] = 'adblock_other'
            result['adblock_syntax'] = True
            result['valid'] = True
            return result
        
        return result
    
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
            
            rule_info = self.classify_rule(line)
            
            if rule_info['valid'] and rule_info['type'] == 'simple_domain':
                if self.is_valid_dns_rule(rule_info.get('domain', '')):
                    valid_rules += 1
                else:
                    errors.append({
                        'line': line_num,
                        'rule': line[:80] + ('...' if len(line) > 80 else ''),
                        'message': '无效的DNS规则格式'
                    })
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': f'不支持的DNS规则类型: {rule_info["type"]}'
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
            
            rule_info = self.classify_rule(line)
            
            if rule_info['valid'] and rule_info['type'] == 'hosts_rule':
                if self.is_valid_dns_rule(rule_info.get('domain', '')):
                    valid_rules += 1
                    
                    # 检查是否使用127.0.0.1
                    if line.startswith('127.0.0.1'):
                        warnings.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'message': '建议使用0.0.0.0而非127.0.0.1'
                        })
                else:
                    errors.append({
                        'line': line_num,
                        'rule': line[:80] + ('...' if len(line) > 80 else ''),
                        'message': '无效的Hosts规则格式'
                    })
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': '无效的Hosts规则格式'
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
            
            rule_info = self.classify_rule(line)
            
            if rule_info['valid']:
                valid_rules += 1
                
                # 检查警告
                if self.has_warnings(line, rule_info):
                    warnings.append({
                        'line': line_num,
                        'rule': line[:80] + ('...' if len(line) > 80 else ''),
                        'message': self.get_warning_message(line, rule_info)
                    })
            else:
                errors.append({
                    'line': line_num,
                    'rule': line[:80] + ('...' if len(line) > 80 else ''),
                    'message': f'无效的规则类型: {rule_info["type"]}'
                })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'errors': errors[:10],
            'warnings': warnings[:5]
        }
    
    def is_valid_dns_rule(self, domain: str) -> bool:
        """验证DNS规则"""
        if not domain:
            return False
        
        # 必须是纯域名
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return False
        
        # 禁止通配符
        if '*' in domain:
            return False
        
        # 禁止特殊符号
        if any(c in domain for c in ['^', '|', '$', '@', '#', '/']):
            return False
        
        # 域名长度检查
        if len(domain) > 253:
            return False
        
        # 标签长度检查
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return False
            if not label:
                return False
        
        return True
    
    def has_warnings(self, rule: str, rule_info: Dict[str, Any]) -> bool:
        """检查规则是否有警告"""
        # 长度警告
        if len(rule) > 1000:
            return True
        
        # 通配符警告
        if '*' in rule and not rule.startswith('##'):
            return True
        
        # 正则表达式警告
        if rule.startswith('/') and rule.endswith('/'):
            return True
        
        # 127.0.0.1警告
        if rule.startswith('127.0.0.1'):
            return True
        
        # 过长的元素隐藏规则
        if rule_info['type'] == 'element_hiding' and len(rule) > 500:
            return True
        
        return False
    
    def get_warning_message(self, rule: str, rule_info: Dict[str, Any]) -> str:
        """获取警告消息"""
        if len(rule) > 1000:
            return "规则过长"
        elif '*' in rule and not rule.startswith('##'):
            return "规则包含通配符*"
        elif rule.startswith('/') and rule.endswith('/'):
            return "规则使用正则表达式"
        elif rule.startswith('127.0.0.1'):
            return "建议使用0.0.0.0而非127.0.0.1"
        elif rule_info['type'] == 'element_hiding' and len(rule) > 500:
            return "CSS选择器过长"
        
        return "规则可能有潜在问题"
    
    def run_comprehensive_validation(self):
        """执行综合验证"""
        print("=" * 60)
        print("🔍 综合规则验证 - Adblock语法版")
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
                validity_rate = (result['valid'] / result['total']) * 100 if result['total'] > 0 else 0
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
            },
            "syntax_version": "adblock_1.0",
            "notes": "Adblock语法验证，支持完整Adblock语法规则"
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
        print("🔍 简单规则验证 - Adblock语法版")
        print("=" * 60)
        
        required_files = [
            ('dns.txt', 'DNS规则文件'),
            ('hosts.txt', 'Hosts规则文件'),
            ('filter.txt', '浏览器规则文件'),
            ('ping_results.json', 'Ping检测结果')
        ]
        
        all_exist = True
        
        for filename, description in required_files:
            filepath = self.base_dir / 'dist' / filename
            if filepath.exists():
                file_size = filepath.stat().st_size
                
                # 检查文件是否为空
                if file_size == 0:
                    print(f"❌ {description}: 存在但为空")
                    all_exist = False
                else:
                    # 粗略检查规则数量
                    if filename != 'ping_results.json':
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if filename == 'filter.txt':
                            lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('!')]
                        else:
                            lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
                        
                        print(f"✅ {description}: 存在 ({file_size:,} 字节, {len(lines)} 条规则)")
                    else:
                        print(f"✅ {description}: 存在 ({file_size:,} 字节)")
            else:
                print(f"❌ {description}: 不存在")
                all_exist = False
        
        # 检查Ping检测结果
        ping_file = self.base_dir / 'dist/ping_results.json'
        if ping_file.exists():
            try:
                with open(ping_file, 'r', encoding='utf-8') as f:
                    ping_data = json.load(f)
                
                valid = ping_data.get('statistics', {}).get('valid_count', 0)
                failed = ping_data.get('statistics', {}).get('failed_count', 0)
                total = valid + failed
                
                if total > 0:
                    rate = (valid / total) * 100
                    print(f"📊 Ping检测结果: {valid}/{total} 可达 ({rate:.1f}%)")
            except:
                print("⚠️  Ping检测结果文件格式错误")
        
        if all_exist:
            print("\n✅ 所有规则文件都存在且非空")
            return 0
        else:
            print("\n❌ 缺少必要的规则文件或文件为空")
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
