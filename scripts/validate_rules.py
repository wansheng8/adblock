#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - Adblock语法版
验证三层规则文件的语法正确性
"""

import re
import sys
import json
import socket
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Tuple, Dict, Any, List


class RuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Adblock语法模式
        self.adblock_patterns = {
            'whitelist': re.compile(r'^@@'),
            'domain_block': re.compile(r'^\|\|([^\/\^\$\s]+)\^'),
            'element_hiding': re.compile(r'^##'),
            'regex': re.compile(r'^/(.*)/$'),
            'hosts': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^#\s]+)'),
            'advanced': re.compile(r'\$[a-z]+='),
            'comment': re.compile(r'^[!\[#]')
        }
    
    def validate_domain_format(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain or len(domain) > 253:
            return False
        
        # 允许通配符
        if '*' in domain:
            if not domain.startswith('*.'):
                return False
            domain = domain[2:]
        
        # 基本域名格式验证
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return False
        
        # 检查标签长度
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
        
        return True
    
    def ping_domain(self, domain: str) -> Tuple[bool, str]:
        """Ping检查域名"""
        if not domain or domain.startswith('*.'):
            return True, "通配符域名跳过检查"
        
        try:
            # 尝试DNS解析
            start_time = time.time()
            socket.setdefaulttimeout(3)
            ip_address = socket.gethostbyname(domain)
            resolve_time = time.time() - start_time
            
            return True, f"DNS解析成功: {ip_address} ({resolve_time:.2f}s)"
        except socket.gaierror:
            return False, "DNS解析失败"
        except Exception as e:
            return False, f"检查失败: {str(e)}"
    
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
            
            # 验证域名格式
            if self.validate_domain_format(line):
                valid_rules += 1
                
                # 对有效域名进行ping检查
                if not line.startswith('*.'):
                    ping_result, ping_msg = self.ping_domain(line)
                    if not ping_result:
                        warnings.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'message': f'域名无法访问: {ping_msg}'
                        })
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
            'warnings': warnings[:5]
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
            
            # 验证Hosts规则格式
            match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^#\s]+)$', line)
            if match:
                domain = match.group(2)
                if self.validate_domain_format(domain):
                    valid_rules += 1
                    
                    # 检查是否使用127.0.0.1
                    if line.startswith('127.0.0.1'):
                        warnings.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'message': '建议使用0.0.0.0而非127.0.0.1'
                        })
                    
                    # ping检查
                    if not domain.startswith('*.'):
                        ping_result, ping_msg = self.ping_domain(domain)
                        if not ping_result:
                            warnings.append({
                                'line': line_num,
                                'rule': line[:80] + ('...' if len(line) > 80 else ''),
                                'message': f'域名无法访问: {ping_msg}'
                            })
                else:
                    errors.append({
                        'line': line_num,
                        'rule': line[:80] + ('...' if len(line) > 80 else ''),
                        'message': '无效的域名格式'
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
            
            # 分类和验证规则
            rule_info = self.classify_adblock_rule(line)
            
            if rule_info['valid']:
                valid_rules += 1
                
                # 检查警告
                if self.has_warnings(line, rule_info):
                    warnings.append({
                        'line': line_num,
                        'rule': line[:80] + ('...' if len(line) > 80 else ''),
                        'message': self.get_warning_message(line, rule_info)
                    })
                
                # 对域名规则进行ping检查
                if rule_info.get('domain') and not rule_info['domain'].startswith('*.'):
                    ping_result, ping_msg = self.ping_domain(rule_info['domain'])
                    if not ping_result:
                        warnings.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'message': f'域名无法访问: {ping_msg}'
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
    
    def classify_adblock_rule(self, rule: str) -> Dict[str, Any]:
        """分类Adblock规则"""
        if not rule:
            return {'type': 'empty', 'valid': False}
        
        if rule.startswith('!'):
            return {'type': 'comment', 'valid': True}
        
        result = {
            'type': 'unknown',
            'valid': False,
            'domain': '',
            'raw_rule': rule
        }
        
        if rule.startswith('@@'):
            result['type'] = 'whitelist'
            # 提取域名
            match = re.match(r'^@@\|\|([^\/\^\$\s]+)\^', rule)
            if match:
                result['domain'] = match.group(1)
                if self.validate_domain_format(result['domain']):
                    result['valid'] = True
            else:
                result['valid'] = True  # 白名单规则可能没有域名
        
        elif rule.startswith('||') and '^' in rule:
            result['type'] = 'domain_block'
            match = re.match(r'^\|\|([^\/\^\$\s]+)\^', rule)
            if match:
                result['domain'] = match.group(1)
                if self.validate_domain_format(result['domain']):
                    result['valid'] = True
        
        elif rule.startswith('##'):
            result['type'] = 'element_hiding'
            result['valid'] = True if len(rule) > 2 else False
        
        elif rule.startswith('/') and rule.endswith('/'):
            result['type'] = 'regex'
            try:
                re.compile(rule[1:-1])
                result['valid'] = True
            except re.error:
                result['valid'] = False
        
        elif '$' in rule:
            result['type'] = 'advanced'
            result['valid'] = True
            # 尝试提取域名
            match = re.match(r'^\|\|([^\/\^\$\s]+)\^', rule.split('$')[0])
            if match:
                result['domain'] = match.group(1)
        
        elif re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+', rule):
            result['type'] = 'hosts'
            match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^#\s]+)', rule)
            if match:
                result['domain'] = match.group(2)
                if self.validate_domain_format(result['domain']):
                    result['valid'] = True
        
        else:
            # 尝试作为简单域名
            if self.validate_domain_format(rule):
                result['type'] = 'simple_domain'
                result['domain'] = rule
                result['valid'] = True
        
        return result
    
    def has_warnings(self, rule: str, rule_info: Dict[str, Any]) -> bool:
        """检查规则是否有警告"""
        # 长度警告
        if len(rule) > 1000:
            return True
        
        # 复杂的正则表达式
        if rule_info['type'] == 'regex':
            pattern = rule[1:-1]
            if len(pattern) > 100:
                return True
        
        # 127.0.0.1警告
        if rule.startswith('127.0.0.1'):
            return True
        
        return False
    
    def get_warning_message(self, rule: str, rule_info: Dict[str, Any]) -> str:
        """获取警告消息"""
        if len(rule) > 1000:
            return "规则过长"
        elif rule_info['type'] == 'regex':
            return "规则使用正则表达式"
        elif rule.startswith('127.0.0.1'):
            return "建议使用0.0.0.0而非127.0.0.1"
        
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
            "syntax_type": "adblock",
            "validation_features": [
                "domain_format_validation",
                "ping_check",
                "adblock_syntax_validation"
            ]
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
            ('filter.txt', '浏览器规则文件')
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
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if filename == 'filter.txt':
                        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('!')]
                    else:
                        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
                    
                    print(f"✅ {description}: 存在 ({file_size:,} 字节, {len(lines)} 条规则)")
                    
                    # 检查Adblock语法规则
                    if filename == 'filter.txt' and len(lines) > 0:
                        adblock_rules = 0
                        for line in lines[:20]:  # 只检查前20行
                            if any(line.startswith(pattern) for pattern in ['||', '@@', '##', '#@#', '#$#', '/']):
                                adblock_rules += 1
                        
                        if adblock_rules > 0:
                            print(f"  ⚡ 检测到Adblock语法规则: {adblock_rules} 条")
            else:
                print(f"❌ {description}: 不存在")
                all_exist = False
        
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
