#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - 完整增强版
支持高级广告拦截规则语法验证
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
        
        # 广告拦截规则模式
        self.patterns = {
            'domain_block': r'^@@?\|\|[^\s\^]+(\^|\^[^\s]+)?$',
            'element_hiding': r'^##[^\s#?@]+$',
            'element_hiding_exception': r'^#@#[^\s]+$',
            'advanced_selector': r'^#\?#[^\s]+$',
            'element_removal': r'^\$\$[^\s]+$',
            'regex_rule': r'^/[^/]+/$',
            'hosts_rule': r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+\S+',
            'modifier_rule': r'^[^\s]+\$[^,\s]+(,[^,\s]+)*$',
            'redirect_rule': r'^.+\$(redirect|redirect-rule)=[^,\s]+$',
            'removeparam_rule': r'^.+\$removeparam=[^,\s]+$',
            'domain_restriction': r'^.+\$(domain|denyallow)=[^,\s]+$',
            'comment': r'^!.*$',
        }
        
        # CSS选择器验证模式
        self.css_patterns = [
            r'^[a-zA-Z_\-][a-zA-Z0-9_\-]*$',  # 标签选择器
            r'^\.[a-zA-Z_\-][a-zA-Z0-9_\-]*$',  # 类选择器
            r'^#[a-zA-Z_\-][a-zA-Z0-9_\-]*$',  # ID选择器
            r'^\[[a-zA-Z_\-][a-zA-Z0-9_\-]*(\|?=.*?)?\]$',  # 属性选择器
            r'^[a-zA-Z_\-][a-zA-Z0-9_\-]*:[a-zA-Z_\-]+$',  # 伪类
            r'^[a-zA-Z_\-][a-zA-Z0-9_\-]*::[a-zA-Z_\-]+$',  # 伪元素
        ]
        
        # 合法修饰符
        self.valid_modifiers = {
            'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
            'object-subrequest', 'subdocument', 'ping', 'websocket',
            'webrtc', 'other', 'font', 'media', 'third-party', 'first-party',
            '~third-party', '~first-party', 'domain', 'denyallow',
            'important', 'redirect', 'redirect-rule', 'removeparam',
            'cname', 'generichide', 'specifichide', 'badfilter',
            'empty', 'mp4', 'noop', 'nooptext', 'noopframe', 'noopredirect'
        }
    
    def classify_rule(self, rule):
        """分类规则类型"""
        for rule_type, pattern in self.patterns.items():
            if re.match(pattern, rule):
                return rule_type
        return 'unknown'
    
    def validate_single_rule(self, rule):
        """验证单条规则 - 增强版"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule:
            return True, "empty", []
        
        if rule.startswith('!'):
            self.rule_types['comment'] += 1
            return True, "comment", []
        
        # 分类规则
        rule_type = self.classify_rule(rule)
        self.rule_types[rule_type] += 1
        
        errors = []
        warnings = []
        
        # 通用验证
        if len(rule) > 2000:
            errors.append(f"规则过长 ({len(rule)} 字符)")
        elif len(rule) > 500:
            warnings.append(f"规则较长 ({len(rule)} 字符)")
        
        if '\x00' in rule:
            errors.append("包含空字符")
        
        # 特定类型验证
        if rule_type == 'domain_block':
            if not self.validate_domain_rule(rule):
                errors.append("域名规则格式错误")
        
        elif rule_type == 'element_hiding':
            if not self.validate_css_selector(rule[2:]):
                errors.append("CSS选择器格式错误")
        
        elif rule_type == 'element_hiding_exception':
            selector = rule.split('#@#')[-1]
            if not self.validate_css_selector(selector):
                errors.append("CSS选择器格式错误")
        
        elif rule_type == 'advanced_selector':
            selector = rule.split('#?#')[-1]
            if not self.validate_css_selector(selector):
                errors.append("高级选择器格式错误")
        
        elif rule_type == 'element_removal':
            selector = rule[2:]
            if not self.validate_css_selector(selector):
                errors.append("元素移除选择器格式错误")
        
        elif rule_type == 'regex_rule':
            try:
                regex_pattern = rule[1:-1]
                re.compile(regex_pattern)
            except re.error as e:
                errors.append(f"正则表达式错误: {str(e)}")
        
        elif rule_type == 'modifier_rule':
            if not self.validate_modifiers(rule):
                errors.append("修饰符格式错误")
        
        elif rule_type == 'unknown':
            # 尝试分析未知规则
            if '$' in rule:
                warnings.append("未知规则格式，但包含修饰符")
            else:
                errors.append("未知规则格式")
        
        # 检查潜在问题
        if '  ' in rule:
            warnings.append("包含多个连续空格")
        
        if rule.startswith(' ') or rule.endswith(' '):
            warnings.append("包含首尾空格")
        
        # 检查常见错误模式
        if '||.' in rule:
            errors.append("域名规则包含非法字符 '.'")
        
        if '## ' in rule:
            errors.append("元素隐藏规则包含空格")
        
        return len(errors) == 0, rule_type, errors + warnings
    
    def validate_domain_rule(self, rule):
        """验证域名规则"""
        # 提取域名部分
        if rule.startswith('@@'):
            domain_part = rule[2:]
        elif rule.startswith('||'):
            domain_part = rule[2:]
        elif rule.startswith('|'):
            domain_part = rule[1:]
        else:
            return False
        
        # 移除修饰符
        if '$' in domain_part:
            domain_part = domain_part.split('$')[0]
        
        # 检查域名格式
        if domain_part.endswith('^'):
            domain_part = domain_part[:-1]
        
        if not domain_part:
            return False
        
        # 基本域名格式验证
        domain_regex = r'^[a-zA-Z0-9*\.\-_]+(\/[^\s]*)?$'
        return re.match(domain_regex, domain_part) is not None
    
    def validate_css_selector(self, selector):
        """验证CSS选择器"""
        # 简单验证：检查是否包含合法字符
        # 更复杂的验证需要解析CSS选择器，这里简化处理
        if not selector:
            return False
        
        # 检查是否包含非法字符
        illegal_chars = ['\x00', '\n', '\r', '\t']
        for char in illegal_chars:
            if char in selector:
                return False
        
        # 检查基本格式
        # 允许的字符：字母、数字、下划线、连字符、点、井号、方括号、冒号、星号、空格
        valid_chars = r'[a-zA-Z0-9_\-\.#\[\]:* >=+~|"\'\(\)\s]'
        
        # 检查每个字符
        for char in selector:
            if not re.match(valid_chars, char):
                return False
        
        return True
    
    def validate_modifiers(self, rule):
        """验证修饰符"""
        if '$' not in rule:
            return False
        
        parts = rule.split('$')
        if len(parts) != 2:
            return False
        
        modifiers = parts[1].split(',')
        
        for modifier in modifiers:
            mod = modifier.strip()
            
            # 处理带值的修饰符
            if '=' in mod:
                mod_name = mod.split('=')[0]
                if mod_name not in self.valid_modifiers:
                    return False
            else:
                if mod not in self.valid_modifiers:
                    return False
        
        return True
    
    def validate_file(self, file_path):
        """验证整个文件"""
        path = Path(file_path)
        if not path.exists():
            print(f"❌ 文件不存在: {file_path}")
            return {'total': 0, 'valid': 0, 'errors': [], 'warnings': []}
        
        print(f"🔍 验证文件: {path.name}")
        
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_rules = 0
        valid_rules = 0
        invalid_details = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.rstrip('\n')
            
            # 统计非空行
            if line.strip():
                total_rules += 1
                
                is_valid, rule_type, messages = self.validate_single_rule(line)
                
                if is_valid:
                    valid_rules += 1
                else:
                    error_msg = f"第{line_num}行: {messages[0] if messages else '未知错误'}"
                    if len(messages) > 1:
                        error_msg += f" (+{len(messages)-1}个其他问题)"
                    invalid_details.append({
                        'line': line_num,
                        'rule': line[:100] + ('...' if len(line) > 100 else ''),
                        'errors': [m for m in messages if '错误' in m],
                        'warnings': [m for m in messages if '警告' in m]
                    })
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'invalid': total_rules - valid_rules,
            'details': invalid_details,
            'rule_types': dict(self.rule_types)
        }
    
    def generate_validation_report(self, blacklist_stats, whitelist_stats):
        """生成验证报告"""
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'files': {
                'blacklist': blacklist_stats,
                'whitelist': whitelist_stats
            },
            'summary': {
                'total_rules': blacklist_stats['total'] + whitelist_stats['total'],
                'valid_rules': blacklist_stats['valid'] + whitelist_stats['valid'],
                'invalid_rules': blacklist_stats['invalid'] + whitelist_stats['invalid'],
                'validity_rate': 0
            }
        }
        
        # 计算有效性比例
        total = report['summary']['total_rules']
        valid = report['summary']['valid_rules']
        if total > 0:
            report['summary']['validity_rate'] = (valid / total) * 100
        
        # 规则类型统计
        all_rule_types = defaultdict(int)
        for stats in [blacklist_stats, whitelist_stats]:
            for rule_type, count in stats.get('rule_types', {}).items():
                all_rule_types[rule_type] += count
        
        report['rule_type_distribution'] = dict(all_rule_types)
        
        # 主要错误统计
        error_categories = defaultdict(int)
        for stats in [blacklist_stats, whitelist_stats]:
            for detail in stats.get('details', []):
                for error in detail['errors']:
                    # 提取错误类别
                    if '格式错误' in error:
                        error_categories['格式错误'] += 1
                    elif '域名' in error:
                        error_categories['域名错误'] += 1
                    elif 'CSS' in error:
                        error_categories['CSS错误'] += 1
                    elif '正则' in error:
                        error_categories['正则表达式错误'] += 1
                    elif '修饰符' in error:
                        error_categories['修饰符错误'] += 1
                    else:
                        error_categories['其他错误'] += 1
        
        report['error_categories'] = dict(error_categories)
        
        return report
    
    def print_detailed_report(self, report, file_name, stats):
        """打印详细报告"""
        print(f"\n📄 {file_name} 验证报告:")
        print("-" * 60)
        print(f"总计规则: {stats['total']} 条")
        print(f"有效规则: {stats['valid']} 条")
        print(f"无效规则: {stats['invalid']} 条")
        
        if stats['total'] > 0:
            validity_rate = (stats['valid'] / stats['total']) * 100
            print(f"有效性: {validity_rate:.1f}%")
        
        # 规则类型分布
        if stats.get('rule_types'):
            print(f"\n规则类型分布:")
            for rule_type, count in sorted(stats['rule_types'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / stats['total']) * 100 if stats['total'] > 0 else 0
                print(f"  ├── {rule_type}: {count} 条 ({percentage:.1f}%)")
        
        # 错误详情
        if stats.get('details'):
            print(f"\n主要错误 ({min(5, len(stats['details']))}个示例):")
            for i, detail in enumerate(stats['details'][:5]):
                print(f"  {i+1}. 第{detail['line']}行:")
                print(f"     规则: {detail['rule'][:80]}...")
                if detail['errors']:
                    print(f"     错误: {', '.join(detail['errors'][:2])}")
                if detail['warnings']:
                    print(f"     警告: {', '.join(detail['warnings'][:2])}")
        
        print("-" * 60)
    
    def save_report_json(self, report):
        """保存报告为JSON文件"""
        report_file = self.base_dir / 'dist/validation_report.json'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📊 验证报告已保存: {report_file}")
    
    def run(self):
        """执行验证"""
        print("=" * 60)
        print("🔍 AdBlock规则验证工具 - 增强版")
        print("=" * 60)
        
        # 重置统计
        self.validation_errors = []
        self.validation_warnings = []
        self.rule_types = defaultdict(int)
        
        # 验证黑名单
        print("\n📄 验证黑名单文件...")
        blacklist_stats = self.validate_file(self.base_dir / 'dist/blacklist.txt')
        
        # 验证白名单
        print("\n📄 验证白名单文件...")
        self.rule_types = defaultdict(int)  # 重置统计
        whitelist_stats = self.validate_file(self.base_dir / 'dist/whitelist.txt')
        
        # 生成报告
        print("\n📊 生成验证报告...")
        report = self.generate_validation_report(blacklist_stats, whitelist_stats)
        
        # 打印详细报告
        self.print_detailed_report(report, "黑名单", blacklist_stats)
        self.print_detailed_report(report, "白名单", whitelist_stats)
        
        # 总体统计
        print("\n📈 总体验证统计:")
        print("-" * 60)
        print(f"总计规则: {report['summary']['total_rules']} 条")
        print(f"有效规则: {report['summary']['valid_rules']} 条")
        print(f"无效规则: {report['summary']['invalid_rules']} 条")
        print(f"有效性: {report['summary']['validity_rate']:.1f}%")
        
        # 规则类型统计
        if report.get('rule_type_distribution'):
            print(f"\n规则类型分布:")
            for rule_type, count in sorted(report['rule_type_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / report['summary']['total_rules']) * 100 if report['summary']['total_rules'] > 0 else 0
                print(f"  ├── {rule_type}: {count} 条 ({percentage:.1f}%)")
        
        # 错误类别统计
        if report.get('error_categories'):
            print(f"\n错误类别分布:")
            for category, count in sorted(report['error_categories'].items(), key=lambda x: x[1], reverse=True):
                print(f"  ├── {category}: {count} 次")
        
        # 保存报告
        self.save_report_json(report)
        
        print("\n🎯 验证功能:")
        print("  • 支持11种规则类型验证")
        print("  • CSS选择器语法检查")
        print("  • 域名格式验证")
        print("  • 修饰符合法性检查")
        print("  • 正则表达式编译测试")
        print("  • 详细错误报告和统计")
        
        print("\n" + "=" * 60)
        
        # 返回退出码
        if report['summary']['validity_rate'] < 90:
            print("⚠️  警告: 规则有效性低于90%")
            return 1
        elif report['summary']['valid_rules'] == 0:
            print("❌ 错误: 没有有效规则")
            return 2
        else:
            print("✅ 验证完成")
            return 0


def main():
    validator = RuleValidator()
    exit_code = validator.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
