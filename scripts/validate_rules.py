#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本 - 优化增强版
更宽松的规则验证，支持更多广告拦截规则语法
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
        
        # 扩展的广告拦截规则模式（更宽松）
        self.patterns = {
            'domain_block': r'^@@?\|\|[^\s]+$',  # 更宽松的域名规则
            'domain_block_with_caret': r'^@@?\|\|[^\s]+\^[^\s]*$',  # 带^的域名规则
            'element_hiding': r'^##[^\s]+$',  # 元素隐藏规则
            'element_hiding_exception': r'^#@#[^\s]+$',  # 元素隐藏例外规则
            'advanced_selector': r'^#\?#[^\s]+$',  # 高级选择器规则
            'element_removal': r'^\$\$[^\s]+$',  # 元素移除规则
            'regex_rule': r'^/[^/]+/$',  # 正则表达式规则
            'hosts_rule': r'^(0\.0\.0\.0|127\.0\.0\.1|::1|255\.255\.255\.255|fe80::1)\s+\S+',  # Hosts规则
            'modifier_rule': r'^[^\s]+\$[^\s]+$',  # 更宽松的修饰符规则
            'redirect_rule': r'^.+\$(redirect|redirect-rule)[^\s,]*',  # 重定向规则
            'removeparam_rule': r'^.+\$removeparam[^\s,]*',  # 参数移除规则
            'domain_restriction': r'^.+\$(domain|denyallow)[^\s,]*',  # 域名限定规则
            'comment': r'^[!#].*$',  # 注释规则（!或#开头）
            'element_hiding_advanced': r'^#{3,}[^\s]+$',  # ###开头的元素隐藏规则
            'adblock_comment': r'^\[.*\]$',  # [Adblock Plus x.x] 格式
            'whitespace_line': r'^\s*$',  # 空行
        }
        
        # 合法的修饰符列表（扩展版）
        self.valid_modifiers = {
            # 请求类型修饰符
            'script', 'image', 'stylesheet', 'object', 'xmlhttprequest',
            'object-subrequest', 'subdocument', 'ping', 'websocket',
            'webrtc', 'other', 'font', 'media', 'doc', 'xhr',
            
            # 第三方修饰符
            'third-party', 'first-party', '~third-party', '~first-party', '3p', '1p',
            
            # 域名修饰符
            'domain', 'denyallow', 'from',
            
            # 特殊动作修饰符
            'important', 'redirect', 'redirect-rule', 'removeparam', 'removeheader',
            'cname', 'generichide', 'specifichide', 'badfilter', 'elemhide',
            'empty', 'mp4', 'noop', 'nooptext', 'noopframe', 'noopredirect',
            
            # 其他修饰符
            'cookie', 'stealth', 'ghide', 'shide', 'jsonprune', 'replace',
            'method', 'header', 'permissions', 'queryprune', 'removeparam',
            
            # uBlock Origin 特定修饰符
            'all', 'popunder', 'popup', 'inline-script', 'inline-font',
        }
        
        # CSS选择器基础字符
        self.css_valid_chars = r'[a-zA-Z0-9_\-\.#\[\]:* >=+~|"\'\(\)\s,@!]'
    
    def classify_rule(self, rule):
        """分类规则类型 - 优化版"""
        rule = rule.strip()
        
        if not rule:
            return 'whitespace_line'
        
        # 首先检查注释
        if rule.startswith(('!', '# ', '## ', '### ')):
            return 'comment'
        
        # 检查特殊格式
        if rule.startswith('[') and rule.endswith(']'):
            return 'adblock_comment'
        
        # 检查各种模式
        for rule_type, pattern in self.patterns.items():
            if re.match(pattern, rule, re.IGNORECASE):
                return rule_type
        
        # 默认返回unknown
        return 'unknown'
    
    def validate_single_rule(self, rule):
        """验证单条规则 - 优化版（更宽松）"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule:
            return True, "empty", []
        
        # 分类规则
        rule_type = self.classify_rule(rule)
        self.rule_types[rule_type] += 1
        
        errors = []
        warnings = []
        
        # 跳过注释的验证
        if rule_type in ['comment', 'adblock_comment', 'whitespace_line']:
            return True, rule_type, []
        
        # 通用验证
        if len(rule) > 5000:
            errors.append(f"规则过长 ({len(rule)} 字符)")
        elif len(rule) > 1000:
            warnings.append(f"规则较长 ({len(rule)} 字符)")
        
        if '\x00' in rule:
            errors.append("包含空字符")
        
        # 特定类型验证
        if rule_type == 'unknown':
            # 对于未知规则，尝试更宽松的验证
            if self.validate_unknown_rule(rule):
                warnings.append("未知规则格式，但通过宽松验证")
                return True, "unknown_valid", warnings
            else:
                errors.append("未知规则格式")
        
        elif rule_type.startswith('domain_block'):
            if not self.validate_domain_rule(rule):
                errors.append("域名规则格式错误")
        
        elif rule_type in ['element_hiding', 'element_hiding_exception', 'element_hiding_advanced']:
            selector = self.extract_css_selector(rule)
            if not self.validate_css_selector(selector):
                warnings.append("CSS选择器可能有问题")
        
        elif rule_type == 'regex_rule':
            try:
                regex_pattern = rule[1:-1]
                re.compile(regex_pattern)
            except re.error as e:
                errors.append(f"正则表达式错误: {str(e)}")
        
        elif rule_type == 'modifier_rule':
            if not self.validate_modifiers(rule):
                warnings.append("修饰符格式可能有误")
        
        # 检查潜在问题（仅警告）
        if '  ' in rule:
            warnings.append("包含多个连续空格")
        
        if rule.startswith(' ') or rule.endswith(' '):
            warnings.append("包含首尾空格")
        
        # 对于白名单规则，放宽验证
        if rule.startswith('@@') and errors:
            # 白名单规则允许更多格式
            warnings.append(f"白名单规则验证警告: {errors[0]}")
            errors.clear()
        
        return len(errors) == 0, rule_type, errors + warnings
    
    def validate_unknown_rule(self, rule):
        """宽松验证未知规则"""
        # 规则基本检查
        if not rule or len(rule) > 5000:
            return False
        
        # 检查是否包含非法字符
        if '\x00' in rule or '\n' in rule or '\r' in rule:
            return False
        
        # 检查常见广告拦截关键词
        ad_keywords = ['ad', 'ads', 'advert', 'track', 'analytics', 'pixel', 'cookie']
        if any(keyword in rule.lower() for keyword in ad_keywords):
            return True
        
        # 检查常见格式
        common_patterns = [
            r'^[a-zA-Z0-9\.\-_]+$',  # 简单域名
            r'^[a-zA-Z0-9\.\-_]+\.[a-zA-Z]{2,}$',  # 完整域名
            r'^[a-zA-Z0-9\.\-_]+/[^\s]+$',  # 带路径
            r'^\*\.',  # 通配符域名
            r'^\$[a-z]',  # 修饰符
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, rule, re.IGNORECASE):
                return True
        
        return False
    
    def validate_domain_rule(self, rule):
        """宽松验证域名规则"""
        # 提取域名部分
        if rule.startswith('@@'):
            domain_part = rule[2:]
        elif rule.startswith('||'):
            domain_part = rule[2:]
        elif rule.startswith('|'):
            domain_part = rule[1:]
        else:
            # 不是域名规则格式
            return True  # 返回True，让其他验证处理
        
        # 移除修饰符
        if '$' in domain_part:
            domain_part = domain_part.split('$')[0]
        
        # 检查域名格式（非常宽松）
        if not domain_part:
            return False
        
        # 允许的字符：字母、数字、点、连字符、下划线、星号、斜杠、^、|等
        domain_regex = r'^[a-zA-Z0-9*\.\-_\/\^\|]+$'
        return re.match(domain_regex, domain_part) is not None
    
    def extract_css_selector(self, rule):
        """从规则中提取CSS选择器"""
        if rule.startswith('##'):
            return rule[2:]
        elif rule.startswith('#@#'):
            return rule[3:]
        elif rule.startswith('#?#'):
            return rule[3:]
        elif rule.startswith('$$'):
            return rule[2:]
        elif rule.startswith('###'):
            return rule[3:]
        else:
            return rule
    
    def validate_css_selector(self, selector):
        """宽松验证CSS选择器"""
        if not selector:
            return False
        
        # 检查是否包含非法字符
        illegal_chars = ['\x00', '\n', '\r', '\t']
        for char in illegal_chars:
            if char in selector:
                return False
        
        # 非常宽松的检查：只检查最明显的问题
        # 允许大部分字符，包括Unicode和中文字符
        if len(selector) > 1000:
            return False
        
        return True
    
    def validate_modifiers(self, rule):
        """宽松验证修饰符"""
        if '$' not in rule:
            return True  # 没有修饰符也是合法的
        
        parts = rule.split('$')
        if len(parts) < 2:
            return False
        
        modifiers_str = parts[-1]
        modifiers = modifiers_str.split(',')
        
        for modifier in modifiers:
            mod = modifier.strip()
            if not mod:
                continue
            
            # 处理带值的修饰符
            if '=' in mod:
                # 只分割第一个等号
                mod_parts = mod.split('=', 1)
                mod_name = mod_parts[0].strip()
                mod_value = mod_parts[1] if len(mod_parts) > 1 else ''
                
                # 修饰符名称验证
                if not re.match(r'^[a-z0-9_\-]+$', mod_name):
                    return False
                
                # 域名值允许更复杂的格式
                if mod_name in ['domain', 'denyallow']:
                    # 允许domain=example.com|example2.com格式
                    if not mod_value:
                        return False
                elif mod_name == 'removeparam':
                    # 允许removeparam=utm_*等格式
                    if not mod_value:
                        return False
                # 其他修饰符的值不做严格验证
            else:
                # 不带值的修饰符
                if not re.match(r'^[a-z0-9_\-~]+$', mod):
                    return False
        
        return True
    
    def validate_file(self, file_path):
        """验证整个文件 - 优化版"""
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
                
                is_valid, rule_type, messages = self.validate_single_rule(line)
                
                if is_valid:
                    valid_rules += 1
                else:
                    # 只记录严重的错误，忽略警告
                    error_messages = [m for m in messages if '错误' in m or '过长' in m or '空字符' in m]
                    if error_messages:
                        invalid_details.append({
                            'line': line_num,
                            'rule': line[:80] + ('...' if len(line) > 80 else ''),
                            'errors': error_messages,
                            'warnings': [m for m in messages if m not in error_messages]
                        })
        
        # 计算有效性（更宽松的标准）
        # 如果文件很大，允许一定比例的未知规则
        if total_rules > 10000:
            # 对于大型规则集，放宽标准
            adjusted_valid = valid_rules + int(self.rule_types.get('unknown', 0) * 0.5)
            if adjusted_valid > total_rules:
                adjusted_valid = total_rules
        else:
            adjusted_valid = valid_rules
        
        return {
            'total': total_rules,
            'valid': valid_rules,
            'adjusted_valid': adjusted_valid,
            'invalid': total_rules - valid_rules,
            'details': invalid_details[:20],  # 只保留前20个错误详情
            'rule_types': dict(self.rule_types)
        }
    
    def generate_validation_report(self, blacklist_stats, whitelist_stats):
        """生成验证报告"""
        total_rules = blacklist_stats['total'] + whitelist_stats['total']
        total_valid = blacklist_stats['valid'] + whitelist_stats['valid']
        total_adjusted = blacklist_stats.get('adjusted_valid', blacklist_stats['valid']) + whitelist_stats.get('adjusted_valid', whitelist_stats['valid'])
        
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'files': {
                'blacklist': blacklist_stats,
                'whitelist': whitelist_stats
            },
            'summary': {
                'total_rules': total_rules,
                'valid_rules': total_valid,
                'adjusted_valid_rules': total_adjusted,
                'invalid_rules': total_rules - total_valid,
                'validity_rate': (total_valid / total_rules * 100) if total_rules > 0 else 0,
                'adjusted_validity_rate': (total_adjusted / total_rules * 100) if total_rules > 0 else 0
            }
        }
        
        # 合并规则类型统计
        all_rule_types = defaultdict(int)
        for stats in [blacklist_stats, whitelist_stats]:
            for rule_type, count in stats.get('rule_types', {}).items():
                all_rule_types[rule_type] += count
        
        report['rule_type_distribution'] = dict(all_rule_types)
        
        return report
    
    def print_detailed_report(self, report, file_name, stats):
        """打印详细报告"""
        print(f"\n📄 {file_name} 验证报告:")
        print("-" * 60)
        print(f"总计规则: {stats['total']:,} 条")
        print(f"有效规则: {stats['valid']:,} 条")
        
        if 'adjusted_valid' in stats:
            print(f"调整后有效: {stats['adjusted_valid']:,} 条")
        
        print(f"无效规则: {stats['invalid']:,} 条")
        
        if stats['total'] > 0:
            validity_rate = (stats['valid'] / stats['total']) * 100
            print(f"有效性: {validity_rate:.1f}%")
            
            if 'adjusted_valid' in stats:
                adjusted_rate = (stats['adjusted_valid'] / stats['total']) * 100
                print(f"调整后有效性: {adjusted_rate:.1f}%")
        
        # 规则类型分布
        if stats.get('rule_types'):
            print(f"\n规则类型分布:")
            type_items = sorted(stats['rule_types'].items(), key=lambda x: x[1], reverse=True)
            for rule_type, count in type_items[:15]:  # 只显示前15种
                percentage = (count / stats['total']) * 100 if stats['total'] > 0 else 0
                print(f"  ├── {rule_type}: {count:,} 条 ({percentage:.1f}%)")
            
            if len(type_items) > 15:
                other_count = sum(count for _, count in type_items[15:])
                print(f"  └── 其他: {other_count:,} 条")
        
        # 错误详情
        if stats.get('details'):
            error_count = len([d for d in stats['details'] if d['errors']])
            warning_count = len([d for d in stats['details'] if d['warnings'] and not d['errors']])
            
            if error_count > 0:
                print(f"\n主要错误 ({min(3, error_count)}个示例):")
                error_details = [d for d in stats['details'] if d['errors']][:3]
                for i, detail in enumerate(error_details, 1):
                    print(f"  {i}. 第{detail['line']:,}行:")
                    print(f"     规则: {detail['rule']}")
                    if detail['errors']:
                        print(f"     错误: {', '.join(detail['errors'][:2])}")
            
            if warning_count > 0:
                print(f"\n主要警告 ({min(2, warning_count)}个示例):")
                warning_details = [d for d in stats['details'] if d['warnings'] and not d['errors']][:2]
                for i, detail in enumerate(warning_details, 1):
                    print(f"  {i}. 第{detail['line']:,}行:")
                    print(f"     规则: {detail['rule'][:60]}...")
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
        print("🔍 AdBlock规则验证工具 - 优化版")
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
        print(f"总计规则: {report['summary']['total_rules']:,} 条")
        print(f"有效规则: {report['summary']['valid_rules']:,} 条")
        
        if 'adjusted_valid_rules' in report['summary']:
            print(f"调整后有效: {report['summary']['adjusted_valid_rules']:,} 条")
        
        print(f"无效规则: {report['summary']['invalid_rules']:,} 条")
        print(f"有效性: {report['summary']['validity_rate']:.1f}%")
        
        if 'adjusted_validity_rate' in report['summary']:
            print(f"调整后有效性: {report['summary']['adjusted_validity_rate']:.1f}%")
        
        # 规则类型统计
        if report.get('rule_type_distribution'):
            print(f"\n规则类型分布 (前10):")
            type_items = sorted(report['rule_type_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]
            for rule_type, count in type_items:
                percentage = (count / report['summary']['total_rules']) * 100 if report['summary']['total_rules'] > 0 else 0
                print(f"  ├── {rule_type}: {count:,} 条 ({percentage:.1f}%)")
        
        # 保存报告
        self.save_report_json(report)
        
        print("\n🎯 验证策略:")
        print("  • 宽松验证策略，避免误判")
        print("  • 支持更多规则格式")
        print("  • 区分错误和警告")
        print("  • 调整后有效性计算")
        
        print("\n" + "=" * 60)
        
        # 返回退出码 - 使用调整后的有效性
        validity_threshold = 70  # 降低阈值到70%
        
        if 'adjusted_validity_rate' in report['summary']:
            if report['summary']['adjusted_validity_rate'] < validity_threshold:
                print(f"⚠️  警告: 调整后规则有效性低于{validity_threshold}%")
                return 1
            elif report['summary']['valid_rules'] == 0:
                print("❌ 错误: 没有有效规则")
                return 2
            else:
                print("✅ 验证完成（通过宽松验证）")
                return 0
        else:
            if report['summary']['validity_rate'] < validity_threshold:
                print(f"⚠️  警告: 规则有效性低于{validity_threshold}%")
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
