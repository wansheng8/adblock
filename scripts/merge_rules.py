#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则合并脚本 - 完整语法兼容版
用于合并多个规则文件，支持所有增强语法
"""

import re
from pathlib import Path
from typing import List, Tuple, Dict, Any, Set
from collections import defaultdict, Counter
import json
from datetime import datetime


class RuleMerger:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # 增强语法模式
        self.advanced_patterns = [
            r'@@\|\|',  # 白名单
            r'\$dnstype=CNAME',  # CNAME拦截
            r'\$category=',  # 分类规则
            r'\$responsepolicy=',  # 响应策略
            r'\$removeparam=',  # 参数移除
            r'\$(domain|denyallow)=',  # 域名限定
            r'\$redirect=',  # 重定向
            r'\$(generichide|specifichide)',  # 隐藏规则
            r'\$(badfilter|important)',  # 特殊修饰符
            r'#@#',  # 元素隐藏例外
            r'#\?#',  # 高级选择器
            r'\$\$',  # 元素移除
        ]
        
        # 规则类型映射
        self.rule_type_names = {
            'whitelist': '白名单规则',
            'domain_block': '域名阻断规则',
            'exact_domain': '精确域名规则',
            'cname_block': 'CNAME拦截规则',
            'element_hiding': '元素隐藏规则',
            'advanced': '高级规则',
            'category_rule': '分类规则',
            'response_policy': '响应策略规则',
            'hosts': 'Hosts格式规则',
            'regex': '正则表达式规则',
            'comment': '注释',
            'other': '其他规则'
        }
    
    def is_advanced_rule(self, rule: str) -> bool:
        """检测是否是高级规则"""
        return any(re.search(pattern, rule) for pattern in self.advanced_patterns)
    
    def classify_rule(self, rule: str) -> Tuple[str, Dict[str, Any]]:
        """分类规则类型 - 完整语法版"""
        rule = rule.strip()
        
        if not rule:
            return 'comment', {}
        
        if rule.startswith('!'):
            return 'comment', {}
        
        # 1. 白名单规则 (@@开头)
        if rule.startswith('@@'):
            if re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule):
                return 'whitelist', {
                    'domain': re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule).group(1),
                    'subdomain': True,
                    'full_rule': rule
                }
            else:
                return 'whitelist', {'full_rule': rule}
        
        # 2. CNAME拦截规则
        if '$dnstype=CNAME' in rule:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                return 'cname_block', {
                    'domain': match.group(1),
                    'full_rule': rule
                }
        
        # 3. 分类规则
        if '$category=' in rule:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                category_match = re.search(r'\$category=([^,]+)', rule)
                category = category_match.group(1) if category_match else 'unknown'
                return 'category_rule', {
                    'domain': match.group(1),
                    'category': category,
                    'full_rule': rule
                }
        
        # 4. 响应策略规则
        if '$responsepolicy=' in rule:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                policy_match = re.search(r'\$responsepolicy=([^,]+)', rule)
                policy = policy_match.group(1) if policy_match else 'block'
                return 'response_policy', {
                    'domain': match.group(1),
                    'policy': policy,
                    'full_rule': rule
                }
        
        # 5. 域名阻断规则 (||开头 ^结尾)
        if rule.startswith('||') and '^' in rule:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                return 'domain_block', {
                    'domain': match.group(1),
                    'subdomain': True,
                    'exact': rule.endswith('^$'),
                    'full_rule': rule
                }
        
        # 6. 精确域名规则
        if rule.startswith('||') and '^$' in rule:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^\$', rule)
            if match:
                return 'exact_domain', {
                    'domain': match.group(1),
                    'full_rule': rule
                }
        
        # 7. 元素隐藏规则
        if rule.startswith('##'):
            return 'element_hiding', {'full_rule': rule}
        
        # 8. Hosts规则
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            return 'hosts', {
                'ip': match.group(1),
                'domain': match.group(2),
                'full_rule': rule
            }
        
        # 9. 正则表达式规则
        if rule.startswith('/') and rule.endswith('/'):
            return 'regex', {'full_rule': rule}
        
        # 10. 高级规则（带其他修饰符）
        if self.is_advanced_rule(rule):
            return 'advanced', {'full_rule': rule}
        
        # 11. 简单域名
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return 'domain_block', {
                'domain': rule,
                'exact': True,
                'full_rule': f'||{rule}^'
            }
        
        # 12. 其他规则
        return 'other', {'full_rule': rule}
    
    def merge_files(self, file_paths: List[Path]) -> Tuple[List[str], Dict[str, int]]:
        """合并多个规则文件 - 完整语法版"""
        all_rules = []
        rule_stats = defaultdict(int)
        rule_details = defaultdict(list)
        
        print(f"📄 开始合并 {len(file_paths)} 个文件...")
        
        for file_path in file_paths:
            if file_path.exists():
                file_name = file_path.name
                print(f"  ├── 读取: {file_name}")
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    lines = content.split('\n')
                    file_rules = 0
                    
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith('!'):
                            continue
                        
                        rule_type, details = self.classify_rule(line)
                        rule_stats[rule_type] += 1
                        
                        # 根据规则类型处理
                        if rule_type in ['whitelist', 'cname_block', 'category_rule', 
                                       'response_policy', 'element_hiding', 'regex']:
                            # 这些规则直接添加，不修改
                            all_rules.append(details['full_rule'])
                        elif rule_type == 'domain_block':
                            # 域名阻断规则，标准化格式
                            if 'domain' in details:
                                rule = f"||{details['domain']}^"
                                if details.get('exact'):
                                    rule += '$'
                                all_rules.append(rule)
                            else:
                                all_rules.append(details['full_rule'])
                        elif rule_type == 'hosts':
                            # Hosts规则，标准化为0.0.0.0
                            if 'domain' in details:
                                all_rules.append(f"0.0.0.0 {details['domain']}")
                            else:
                                all_rules.append(details['full_rule'])
                        elif rule_type == 'advanced':
                            # 高级规则，保持原样
                            all_rules.append(details['full_rule'])
                        else:
                            # 其他规则，保持原样
                            all_rules.append(details['full_rule'])
                        
                        file_rules += 1
                    
                    print(f"  └── {file_name}: {file_rules} 条规则")
                    
                except Exception as e:
                    print(f"  ⚠️  读取 {file_name} 失败: {str(e)}")
            else:
                print(f"  ❌ 文件不存在: {file_path}")
        
        # 去重
        print("\n🔧 处理规则...")
        unique_rules = sorted(set(all_rules))
        
        # 重新统计去重后的规则类型
        final_stats = defaultdict(int)
        for rule in unique_rules:
            rule_type, _ = self.classify_rule(rule)
            final_stats[rule_type] += 1
        
        print(f"📊 合并统计:")
        print(f"  ├── 原始规则: {len(all_rules)} 条")
        print(f"  ├── 去重后: {len(unique_rules)} 条")
        print(f"  └── 移除重复: {len(all_rules) - len(unique_rules)} 条")
        
        for rule_type, count in sorted(final_stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                type_name = self.rule_type_names.get(rule_type, rule_type)
                print(f"    • {type_name}: {count} 条")
        
        return unique_rules, dict(final_stats)
    
    def merge_custom_rules(self) -> Tuple[List[str], Dict[str, int]]:
        """合并自定义规则"""
        custom_dir = self.base_dir / 'rules/custom'
        if not custom_dir.exists():
            print("📂 自定义规则目录不存在")
            return [], {}
        
        custom_files = list(custom_dir.glob('*.txt'))
        if not custom_files:
            print("📂 未找到自定义规则文件")
            return [], {}
        
        print(f"📂 找到 {len(custom_files)} 个自定义规则文件")
        
        merged_rules, stats = self.merge_files(custom_files)
        
        return merged_rules, stats
    
    def optimize_rules(self, rules: List[str]) -> List[str]:
        """优化规则集合 - 完整语法版"""
        print("\n⚡ 优化规则...")
        
        # 分类规则
        rule_categories = defaultdict(list)
        for rule in rules:
            rule_type, details = self.classify_rule(rule)
            rule_categories[rule_type].append((rule, details))
        
        optimized_rules = []
        
        # 处理每种规则类型
        for rule_type, rule_list in rule_categories.items():
            if not rule_list:
                continue
            
            type_name = self.rule_type_names.get(rule_type, rule_type)
            print(f"  ├── 处理 {type_name}: {len(rule_list)} 条")
            
            if rule_type == 'domain_block':
                # 域名阻断规则：合并相同域名的规则
                domain_map = defaultdict(list)
                for rule, details in rule_list:
                    if 'domain' in details:
                        domain = details['domain']
                        domain_map[domain].append(rule)
                    else:
                        optimized_rules.append(rule)
                
                # 对于每个域名，只保留一个规则
                for domain, domain_rules in domain_map.items():
                    if len(domain_rules) > 1:
                        # 如果有多个规则，选择一个
                        # 优先选择精确匹配的规则
                        exact_rules = [r for r in domain_rules if '$' in r and 'domain=' in r]
                        if exact_rules:
                            optimized_rules.append(exact_rules[0])
                        else:
                            optimized_rules.append(f"||{domain}^")
                    else:
                        optimized_rules.extend(domain_rules)
            
            elif rule_type == 'hosts':
                # Hosts规则：确保使用0.0.0.0
                hosts_map = set()
                for rule, details in rule_list:
                    if 'domain' in details:
                        hosts_map.add(f"0.0.0.0 {details['domain']}")
                    else:
                        optimized_rules.append(rule)
                
                optimized_rules.extend(sorted(hosts_map))
            
            elif rule_type in ['whitelist', 'cname_block', 'category_rule', 
                             'response_policy', 'element_hiding', 'advanced']:
                # 这些规则保持原样
                optimized_rules.extend([rule for rule, _ in rule_list])
            
            else:
                # 其他规则保持原样
                optimized_rules.extend([rule for rule, _ in rule_list])
        
        # 去重
        optimized_rules = sorted(set(optimized_rules))
        
        print(f"📊 优化结果:")
        print(f"  ├── 原始规则: {len(rules)} 条")
        print(f"  ├── 优化后: {len(optimized_rules)} 条")
        print(f"  └── 减少: {len(rules) - len(optimized_rules)} 条")
        
        return optimized_rules
    
    def generate_report(self, original_rules: List[str], optimized_rules: List[str], 
                       stats: Dict[str, int]) -> Dict[str, Any]:
        """生成合并报告"""
        report = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "summary": {
                "original_rules": len(original_rules),
                "optimized_rules": len(optimized_rules),
                "removed_duplicates": len(original_rules) - len(optimized_rules),
                "optimization_rate": ((len(original_rules) - len(optimized_rules)) / len(original_rules) * 100) 
                                     if original_rules else 0
            },
            "rule_statistics": {},
            "features_supported": [
                "whitelist_rules",
                "exact_domain_rules",
                "subdomain_wildcard",
                "cname_blocking",
                "category_based_rules",
                "response_policies",
                "element_hiding",
                "advanced_modifiers"
            ]
        }
        
        # 转换统计信息
        for rule_type, count in stats.items():
            type_name = self.rule_type_names.get(rule_type, rule_type)
            report["rule_statistics"][type_name] = count
        
        return report
    
    def run(self):
        """运行合并 - 完整语法版"""
        print("=" * 60)
        print("🔄 AdBlock规则合并工具 - 完整语法版")
        print("=" * 60)
        
        # 合并自定义规则
        print("\n📄 步骤1: 合并自定义规则")
        custom_rules, stats = self.merge_custom_rules()
        
        if custom_rules:
            print(f"\n✅ 找到 {len(custom_rules)} 条自定义规则")
            
            # 优化规则
            print("\n📄 步骤2: 优化规则")
            optimized_rules = self.optimize_rules(custom_rules)
            
            # 生成报告
            print("\n📄 步骤3: 生成报告")
            report = self.generate_report(custom_rules, optimized_rules, stats)
            
            # 保存结果
            print("\n📄 步骤4: 保存结果")
            output_file = self.base_dir / 'rules/processed/custom_merged.txt'
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # 构建文件头
            header = f"""! 自定义规则合并文件 - 完整语法版
! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
! 规则总数: {len(optimized_rules)} 条
! 原始规则: {len(custom_rules)} 条
! 优化比例: {report['summary']['optimization_rate']:.1f}%
! 
! 支持的语法特性:
! • 白名单规则 (@@||domain^)
! • 精确域名规则
! • 子域/通配规则 (||domain^)
! • CNAME拦截规则 ($dnstype=CNAME)
! • 分类规则 ($category=xxx)
! • 响应策略规则 ($responsepolicy=xxx)
! • 元素隐藏规则 (##selector)
! • 高级修饰符规则
! 
! 规则类型统计:
"""
            
            for type_name, count in sorted(report['rule_statistics'].items(), 
                                         key=lambda x: x[1], reverse=True):
                header += f"! • {type_name}: {count} 条\n"
            
            header += "\n! ============================================================\n\n"
            
            # 写入文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(header + '\n'.join(optimized_rules))
            
            # 保存JSON报告
            report_file = self.base_dir / 'rules/processed/merge_report.json'
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"📁 保存规则文件: {output_file}")
            print(f"📊 保存合并报告: {report_file}")
            print(f"\n📊 最终统计:")
            print(f"  ├── 原始规则: {len(custom_rules)} 条")
            print(f"  ├── 优化后: {len(optimized_rules)} 条")
            print(f"  ├── 高级规则: {sum(1 for r in optimized_rules if self.is_advanced_rule(r))} 条")
            print(f"  └── 文件大小: {output_file.stat().st_size:,} 字节")
        
        print("\n" + "=" * 60)
        print("✅ 合并完成!")
        print("🎯 完整语法支持:")
        print("  • 白名单规则 (@@||example.com^)")
        print("  • 精确域名匹配")
        print("  • 子域/通配规则 (||example.com^)")
        print("  • CNAME拦截 ($dnstype=CNAME)")
        print("  • 分类规则 ($category=ads/tracking)")
        print("  • 响应策略 ($responsepolicy=block)")
        print("  • 元素隐藏规则 (##selector)")
        print("  • 高级修饰符规则")
        print("=" * 60)
        
        return custom_rules


if __name__ == "__main__":
    merger = RuleMerger()
    merger.run()
