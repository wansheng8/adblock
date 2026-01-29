#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则合并脚本 - Adblock语法版
用于合并多个规则文件，支持完整Adblock语法
"""

import re
from pathlib import Path
from typing import List, Tuple, Dict, Any
from collections import defaultdict
import json
from datetime import datetime


class RuleMerger:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Adblock语法模式
        self.adblock_patterns = [
            r'^@@',  # 白名单
            r'^\|\|',  # 域名阻断
            r'^##',  # 元素隐藏
            r'^#@#',  # 元素隐藏例外
            r'^#\$#',  # 脚本注入
            r'^/\S+/$',  # 正则表达式
            r'\$[a-z]+=',  # 高级修饰符
            r'\$dnstype=',  # DNS类型
            r'\$domain=',  # 域名限定
            r'\$important',  # 重要规则
        ]
    
    def is_adblock_rule(self, rule):
        """检测是否是Adblock规则"""
        return any(re.search(pattern, rule) for pattern in self.adblock_patterns)
    
    def classify_rule(self, rule):
        """分类规则类型"""
        if not rule or rule.startswith('!'):
            return 'comment'
        
        if self.is_adblock_rule(rule):
            if rule.startswith('@@'):
                return 'whitelist'
            elif rule.startswith('||'):
                return 'domain_block'
            elif rule.startswith('##'):
                return 'element_hiding'
            elif rule.startswith('#@#'):
                return 'element_hiding_exception'
            elif rule.startswith('#$#'):
                return 'scriptlet_injection'
            elif rule.startswith('/') and rule.endswith('/'):
                return 'regex'
            elif '$' in rule:
                return 'advanced'
            else:
                return 'adblock_other'
        
        elif rule.startswith(('0.0.0.0', '127.0.0.1', '::1')):
            return 'hosts'
        else:
            return 'other'
    
    def merge_files(self, file_paths: List[Path]) -> Tuple[List[str], dict]:
        """合并多个规则文件 - Adblock语法版"""
        all_rules = []
        rule_stats = defaultdict(int)
        adblock_rules = []
        
        for file_path in file_paths:
            if file_path.exists():
                print(f"📄 读取文件: {file_path.name}")
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 提取规则（跳过注释）
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('!'):
                        rule_type = self.classify_rule(line)
                        rule_stats[rule_type] += 1
                        
                        # 分离Adblock规则
                        if rule_type in ['whitelist', 'domain_block', 'element_hiding', 
                                       'element_hiding_exception', 'scriptlet_injection', 
                                       'regex', 'advanced', 'adblock_other']:
                            adblock_rules.append(line)
                        else:
                            all_rules.append(line)
        
        # 去重
        print("\n🔧 处理规则...")
        unique_rules = sorted(set(all_rules))
        unique_adblock = sorted(set(adblock_rules))
        
        # Adblock规则放在前面
        merged_rules = unique_adblock + unique_rules
        
        print(f"📊 合并统计:")
        for rule_type, count in sorted(rule_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  ├── {rule_type}: {count} 条")
        
        print(f"  ├── 总计: {len(all_rules) + len(adblock_rules)} 条")
        print(f"  ├── 去重后: {len(merged_rules)} 条")
        print(f"  └── Adblock规则: {len(unique_adblock)} 条")
        
        return merged_rules, dict(rule_stats)
    
    def merge_custom_rules(self):
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
    
    def optimize_rules(self, rules):
        """优化规则集合"""
        print("\n⚡ 优化规则...")
        
        # 按域名分组，合并相似规则
        domain_rules = defaultdict(list)
        other_rules = []
        
        for rule in rules:
            # 提取域名阻断规则中的域名
            if rule.startswith('||'):
                match = re.match(r'^\|\|([^\/\^\$\s]+)\^', rule)
                if match:
                    domain = match.group(1)
                    domain_rules[domain].append(rule)
                else:
                    other_rules.append(rule)
            else:
                other_rules.append(rule)
        
        # 合并相同域名的多个规则
        optimized_rules = []
        
        for domain, domain_rule_list in domain_rules.items():
            if len(domain_rule_list) > 1:
                # 合并为通配符规则
                optimized_rules.append(f"||{domain}^")
            else:
                optimized_rules.extend(domain_rule_list)
        
        optimized_rules.extend(other_rules)
        
        # 去重
        optimized_rules = sorted(set(optimized_rules))
        
        print(f"📊 优化结果:")
        print(f"  ├── 原始规则: {len(rules)} 条")
        print(f"  ├── 优化后: {len(optimized_rules)} 条")
        print(f"  └── 减少: {len(rules) - len(optimized_rules)} 条")
        
        return optimized_rules
    
    def run(self):
        """运行合并 - Adblock语法版"""
        print("=" * 60)
        print("🔄 Adblock规则合并工具")
        print("=" * 60)
        
        # 合并自定义规则
        print("\n📄 步骤1: 合并自定义规则")
        custom_rules, stats = self.merge_custom_rules()
        
        if custom_rules:
            print(f"\n✅ 找到 {len(custom_rules)} 条自定义规则")
            
            # 优化规则
            print("\n📄 步骤2: 优化规则")
            optimized_rules = self.optimize_rules(custom_rules)
            
            # 保存到文件
            print("\n📄 步骤3: 保存结果")
            output_file = self.base_dir / 'rules/processed/custom_merged.txt'
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # 添加文件头
            now = datetime.now()
            header = f"""! 自定义规则合并文件 - Adblock语法版
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')}
! 规则总数: {len(optimized_rules)} 条
! 原始规则: {len(custom_rules)} 条
! 优化比例: {((len(custom_rules) - len(optimized_rules)) / len(custom_rules) * 100):.1f}%
! 
! 规则类型统计:
"""
            
            for rule_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
                header += f"! • {rule_type}: {count} 条\n"
            
            header += "\n! ============================================================\n\n"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(header + '\n'.join(optimized_rules))
            
            print(f"📁 保存到: {output_file}")
            print(f"📊 最终统计:")
            print(f"  ├── 原始规则: {len(custom_rules)} 条")
            print(f"  ├── 优化后: {len(optimized_rules)} 条")
            print(f"  ├── Adblock规则: {sum(1 for r in optimized_rules if self.is_adblock_rule(r))} 条")
            print(f"  └── 文件大小: {output_file.stat().st_size:,} 字节")
        
        print("\n" + "=" * 60)
        print("✅ 合并完成!")
        print("🎯 Adblock语法支持:")
        print("  • 域名阻断规则: ||example.com^")
        print("  • 白名单规则: @@||example.com^")
        print("  • 元素隐藏规则: ##.ad-banner")
        print("  • 脚本注入规则: #$#alert('Blocked!')")
        print("  • 正则表达式规则: /ads.*\\.com/")
        print("  • 高级修饰符规则: ||example.com^$domain=example.com")
        print("=" * 60)
        
        return custom_rules


if __name__ == "__main__":
    merger = RuleMerger()
    merger.run()
