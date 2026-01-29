#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则合并脚本 - Adblock语法版
用于合并多个规则文件，支持Adblock语法
"""

import re
from pathlib import Path
from typing import List, Tuple, Dict, Any
from collections import defaultdict, Counter
import json
from datetime import datetime


class RuleMerger:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Adblock语法模式
        self.adblock_patterns = [
            r'^@@\|\|',  # 白名单
            r'^\|\|.*\^',  # 域名阻断
            r'^##',  # 元素隐藏
            r'\$',  # 修饰符
            r'^/',  # 正则表达式
            r'^0\.0\.0\.0',  # Hosts规则
        ]
    
    def is_adblock_rule(self, rule: str) -> bool:
        """检测是否是Adblock规则"""
        return any(re.search(pattern, rule) for pattern in self.adblock_patterns)
    
    def classify_adblock_rule(self, rule: str) -> str:
        """分类Adblock规则类型"""
        rule = rule.strip()
        
        if not rule or rule.startswith('!'):
            return 'comment'
        
        if self.is_adblock_rule(rule):
            if rule.startswith('@@'):
                return 'whitelist'
            elif rule.startswith('||'):
                return 'domain_block'
            elif rule.startswith('##'):
                return 'element_hiding'
            elif rule.startswith(('0.0.0.0', '127.0.0.1')):
                return 'hosts'
            elif '$' in rule:
                return 'modifier'
            elif rule.startswith('/') and rule.endswith('/'):
                return 'regex'
            else:
                return 'adblock_other'
        else:
            # 尝试匹配纯域名
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
                return 'simple_domain'
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
                        rule_type = self.classify_adblock_rule(line)
                        rule_stats[rule_type] += 1
                        
                        # 分离Adblock规则
                        if rule_type in ['whitelist', 'domain_block', 'element_hiding', 'modifier', 'regex']:
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
    
    def optimize_adblock_rules(self, rules):
        """优化Adblock规则集合"""
        print("\n⚡ 优化Adblock规则...")
        
        # 按域名分组，合并相似规则
        domain_rules = defaultdict(list)
        other_rules = []
        
        for rule in rules:
            # 提取域名
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                domain = match.group(1)
                domain_rules[domain].append(rule)
            else:
                other_rules.append(rule)
        
        # 合并相同域名的多个规则
        optimized_rules = []
        
        for domain, domain_rule_list in domain_rules.items():
            if len(domain_rule_list) > 1:
                # 合并为通用规则
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
        print("🔄 Adblock规则合并工具 - Adblock语法版")
        print("=" * 60)
        
        # 合并自定义规则
        print("\n📄 步骤1: 合并自定义规则")
        custom_rules, stats = self.merge_custom_rules()
        
        if custom_rules:
            print(f"\n✅ 找到 {len(custom_rules)} 条自定义规则")
            
            # 优化规则
            print("\n📄 步骤2: 优化规则")
            optimized_rules = self.optimize_adblock_rules(custom_rules)
            
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
! Adblock语法规则类型统计:
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
        print("  • 白名单规则 (@@||example.com^)")
        print("  • 域名阻断规则 (||example.com^)")
        print("  • 元素隐藏规则 (##selector)")
        print("  • 修饰符规则 ($script,third-party)")
        print("  • Hosts规则 (0.0.0.0 example.com)")
        print("  • 正则表达式规则 (/advertisement/)")
        print("=" * 60)
        
        return custom_rules


if __name__ == "__main__":
    merger = RuleMerger()
    merger.run()
