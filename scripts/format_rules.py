#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化与优化脚本
"""

import re
import sys
from pathlib import Path


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
    def optimize_blacklist(self):
        """优化黑名单规则"""
        file_path = self.base_dir / 'dist/blacklist.txt'
        if not file_path.exists():
            print("黑名单文件不存在")
            return
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 分离头部注释和规则
        header = []
        rules = []
        
        for line in lines:
            line = line.rstrip('\n')
            if line.startswith('!'):
                header.append(line)
            elif line.strip():
                rules.append(line)
        
        # 规则优化
        optimized_rules = []
        rule_set = set()
        
        for rule in rules:
            # 去除多余空格
            rule = rule.strip()
            
            # 跳过重复规则
            if rule in rule_set:
                continue
            
            # 简单的规则标准化
            # 例如: 确保通配符规则以 ^ 结尾
            if rule.endswith('*'):
                rule = rule.rstrip('*') + '^'
            
            rule_set.add(rule)
            optimized_rules.append(rule)
        
        # 排序规则（可选，但可以提升性能）
        optimized_rules.sort(key=lambda x: (
            x.startswith('||'),  # 域名规则优先
            x.startswith('|'),   # 协议规则
            len(x),              # 短规则优先
            x                    # 字母顺序
        ))
        
        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header))
            if header:
                f.write('\n\n')
            f.write('\n'.join(optimized_rules))
        
        print(f"黑名单优化完成: 原始 {len(rules)} 条, 优化后 {len(optimized_rules)} 条")
        
    def compress_whitelist(self):
        """压缩白名单规则"""
        file_path = self.base_dir / 'dist/whitelist.txt'
        if not file_path.exists():
            print("白名单文件不存在")
            return
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 类似黑名单的处理
        header = []
        rules = []
        
        for line in lines:
            line = line.rstrip('\n')
            if line.startswith('!'):
                header.append(line)
            elif line.strip():
                rules.append(line)
        
        # 去重
        unique_rules = list(set(rules))
        unique_rules.sort()
        
        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header))
            if header:
                f.write('\n\n')
            f.write('\n'.join(unique_rules))
        
        print(f"白名单压缩完成: 原始 {len(rules)} 条, 压缩后 {len(unique_rules)} 条")
        
    def run(self):
        """执行格式化"""
        print("开始规则格式化与优化...")
        print("=" * 60)
        
        self.optimize_blacklist()
        print("-" * 60)
        self.compress_whitelist()
        print("=" * 60)
        print("规则格式化完成")


if __name__ == "__main__":
    formatter = RuleFormatter()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--optimize':
        formatter.run()
    else:
        print("使用方法: python format_rules.py --optimize")
