#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本
"""

from pathlib import Path


def format_rules():
    """格式化规则文件"""
    base_dir = Path(__file__).parent.parent
    
    # 格式化黑名单文件
    blacklist_file = base_dir / 'dist/blacklist.txt'
    if blacklist_file.exists():
        with open(blacklist_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 保留头部注释，对规则行排序去重
        header = []
        rules = []
        
        for line in lines:
            if line.startswith('!') or line.strip() == '':
                header.append(line.rstrip('\n'))
            else:
                rules.append(line.strip())
        
        # 去重并排序
        rules = sorted(set(rules))
        
        # 写回文件
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header))
            if header:
                f.write('\n\n')
            f.write('\n'.join(rules))
        
        print(f"黑名单格式化完成: {len(rules)} 条规则")
    
    # 格式化白名单文件
    whitelist_file = base_dir / 'dist/whitelist.txt'
    if whitelist_file.exists():
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        header = []
        rules = []
        
        for line in lines:
            if line.startswith('!') or line.strip() == '':
                header.append(line.rstrip('\n'))
            else:
                rules.append(line.strip())
        
        # 去重并排序
        rules = sorted(set(rules))
        
        # 写回文件
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header))
            if header:
                f.write('\n\n')
            f.write('\n'.join(rules))
        
        print(f"白名单格式化完成: {len(rules)} 条规则")


if __name__ == "__main__":
    format_rules()
    print("规则格式化完成")
