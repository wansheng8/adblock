#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本
"""

import re
from pathlib import Path


def validate_rule(rule):
    """验证单条规则语法"""
    if not rule or rule.startswith('!'):
        return False
    
    patterns = [
        r'^@@?\|',
        r'^\|\|',
        r'^\|',
        r'^##',
        r'^/.*/$',
        r'^0\.0\.0\.0\s+',
        r'^127\.0\.0\.1\s+',
    ]
    
    return any(re.match(p, rule) for p in patterns)


def validate_file(file_path):
    """验证整个文件"""
    path = Path(file_path)
    if not path.exists():
        print(f"文件不存在: {file_path}")
        return
    
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    total = 0
    valid = 0
    
    for line in lines:
        line = line.strip()
        if line and not line.startswith('!'):
            total += 1
            if validate_rule(line):
                valid += 1
    
    print(f"文件: {path.name}")
    print(f"总规则数: {total}")
    print(f"有效规则: {valid}")
    print(f"无效规则: {total - valid}")
    
    return total, valid


if __name__ == "__main__":
    import sys
    
    base_dir = Path(__file__).parent.parent
    
    print("验证规则文件...")
    print("=" * 60)
    
    # 验证黑名单
    validate_file(base_dir / 'dist/blacklist.txt')
    print("-" * 60)
    
    # 验证白名单
    validate_file(base_dir / 'dist/whitelist.txt')
    print("=" * 60)
