#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本
"""

import re
import sys
from pathlib import Path


def validate_rule(rule):
    """验证单条规则语法"""
    if not rule or rule.startswith('!'):
        return False
    
    # AdBlock规则模式
    patterns = [
        r'^@@?\|',                      # 域名规则
        r'^\|\|',                       # 双竖线规则
        r'^\|',                         # 单竖线规则
        r'^##',                         # 元素隐藏规则
        r'^/.*/$',                      # 正则表达式规则
        r'^0\.0\.0\.0\s+',              # hosts格式
        r'^127\.0\.0\.1\s+',            # hosts格式
        r'^::1\s+',                     # IPv6 hosts格式
        r'^#',                          # 注释（虽然已经过滤）
        r'^\$[^,]+',                    # 选项修饰符
    ]
    
    return any(re.match(p, rule) for p in patterns)


def validate_file(file_path):
    """验证整个文件"""
    path = Path(file_path)
    if not path.exists():
        print(f"❌ 文件不存在: {file_path}")
        return 0, 0
    
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    total = 0
    valid = 0
    invalid_rules = []
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if line and not line.startswith('!'):
            total += 1
            if validate_rule(line):
                valid += 1
            else:
                invalid_rules.append((i, line))
    
    print(f"📄 文件: {path.name}")
    print(f"📊 总规则数: {total}")
    print(f"✅ 有效规则: {valid}")
    print(f"❌ 无效规则: {total - valid}")
    
    # 显示部分无效规则（最多10条）
    if invalid_rules:
        print("\n🔍 无效规则示例:")
        for i, (line_num, rule) in enumerate(invalid_rules[:10]):
            print(f"  第{line_num}行: {rule[:50]}...")
    
    return total, valid


if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    
    print("🔍 验证规则文件...")
    print("=" * 60)
    
    # 验证黑名单
    black_total, black_valid = validate_file(base_dir / 'dist/blacklist.txt')
    print("-" * 60)
    
    # 验证白名单
    white_total, white_valid = validate_file(base_dir / 'dist/whitelist.txt')
    
    print("=" * 60)
    print(f"📊 总体统计:")
    print(f"  黑名单: {black_valid}/{black_total} 有效 ({black_total-black_valid} 无效)")
    print(f"  白名单: {white_valid}/{white_total} 有效 ({white_total-white_valid} 无效)")
    print(f"  总计: {black_valid+white_valid}/{black_total+white_total} 有效")
    print("=" * 60)
    
    # 返回退出码
    if black_valid == 0 and white_valid == 0:
        print("❌ 没有有效规则，验证失败")
        sys.exit(1)
    else:
        print("✅ 验证完成")
        sys.exit(0)
