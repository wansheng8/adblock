#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本
"""

import re
from pathlib import Path
from datetime import datetime


def format_file(file_path):
    """格式化规则文件"""
    path = Path(file_path)
    if not path.exists():
        print(f"文件不存在: {file_path}")
        return
    
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 分离头部和规则
    lines = content.split('\n')
    header = []
    rules = []
    
    for line in lines:
        if line.startswith('!'):
            header.append(line)
        elif line.strip():
            rules.append(line.strip())
    
    # 分组规则
    groups = {
        'whitelist': [],
        'domain': [],
        'url': [],
        'element': [],
        'hosts': [],
        'other': []
    }
    
    for rule in rules:
        if rule.startswith('@@'):
            groups['whitelist'].append(rule)
        elif rule.startswith('||'):
            groups['domain'].append(rule)
        elif rule.startswith('|'):
            groups['url'].append(rule)
        elif rule.startswith('##'):
            groups['element'].append(rule)
        elif rule.startswith(('0.0.0.0', '127.0.0.1')):
            groups['hosts'].append(rule)
        else:
            groups['other'].append(rule)
    
    # 排序
    for key in groups:
        groups[key].sort()
    
    # 重新组装文件
    formatted = []
    formatted.extend(header)
    
    # 添加格式化信息
    formatted.append(f'! 格式化时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    formatted.append('!')
    
    # 添加分组
    group_names = {
        'whitelist': '白名单规则',
        'domain': '域名规则',
        'url': 'URL规则',
        'element': '元素隐藏规则',
        'hosts': 'Hosts规则',
        'other': '其他规则'
    }
    
    for group_key, group_rules in groups.items():
        if group_rules:
            formatted.append(f'! {"="*60}')
            formatted.append(f'! {group_names[group_key]} ({len(group_rules)}条)')
            formatted.append(f'! {"="*60}')
            formatted.append('')
            formatted.extend(group_rules)
            formatted.append('')
    
    # 写入文件
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(formatted))
    
    print(f"格式化完成: {path.name}")
    print(f"总规则数: {len(rules)}")


if __name__ == "__main__":
    import sys
    
    base_dir = Path(__file__).parent.parent
    
    print("开始格式化规则文件...")
    print("=" * 60)
    
    format_file(base_dir / 'dist/blacklist.txt')
    print("-" * 60)
    format_file(base_dir / 'dist/whitelist.txt')
    
    print("=" * 60)
    print("格式化完成!")
