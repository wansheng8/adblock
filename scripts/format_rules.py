#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本
美化和整理规则文件
"""

import re
from pathlib import Path
from datetime import datetime


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
    
    def format_file(self, file_path: Path):
        """格式化单个规则文件"""
        print(f"格式化: {file_path.name}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 分离头部和规则
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!'):
                header_lines.append(line)
            elif line.strip():
                rule_lines.append(line)
        
        # 按类型分组规则
        groups = {
            'whitelist': [],
            'domain': [],
            'url': [],
            'element': [],
            'regex': [],
            'hosts': [],
            'other': []
        }
        
        for rule in rule_lines:
            rule = rule.strip()
            
            if rule.startswith('@@'):
                groups['whitelist'].append(rule)
            elif rule.startswith('||'):
                groups['domain'].append(rule)
            elif rule.startswith('|'):
                groups['url'].append(rule)
            elif rule.startswith('##'):
                groups['element'].append(rule)
            elif rule.startswith('/') and rule.endswith('/'):
                groups['regex'].append(rule)
            elif rule.startswith(('0.0.0.0', '127.0.0.1', '::1', '::')):
                groups['hosts'].append(rule)
            else:
                groups['other'].append(rule)
        
        # 排序每组内的规则
        for key in groups:
            groups[key].sort()
        
        # 生成格式化内容
        formatted_lines = []
        
        # 保留原始头部
        formatted_lines.extend(header_lines)
        
        # 添加格式化信息
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_lines.append(f'! 格式化时间: {now}')
        formatted_lines.append('!')
        
        # 添加分组规则
        group_names = {
            'whitelist': '白名单规则',
            'domain': '域名规则',
            'url': 'URL规则',
            'element': '元素隐藏规则',
            'regex': '正则表达式规则',
            'hosts': 'Hosts规则',
            'other': '其他规则'
        }
        
        for group_key, group_rules in groups.items():
            if group_rules:
                # 添加分组标题
                group_name = group_names.get(group_key, group_key)
                separator = '=' * 60
                
                formatted_lines.append(f'! {separator}')
                formatted_lines.append(f'! {group_name} ({len(group_rules)}条)')
                formatted_lines.append(f'! {separator}')
                formatted_lines.append('')
                
                # 添加规则
                formatted_lines.extend(group_rules)
                formatted_lines.append('')
        
        # 写入文件
        with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"  完成: {len(rule_lines)} 条规则已格式化")
        
        return len(rule_lines)
    
    def format_all(self):
        """格式化所有规则文件"""
        print("开始格式化规则文件...")
        
        dist_dir = self.base_dir / 'dist'
        files_to_format = ['blacklist.txt', 'whitelist.txt']
        
        results = {}
        
        for filename in files_to_format:
            file_path = dist_dir / filename
            if file_path.exists():
                count = self.format_file(file_path)
                results[filename] = count
            else:
                print(f"  跳过: {filename} (文件不存在)")
        
        # 生成报告
        print("\n格式化完成:")
        for filename, count in results.items():
            print(f"  {filename}: {count} 条规则")
        
        return results


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.format_all()
