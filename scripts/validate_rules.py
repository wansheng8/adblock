#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本
验证规则文件的语法和格式
"""

import re
import json
from pathlib import Path
from typing import List, Dict


class RuleValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # 规则模式
        self.patterns = [
            r'^@@?\|',  # 域名规则
            r'^\/.*\/$',  # 正则表达式
            r'^\|\|',  # 域名开始
            r'^\|',  # URL开始
            r'^\$',  # 规则选项
            r'^@@',  # 白名单
            r'^##',  # 元素隐藏
            r'^#@?#',  # 元素隐藏白名单
            r'^0\.0\.0\.0\s+',  # hosts格式
            r'^127\.0\.0\.1\s+',  # hosts格式
            r'^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$',  # 简单域名
        ]
    
    def validate_file(self, file_path: Path) -> Dict:
        """验证规则文件"""
        print(f"验证文件: {file_path.name}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        stats = {
            'total_lines': len(lines),
            'comment_lines': 0,
            'rule_lines': 0,
            'valid_rules': 0,
            'invalid_rules': 0,
            'invalid_examples': []
        }
        
        for line in lines:
            line = line.strip()
            
            if not line:
                continue
            elif line.startswith('!'):
                stats['comment_lines'] += 1
            else:
                stats['rule_lines'] += 1
                if self.validate_rule(line):
                    stats['valid_rules'] += 1
                else:
                    stats['invalid_rules'] += 1
                    if len(stats['invalid_examples']) < 5:
                        stats['invalid_examples'].append(line)
        
        return stats
    
    def validate_rule(self, rule: str) -> bool:
        """验证单条规则"""
        for pattern in self.patterns:
            if re.match(pattern, rule):
                return True
        return False
    
    def validate_all(self):
        """验证所有规则文件"""
        print("验证规则文件...")
        
        dist_dir = self.base_dir / 'dist'
        files_to_validate = ['blacklist.txt', 'whitelist.txt']
        
        results = {}
        
        for filename in files_to_validate:
            file_path = dist_dir / filename
            if file_path.exists():
                stats = self.validate_file(file_path)
                results[filename] = stats
                
                print(f"\n{filename}:")
                print(f"  总行数: {stats['total_lines']}")
                print(f"  注释行: {stats['comment_lines']}")
                print(f"  规则行: {stats['rule_lines']}")
                print(f"  有效规则: {stats['valid_rules']}")
                print(f"  无效规则: {stats['invalid_rules']}")
                
                if stats['invalid_rules'] > 0:
                    print(f"  无效规则示例:")
                    for rule in stats['invalid_examples']:
                        print(f"    - {rule}")
            else:
                print(f"\n{filename}: 文件不存在")
        
        # 保存验证结果
        report_file = self.base_dir / 'dist/validation_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n验证报告已保存到: {report_file}")
        
        return results


if __name__ == "__main__":
    validator = RuleValidator()
    validator.validate_all()
