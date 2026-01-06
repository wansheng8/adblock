#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则合并脚本
用于合并多个规则文件
"""

import re
from pathlib import Path
from typing import List


class RuleMerger:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
    
    def merge_files(self, file_paths: List[Path]) -> List[str]:
        """合并多个规则文件"""
        all_rules = []
        
        for file_path in file_paths:
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 提取规则（跳过注释）
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('!'):
                        all_rules.append(line)
        
        # 去重
        unique_rules = list(set(all_rules))
        
        # 排序
        unique_rules.sort()
        
        return unique_rules
    
    def merge_custom_rules(self):
        """合并自定义规则"""
        custom_dir = self.base_dir / 'rules/custom'
        if not custom_dir.exists():
            return []
        
        custom_files = list(custom_dir.glob('*.txt'))
        if not custom_files:
            return []
        
        return self.merge_files(custom_files)
    
    def run(self):
        """运行合并"""
        print("合并规则文件...")
        
        # 合并自定义规则
        custom_rules = self.merge_custom_rules()
        if custom_rules:
            print(f"找到 {len(custom_rules)} 条自定义规则")
            
            # 保存到文件
            output_file = self.base_dir / 'rules/processed/custom_merged.txt'
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(custom_rules))
            
            print(f"保存到: {output_file}")
        
        return custom_rules


if __name__ == "__main__":
    merger = RuleMerger()
    merger.run()
