#!/usr/bin/env python3
"""
规则格式化脚本
"""

from pathlib import Path

def format_rules():
    base_dir = Path(__file__).parent.parent
    
    for filename in ['blacklist.txt', 'whitelist.txt']:
        filepath = base_dir / 'dist' / filename
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            header = []
            rules = []
            
            for line in lines:
                line = line.rstrip('\n')
                if line.startswith('!') or not line.strip():
                    header.append(line)
                else:
                    rules.append(line)
            
            # 去重排序
            rules = sorted(set(rules))
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(header))
                if header and rules:
                    f.write('\n\n')
                f.write('\n'.join(rules))
            
            print(f"格式化完成: {filename} - {len(rules)} 条规则")

if __name__ == "__main__":
    format_rules()
