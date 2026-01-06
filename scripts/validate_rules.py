#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证脚本
验证生成的黑名单和白名单规则
"""

import json
import re
from pathlib import Path

class RuleVerifier:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
    def verify_blacklist(self):
        """验证黑名单规则"""
        print("验证黑名单规则...")
        
        blacklist_file = self.base_dir / 'dist/blacklist.txt'
        if not blacklist_file.exists():
            print("错误: 黑名单文件不存在!")
            return False
        
        with open(blacklist_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 统计
        total_lines = len(lines)
        comment_lines = len([l for l in lines if l.startswith('!') or not l.strip()])
        rule_lines = total_lines - comment_lines
        
        print(f"  总行数: {total_lines}")
        print(f"  注释行: {comment_lines}")
        print(f"  规则行: {rule_lines}")
        
        # 验证规则格式
        valid_rules = 0
        invalid_rules = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('!'):
                # 基本验证
                if self.is_valid_rule(line):
                    valid_rules += 1
                else:
                    invalid_rules.append(line)
        
        print(f"  有效规则: {valid_rules}")
        print(f"  无效规则: {len(invalid_rules)}")
        
        if invalid_rules:
            print("  无效规则示例:")
            for rule in invalid_rules[:5]:
                print(f"    - {rule}")
        
        return valid_rules > 0
    
    def verify_whitelist(self):
        """验证白名单规则"""
        print("\n验证白名单规则...")
        
        whitelist_file = self.base_dir / 'dist/whitelist.txt'
        if not whitelist_file.exists():
            print("错误: 白名单文件不存在!")
            return False
        
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 统计
        total_lines = len(lines)
        comment_lines = len([l for l in lines if l.startswith('!') or not l.strip()])
        rule_lines = total_lines - comment_lines
        
        print(f"  总行数: {total_lines}")
        print(f"  注释行: {comment_lines}")
        print(f"  规则行: {rule_lines}")
        
        # 统计白名单规则类型
        domain_rules = 0
        element_rules = 0
        other_rules = 0
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('!'):
                if line.startswith('@@||'):
                    domain_rules += 1
                elif line.startswith('#@?#'):
                    element_rules += 1
                else:
                    other_rules += 1
        
        print(f"  域名白名单: {domain_rules}")
        print(f"  元素白名单: {element_rules}")
        print(f"  其他白名单: {other_rules}")
        
        return rule_lines > 0
    
    def is_valid_rule(self, rule: str) -> bool:
        """检查规则是否有效"""
        # 基础验证
        patterns = [
            r'^@@?\|',
            r'^\/.*\/$',
            r'^\|\|',
            r'^\|',
            r'^\$',
            r'^#@?#',
            r'^##',
            r'^%',
        ]
        
        for pattern in patterns:
            if re.match(pattern, rule):
                return True
        
        return False
    
    def check_common_sites(self):
        """检查常见网站是否在白名单中"""
        print("\n检查常见网站白名单覆盖...")
        
        common_sites = [
            'baidu.com',
            'google.com',
            'taobao.com',
            'jd.com',
            'bilibili.com',
            'zhihu.com',
            'weibo.com',
            'github.com',
            'microsoft.com',
            'apple.com',
        ]
        
        whitelist_file = self.base_dir / 'dist/whitelist.txt'
        if not whitelist_file.exists():
            return
        
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        for site in common_sites:
            pattern = f'@@.*{re.escape(site)}'
            if re.search(pattern, content, re.IGNORECASE):
                print(f"  ✅ {site}: 已保护")
            else:
                print(f"  ⚠️  {site}: 未找到白名单规则")
    
    def run(self):
        """运行验证"""
        print("开始验证规则...")
        
        # 验证黑名单
        blacklist_ok = self.verify_blacklist()
        
        # 验证白名单
        whitelist_ok = self.verify_whitelist()
        
        # 检查常见网站
        self.check_common_sites()
        
        # 检查元数据
        metadata_file = self.base_dir / 'dist/metadata.json'
        if metadata_file.exists():
            print("\n检查元数据...")
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            print(f"  最后更新: {metadata.get('last_updated', 'N/A')}")
            print(f"  总规则数: {metadata.get('total_rules', 0)}")
            print(f"  黑名单规则: {metadata.get('blacklist_rules', 0)}")
            print(f"  白名单规则: {metadata.get('whitelist_rules', 0)}")
        
        print("\n验证完成!")
        if blacklist_ok and whitelist_ok:
            print("✅ 所有检查通过")
            return True
        else:
            print("⚠️  存在一些问题，请检查")
            return False

def main():
    verifier = RuleVerifier()
    success = verifier.run()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    import sys
    main()
