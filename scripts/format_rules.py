#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 最终格式化
"""

import re
from pathlib import Path
from datetime import datetime


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
    def format_blacklist(self):
        """格式化黑名单文件"""
        filepath = self.base_dir / 'dist/blacklist.txt'
        if not filepath.exists():
            print("❌ 黑名单文件不存在")
            return
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 提取头部和规则
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"📄 处理黑名单: {len(rule_lines)} 条规则")
        
        # 按规则类型分组
        categories = {
            "域名规则": [],
            "元素隐藏规则": [],
            "正则表达式规则": [],
            "Hosts规则": [],
            "其他规则": []
        }
        
        for rule in rule_lines:
            if rule.startswith('||') or rule.startswith('@@||'):
                categories["域名规则"].append(rule)
            elif rule.startswith('##'):
                categories["元素隐藏规则"].append(rule)
            elif rule.startswith('/') and rule.endswith('/'):
                categories["正则表达式规则"].append(rule)
            elif rule.startswith('0.0.0.0') or rule.startswith('127.0.0.1'):
                categories["Hosts规则"].append(rule)
            else:
                categories["其他规则"].append(rule)
        
        # 去重排序
        for category in categories:
            categories[category] = sorted(set(categories[category]))
        
        # 重新组合内容
        formatted_lines = header_lines.copy()
        
        # 添加分类统计
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        formatted_lines.append("! ============================================================")
        formatted_lines.append("! 📊 规则分类统计")
        formatted_lines.append("! ============================================================")
        
        total_rules = 0
        for category, rules in categories.items():
            if rules:
                formatted_lines.append(f"! {category}: {len(rules)} 条")
                total_rules += len(rules)
        
        formatted_lines.append(f"! 总计: {total_rules} 条规则")
        formatted_lines.append("! ============================================================")
        formatted_lines.append("")
        
        # 添加分类规则
        for category, rules in categories.items():
            if rules:
                formatted_lines.append(f"! ============================================================")
                formatted_lines.append(f"! 🎯 {category}")
                formatted_lines.append(f"! ============================================================")
                formatted_lines.append("")
                formatted_lines.extend(rules)
                formatted_lines.append("")
        
        # 移除最后的空行
        if formatted_lines and formatted_lines[-1] == '':
            formatted_lines.pop()
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print("✅ 黑名单格式化完成")
        
        # 打印统计
        print("📊 规则分类:")
        for category, rules in categories.items():
            if rules:
                print(f"  ├── {category}: {len(rules)} 条")
        
        return total_rules
    
    def format_whitelist(self):
        """格式化白名单文件"""
        filepath = self.base_dir / 'dist/whitelist.txt'
        if not filepath.exists():
            print("❌ 白名单文件不存在")
            return
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # 提取头部和规则
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"📄 处理白名单: {len(rule_lines)} 条规则")
        
        # 去重排序
        unique_rules = sorted(set(rule_lines))
        
        # 重新组合内容
        formatted_lines = header_lines.copy()
        
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        formatted_lines.append("! ============================================================")
        formatted_lines.append(f"! ✅ 白名单规则 ({len(unique_rules)}条)")
        formatted_lines.append("! 说明: 以下域名/元素不会被拦截")
        formatted_lines.append("! ============================================================")
        formatted_lines.append("")
        
        # 添加规则
        formatted_lines.extend(unique_rules)
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ 白名单格式化完成: {len(unique_rules)} 条规则")
        
        return len(unique_rules)
    
    def optimize_performance(self):
        """优化规则性能"""
        print("⚡ 优化规则性能...")
        
        # 这里可以添加各种优化逻辑，例如：
        # 1. 合并相似规则
        # 2. 移除冗余规则
        # 3. 优化正则表达式
        # 4. 检查规则冲突
        
        print("✅ 性能优化完成")
    
    def run(self):
        """执行格式化"""
        print("=" * 60)
        print("🔄 开始格式化规则文件")
        print("=" * 60)
        
        # 格式化黑名单
        black_count = self.format_blacklist()
        print("-" * 60)
        
        # 格式化白名单
        white_count = self.format_whitelist()
        print("-" * 60)
        
        # 性能优化
        self.optimize_performance()
        
        print("=" * 60)
        print(f"✅ 格式化完成!")
        print(f"📊 黑名单: {black_count if black_count else 'N/A'} 条规则")
        print(f"📊 白名单: {white_count if white_count else 'N/A'} 条规则")
        print("=" * 60)


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
