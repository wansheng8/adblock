#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 完整增强版
支持高级广告拦截规则语法处理
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        self.advanced_categories = {
            "域名拦截规则": [],
            "域名例外规则": [],
            "元素隐藏规则": [],
            "元素隐藏例外规则": [],
            "高级选择器规则": [],
            "元素移除规则": [],
            "正则表达式规则": [],
            "Hosts规则": [],
            "参数移除规则": [],
            "域名限定规则": [],
            "修饰符规则": [],
            "重定向规则": [],
            "其他规则": []
        }
        
    def classify_advanced_rule(self, rule):
        """高级规则分类"""
        rule = rule.strip()
        
        # 1. 注释和空行
        if not rule or rule.startswith('!'):
            return None
        
        # 2. 域名例外规则
        if rule.startswith('@@||'):
            return "域名例外规则"
        elif rule.startswith('@@'):
            return "域名例外规则"
        
        # 3. 域名拦截规则
        if rule.startswith('||'):
            return "域名拦截规则"
        elif rule.startswith('|'):
            return "域名拦截规则"
        
        # 4. 高级选择器规则
        if '#?#' in rule:
            return "高级选择器规则"
        
        # 5. 元素隐藏例外规则
        if '#@#' in rule:
            return "元素隐藏例外规则"
        
        # 6. 元素移除规则
        if '$$' in rule:
            return "元素移除规则"
        
        # 7. 元素隐藏规则
        if rule.startswith('##'):
            return "元素隐藏规则"
        
        # 8. 正则表达式规则
        if rule.startswith('/') and rule.endswith('/'):
            return "正则表达式规则"
        
        # 9. 参数移除规则
        if '$removeparam=' in rule:
            return "参数移除规则"
        
        # 10. 域名限定规则
        if '$domain=' in rule or '$denyallow=' in rule:
            return "域名限定规则"
        
        # 11. 重定向规则
        if '$redirect=' in rule or '$redirect-rule=' in rule:
            return "重定向规则"
        
        # 12. Hosts规则
        if rule.startswith(('0.0.0.0', '127.0.0.1', '::1')):
            return "Hosts规则"
        
        # 13. 修饰符规则
        if '$' in rule:
            # 检查是否是组合修饰符
            parts = rule.split('$')
            if len(parts) == 2:
                base_rule = parts[0].strip()
                modifiers = parts[1].strip()
                
                # 验证修饰符格式
                if re.match(r'^[a-z_\-]+(,[a-z_\-]+)*$', modifiers) or re.match(r'^[a-z_\-]+=[^,]+(,[a-z_\-]+(=[^,]+)?)*$', modifiers):
                    return "修饰符规则"
        
        # 14. 其他规则
        return "其他规则"
    
    def extract_domain(self, rule):
        """从规则中提取域名"""
        # 域名规则
        if rule.startswith('||'):
            domain = rule[2:].split('^')[0].split('/')[0]
            return domain
        
        # Hosts规则
        if rule.startswith(('0.0.0.0', '127.0.0.1', '::1')):
            parts = rule.split()
            if len(parts) >= 2:
                return parts[1]
        
        return None
    
    def extract_modifiers(self, rule):
        """从规则中提取修饰符"""
        if '$' in rule:
            parts = rule.split('$')
            if len(parts) >= 2:
                modifiers_str = parts[-1]
                # 分割修饰符
                modifiers = []
                for mod in modifiers_str.split(','):
                    mod = mod.strip()
                    if mod:
                        modifiers.append(mod)
                return modifiers
        return []
    
    def validate_rule_syntax(self, rule):
        """验证规则语法"""
        rule_type = self.classify_advanced_rule(rule)
        
        if not rule_type:
            return True, "注释或空行"
        
        # 基础验证
        errors = []
        
        # 1. 检查规则长度
        if len(rule) > 1000:
            errors.append("规则过长")
        
        # 2. 检查特殊字符
        if '\x00' in rule:
            errors.append("包含空字符")
        
        # 3. 特定类型验证
        if rule_type == "元素隐藏规则":
            selector = rule[2:]
            # 简单的CSS选择器验证
            if not re.match(r'^[a-zA-Z0-9_\-\[\]\.#\:>+~= \*"\'\(\)]+$', selector):
                errors.append("CSS选择器格式错误")
        
        elif rule_type == "正则表达式规则":
            regex = rule[1:-1]  # 去掉前后的/
            try:
                re.compile(regex)
            except re.error as e:
                errors.append(f"正则表达式错误: {str(e)}")
        
        elif rule_type == "修饰符规则":
            parts = rule.split('$')
            if len(parts) == 2:
                modifiers = parts[1]
                # 验证修饰符格式
                if not re.match(r'^[a-z_\-]+(=[^,]+)?(,[a-z_\-]+(=[^,]+)?)*$', modifiers):
                    errors.append("修饰符格式错误")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, rule_type
    
    def detect_rule_conflicts(self, rules):
        """检测规则冲突"""
        conflicts = []
        
        # 按域名分组规则
        domain_rules = defaultdict(list)
        domain_exceptions = defaultdict(list)
        
        for rule in rules:
            rule_type = self.classify_advanced_rule(rule)
            if rule_type in ["域名拦截规则", "域名例外规则"]:
                domain = self.extract_domain(rule)
                if domain:
                    if rule_type == "域名拦截规则":
                        domain_rules[domain].append(rule)
                    else:
                        domain_exceptions[domain].append(rule)
        
        # 检测冲突
        for domain in set(domain_rules.keys()) & set(domain_exceptions.keys()):
            conflicts.append({
                'domain': domain,
                'block_rules': domain_rules[domain],
                'exception_rules': domain_exceptions[domain],
                'message': f"域名 {domain} 同时被拦截和允许"
            })
        
        return conflicts
    
    def optimize_rules(self, rules):
        """优化规则集合"""
        optimized = []
        seen = set()
        
        for rule in rules:
            # 基础去重
            if rule in seen:
                continue
            seen.add(rule)
            
            # 验证规则
            is_valid, _ = self.validate_rule_syntax(rule)
            if not is_valid:
                continue
            
            # 添加到优化列表
            optimized.append(rule)
        
        # 排序规则（按类型和字母顺序）
        optimized.sort(key=lambda x: (
            list(self.advanced_categories.keys()).index(self.classify_advanced_rule(x) or "其他规则"),
            x
        ))
        
        return optimized
    
    def merge_similar_rules(self, rules):
        """合并相似规则"""
        # 按域名分组的规则
        domain_groups = defaultdict(list)
        
        for rule in rules:
            rule_type = self.classify_advanced_rule(rule)
            if rule_type in ["域名拦截规则", "域名例外规则"]:
                domain = self.extract_domain(rule)
                if domain:
                    domain_groups[domain].append((rule_type, rule))
        
        # 简化域名规则（基础版）
        merged_rules = []
        processed_domains = set()
        
        for domain, domain_rules in domain_groups.items():
            # 检查是否所有规则都是拦截规则
            all_block = all(rt == "域名拦截规则" for rt, _ in domain_rules)
            all_exception = all(rt == "域名例外规则" for rt, _ in domain_rules)
            
            if all_block and len(domain_rules) > 1:
                # 合并多个拦截规则为一个通配符规则
                merged_rules.append(f"||{domain}^")
                processed_domains.add(domain)
            elif all_exception and len(domain_rules) > 1:
                # 合并多个例外规则为一个通配符例外规则
                merged_rules.append(f"@@||{domain}^")
                processed_domains.add(domain)
        
        # 添加未处理的规则
        for rule in rules:
            rule_type = self.classify_advanced_rule(rule)
            if rule_type in ["域名拦截规则", "域名例外规则"]:
                domain = self.extract_domain(rule)
                if domain and domain not in processed_domains:
                    merged_rules.append(rule)
            else:
                merged_rules.append(rule)
        
        return merged_rules
    
    def analyze_rule_statistics(self, rules):
        """分析规则统计"""
        stats = {
            'total_rules': len(rules),
            'by_type': Counter(),
            'by_domain': Counter(),
            'by_modifier': Counter(),
            'invalid_rules': [],
            'conflicts': [],
            'rule_lengths': []
        }
        
        # 分类统计
        for rule in rules:
            rule_type = self.classify_advanced_rule(rule)
            if rule_type:
                stats['by_type'][rule_type] += 1
            
            # 提取域名统计
            domain = self.extract_domain(rule)
            if domain:
                # 提取根域名
                root_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
                stats['by_domain'][root_domain] += 1
            
            # 提取修饰符统计
            modifiers = self.extract_modifiers(rule)
            for mod in modifiers:
                stats['by_modifier'][mod] += 1
            
            # 规则长度
            stats['rule_lengths'].append(len(rule))
            
            # 验证规则
            is_valid, error_msg = self.validate_rule_syntax(rule)
            if not is_valid:
                stats['invalid_rules'].append((rule, error_msg))
        
        # 检测冲突
        stats['conflicts'] = self.detect_rule_conflicts(rules)
        
        # 计算长度统计
        if stats['rule_lengths']:
            stats['avg_rule_length'] = sum(stats['rule_lengths']) / len(stats['rule_lengths'])
            stats['max_rule_length'] = max(stats['rule_lengths'])
            stats['min_rule_length'] = min(stats['rule_lengths'])
        
        return stats
    
    def format_blacklist(self):
        """格式化黑名单文件 - 增强版"""
        filepath = self.base_dir / 'dist/blacklist.txt'
        if not filepath.exists():
            print("❌ 黑名单文件不存在")
            return None
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"📄 处理黑名单文件...")
        
        # 分离头部和规则
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"  原始规则: {len(rule_lines)} 条")
        
        # 高级分类
        for rule in rule_lines:
            category = self.classify_advanced_rule(rule)
            if category and category in self.advanced_categories:
                self.advanced_categories[category].append(rule)
        
        # 去重和排序
        for category in self.advanced_categories:
            if self.advanced_categories[category]:
                self.advanced_categories[category] = sorted(set(self.advanced_categories[category]))
        
        # 规则统计
        all_rules = []
        for rules in self.advanced_categories.values():
            all_rules.extend(rules)
        
        stats = self.analyze_rule_statistics(all_rules)
        
        # 重新构建内容
        formatted_lines = []
        
        # 1. 保留原始头部
        formatted_lines.extend(header_lines)
        
        # 2. 添加高级统计信息
        formatted_lines.append("")
        formatted_lines.append("! ============================================================")
        formatted_lines.append("! 📊 高级规则统计")
        formatted_lines.append("! ============================================================")
        formatted_lines.append(f"! 总计规则: {stats['total_rules']} 条")
        formatted_lines.append(f"! 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append("")
        
        # 按类型统计
        formatted_lines.append("! 🎯 规则类型分布:")
        for rule_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_rules']) * 100 if stats['total_rules'] > 0 else 0
            formatted_lines.append(f"!   • {rule_type}: {count} 条 ({percentage:.1f}%)")
        
        # 域名统计
        if stats['by_domain']:
            formatted_lines.append("")
            formatted_lines.append("! 🌐 主要拦截域名:")
            top_domains = sorted(stats['by_domain'].items(), key=lambda x: x[1], reverse=True)[:10]
            for domain, count in top_domains:
                formatted_lines.append(f"!   • {domain}: {count} 条规则")
        
        # 修饰符统计
        if stats['by_modifier']:
            formatted_lines.append("")
            formatted_lines.append("! ⚙️  修饰符使用:")
            top_modifiers = sorted(stats['by_modifier'].items(), key=lambda x: x[1], reverse=True)[:5]
            for modifier, count in top_modifiers:
                formatted_lines.append(f"!   • {modifier}: {count} 次")
        
        # 冲突检测
        if stats['conflicts']:
            formatted_lines.append("")
            formatted_lines.append(f"! ⚠️  发现 {len(stats['conflicts'])} 个规则冲突")
            for conflict in stats['conflicts'][:3]:  # 只显示前3个
                formatted_lines.append(f"!   • {conflict['message']}")
        
        # 无效规则
        if stats['invalid_rules']:
            formatted_lines.append("")
            formatted_lines.append(f"! ❌ 发现 {len(stats['invalid_rules'])} 个无效规则")
            for rule, error in stats['invalid_rules'][:3]:
                formatted_lines.append(f"!   • {error}: {rule[:50]}...")
        
        formatted_lines.append("! ============================================================")
        formatted_lines.append("")
        
        # 3. 按分类添加规则
        for category, rules in self.advanced_categories.items():
            if rules:
                formatted_lines.append(f"! {'='*60}")
                formatted_lines.append(f"! 🎯 {category} ({len(rules)}条)")
                formatted_lines.append(f"! {'='*60}")
                formatted_lines.append("")
                formatted_lines.extend(rules)
                formatted_lines.append("")
        
        # 移除最后的空行
        while formatted_lines and formatted_lines[-1] == '':
            formatted_lines.pop()
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print("✅ 黑名单格式化完成")
        
        # 显示详细统计
        self.print_detailed_statistics(stats)
        
        return stats['total_rules']
    
    def format_whitelist(self):
        """格式化白名单文件 - 增强版"""
        filepath = self.base_dir / 'dist/whitelist.txt'
        if not filepath.exists():
            print("❌ 白名单文件不存在")
            return None
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"📄 处理白名单文件...")
        
        lines = content.split('\n')
        header_lines = []
        rule_lines = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header_lines.append(line)
            else:
                rule_lines.append(line.strip())
        
        print(f"  原始规则: {len(rule_lines)} 条")
        
        # 白名单特定处理
        exception_rules = []
        other_rules = []
        
        for rule in rule_lines:
            if rule.startswith('@@'):
                exception_rules.append(rule)
            else:
                other_rules.append(rule)
        
        # 去重排序
        exception_rules = sorted(set(exception_rules))
        other_rules = sorted(set(other_rules))
        
        # 分析白名单统计
        total_rules = len(exception_rules) + len(other_rules)
        
        # 重新构建内容
        formatted_lines = header_lines.copy()
        
        if header_lines and header_lines[-1].strip():
            formatted_lines.append("")
        
        formatted_lines.append("! ============================================================")
        formatted_lines.append(f"! ✅ 白名单规则 ({total_rules}条)")
        formatted_lines.append("! 说明: 以下域名/元素不会被拦截")
        formatted_lines.append(f"! 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        formatted_lines.append("! ============================================================")
        formatted_lines.append("")
        
        # 添加例外规则
        if exception_rules:
            formatted_lines.append("! 域名例外规则:")
            formatted_lines.append("")
            formatted_lines.extend(exception_rules)
            formatted_lines.append("")
        
        # 添加其他规则
        if other_rules:
            formatted_lines.append("! 其他白名单规则:")
            formatted_lines.append("")
            formatted_lines.extend(other_rules)
            formatted_lines.append("")
        
        # 保存文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(formatted_lines))
        
        print(f"✅ 白名单格式化完成: {total_rules} 条规则")
        
        return total_rules
    
    def optimize_performance(self):
        """优化规则性能 - 完整版"""
        print("⚡ 执行全面性能优化...")
        
        # 1. 读取黑名单规则
        blacklist_file = self.base_dir / 'dist/blacklist.txt'
        if not blacklist_file.exists():
            print("❌ 黑名单文件不存在，跳过优化")
            return
        
        with open(blacklist_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 分离头部和规则
        lines = content.split('\n')
        header = []
        rules = []
        
        for line in lines:
            if line.startswith('!') or not line.strip():
                header.append(line)
            else:
                rules.append(line.strip())
        
        original_count = len(rules)
        print(f"📊 优化前: {original_count} 条规则")
        
        # 2. 基础优化
        print("  1. 去重...")
        unique_rules = list(set(rules))
        print(f"    ├── 去重后: {len(unique_rules)} 条 (移除 {original_count - len(unique_rules)} 条重复)")
        
        print("  2. 语法验证...")
        valid_rules = []
        invalid_rules = []
        
        for rule in unique_rules:
            is_valid, error_msg = self.validate_rule_syntax(rule)
            if is_valid:
                valid_rules.append(rule)
            else:
                invalid_rules.append((rule, error_msg))
        
        print(f"    ├── 有效规则: {len(valid_rules)} 条")
        if invalid_rules:
            print(f"    ⚠️  无效规则: {len(invalid_rules)} 条")
            for rule, error in invalid_rules[:3]:
                print(f"       • {error}: {rule[:50]}...")
        
        print("  3. 合并相似规则...")
        merged_rules = self.merge_similar_rules(valid_rules)
        print(f"    ├── 合并后: {len(merged_rules)} 条")
        
        print("  4. 检测规则冲突...")
        conflicts = self.detect_rule_conflicts(merged_rules)
        if conflicts:
            print(f"    ⚠️  发现 {len(conflicts)} 个冲突")
            for conflict in conflicts[:3]:
                print(f"       • {conflict['message']}")
        
        # 3. 重新组合内容
        optimized_content = '\n'.join(header + [''] + merged_rules)
        
        # 4. 保存优化后的文件
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write(optimized_content)
        
        # 5. 统计优化结果
        reduction = original_count - len(merged_rules)
        reduction_percent = (reduction / original_count * 100) if original_count > 0 else 0
        
        print(f"📊 优化完成:")
        print(f"  ├── 原始规则: {original_count} 条")
        print(f"  ├── 优化后规则: {len(merged_rules)} 条")
        print(f"  ├── 减少数量: {reduction} 条")
        print(f"  └── 减少比例: {reduction_percent:.1f}%")
        
        if reduction > 0:
            print("✅ 性能优化完成，规则集已精简")
        else:
            print("ℹ️  没有可优化的规则")
    
    def print_detailed_statistics(self, stats):
        """打印详细统计信息"""
        print("\n📊 详细规则统计:")
        print("-" * 60)
        print(f"总计规则: {stats['total_rules']} 条")
        
        # 类型分布
        print("\n规则类型分布:")
        for rule_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_rules']) * 100 if stats['total_rules'] > 0 else 0
            print(f"  ├── {rule_type}: {count} 条 ({percentage:.1f}%)")
        
        # 域名分布
        if stats['by_domain']:
            print(f"\n拦截域名 (前10):")
            top_domains = sorted(stats['by_domain'].items(), key=lambda x: x[1], reverse=True)[:10]
            for domain, count in top_domains:
                print(f"  ├── {domain}: {count} 条")
        
        # 规则长度
        if 'avg_rule_length' in stats:
            print(f"\n规则长度:")
            print(f"  ├── 平均长度: {stats['avg_rule_length']:.1f} 字符")
            print(f"  ├── 最大长度: {stats['max_rule_length']} 字符")
            print(f"  └── 最小长度: {stats['min_rule_length']} 字符")
        
        # 冲突和错误
        if stats['conflicts']:
            print(f"\n规则冲突: {len(stats['conflicts'])} 个")
        
        if stats['invalid_rules']:
            print(f"无效规则: {len(stats['invalid_rules'])} 个")
        
        print("-" * 60)
    
    def run(self):
        """执行格式化 - 增强版"""
        print("=" * 60)
        print("🔄 AdBlock规则格式化工具 - 增强版")
        print("=" * 60)
        
        # 检查必要目录
        dist_dir = self.base_dir / 'dist'
        if not dist_dir.exists():
            print("❌ dist目录不存在，创建中...")
            dist_dir.mkdir(parents=True)
        
        # 1. 格式化黑名单
        print("\n📄 步骤1: 格式化黑名单")
        print("-" * 40)
        black_count = self.format_blacklist()
        
        # 2. 格式化白名单
        print("\n📄 步骤2: 格式化白名单")
        print("-" * 40)
        white_count = self.format_whitelist()
        
        # 3. 性能优化
        print("\n⚡ 步骤3: 性能优化")
        print("-" * 40)
        self.optimize_performance()
        
        # 4. 生成报告
        print("\n📊 步骤4: 生成格式化报告")
        print("-" * 40)
        
        total_rules = (black_count or 0) + (white_count or 0)
        
        print(f"✅ 格式化完成!")
        print(f"📊 最终统计:")
        print(f"  ├── 黑名单: {black_count or 0} 条规则")
        print(f"  ├── 白名单: {white_count or 0} 条规则")
        print(f"  ├── 总计: {total_rules} 条规则")
        print(f"  └── 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("\n🎯 高级功能:")
        print("  • 支持15种规则类型分类")
        print("  • 自动检测规则冲突")
        print("  • 语法验证和错误检查")
        print("  • 智能规则合并优化")
        print("  • 详细统计报告")
        
        print("\n" + "=" * 60)


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
