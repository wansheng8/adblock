#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则格式化脚本 - 根据新语法重制版
支持DNS、Hosts、浏览器规则三层分离
"""

import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


class RuleFormatter:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.now = datetime.now()
        
        # 新语法分类
        self.categories = {
            "DNS规则": {
                "desc": "纯域名规则，用于DNS/AdGuard Home",
                "rules": []
            },
            "Hosts规则": {
                "desc": "0.0.0.0 + 域名，用于系统hosts文件",
                "rules": []
            },
            "浏览器域名阻断规则": {
                "desc": "||domain.com^ 格式，用于浏览器扩展",
                "rules": []
            },
            "浏览器元素隐藏规则": {
                "desc": "##selector 格式，隐藏页面元素",
                "rules": []
            },
            "浏览器白名单规则": {
                "desc": "@@domain.com^ 格式，不拦截的域名",
                "rules": []
            },
            "高级浏览器规则": {
                "desc": "带修饰符的复杂规则（谨慎使用）",
                "rules": []
            }
        }
        
    def classify_rule_by_new_syntax(self, rule):
        """根据新语法分类规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return None
        
        # 1. DNS规则（纯域名）
        # 只包含字母、数字、点、连字符，且没有特殊符号
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            if '*' not in rule:  # 禁止通配符
                return "DNS规则"
        
        # 2. Hosts规则
        if re.match(r'^0\.0\.0\.0\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return "Hosts规则"
        
        # 3. 浏览器域名阻断规则
        if re.match(r'^\|\|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^$', rule):
            return "浏览器域名阻断规则"
        
        # 4. 浏览器元素隐藏规则
        if re.match(r'^##[a-zA-Z0-9_\-\[\]\.#\:>+~= \*"\']+$', rule):
            return "浏览器元素隐藏规则"
        
        # 5. 浏览器白名单规则
        if re.match(r'^@@\|\|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^$', rule):
            return "浏览器白名单规则"
        
        # 6. 高级浏览器规则（带修饰符）
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^?\$[a-z,=]+$', rule):
            return "高级浏览器规则"
        
        return None
    
    def validate_dns_rule(self, rule):
        """验证DNS规则语法"""
        # 基本格式检查
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return False, "格式错误：必须是纯域名"
        
        # 禁止通配符
        if '*' in rule:
            return False, "禁止使用通配符 *"
        
        # 禁止特殊符号
        if any(c in rule for c in ['^', '|', '$', '@', '#', '/', '!']):
            return False, "禁止使用特殊符号"
        
        # 域名长度检查
        if len(rule) > 253:
            return False, "域名过长"
        
        # 标签长度检查（每个点分隔的部分）
        labels = rule.split('.')
        for label in labels:
            if len(label) > 63:
                return False, f"标签 '{label}' 过长"
            if not label:
                return False, "域名标签不能为空"
        
        return True, "有效DNS规则"
    
    def validate_hosts_rule(self, rule):
        """验证Hosts规则语法"""
        # 基本格式检查
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            return False, "格式错误：必须是 '0.0.0.0 域名' 格式"
        
        domain = match.group(1)
        
        # 验证域名部分
        is_valid, message = self.validate_dns_rule(domain)
        if not is_valid:
            return False, f"域名部分{message}"
        
        return True, "有效Hosts规则"
    
    def validate_browser_rule(self, rule):
        """验证浏览器规则语法"""
        rule = rule.strip()
        
        # 1. 域名阻断规则
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return False, "域名格式错误"
            return True, "有效域名阻断规则"
        
        # 2. 元素隐藏规则
        elif rule.startswith('##'):
            selector = rule[2:]
            # 简单的CSS选择器验证
            if len(selector) > 200:
                return False, "CSS选择器过长"
            return True, "有效元素隐藏规则"
        
        # 3. 白名单规则
        elif rule.startswith('@@||') and rule.endswith('^'):
            domain = rule[4:-1]
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return False, "域名格式错误"
            return True, "有效白名单规则"
        
        # 4. 高级规则（带修饰符）
        elif '$' in rule:
            # 检查修饰符格式
            parts = rule.split('$')
            if len(parts) != 2:
                return False, "修饰符格式错误"
            
            base_rule, modifiers = parts
            # 验证修饰符
            if not re.match(r'^[a-z,=]+$', modifiers):
                return False, "修饰符包含非法字符"
            
            return True, "有效高级规则"
        
        return False, "未知规则格式"
    
    def process_dns_file(self):
        """处理DNS规则文件"""
        input_file = self.base_dir / 'dist/blacklist.txt'
        output_file = self.base_dir / 'dist/dns.txt'
        
        if not input_file.exists():
            print("❌ 输入文件不存在")
            return 0
        
        print("🔍 提取DNS规则...")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        dns_rules = []
        invalid_rules = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # 尝试提取纯域名
            domain = self.extract_domain_from_rule(line)
            if domain:
                # 验证DNS规则
                is_valid, message = self.validate_dns_rule(domain)
                if is_valid:
                    dns_rules.append(domain)
                else:
                    invalid_rules.append((line, message))
        
        # 去重排序
        dns_rules = sorted(set(dns_rules))
        
        # 生成文件头
        header = f"""# DNS规则文件 - 用于AdGuard Home/DNS服务
# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}
# 规则数量: {len(dns_rules)} 条
# 说明: 每行一个域名，无特殊符号
# ==================================================

"""
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(dns_rules))
        
        print(f"✅ DNS规则已生成: {len(dns_rules)} 条")
        if invalid_rules:
            print(f"⚠️  跳过 {len(invalid_rules)} 条无效规则")
        
        return len(dns_rules)
    
    def process_hosts_file(self):
        """处理Hosts规则文件"""
        input_file = self.base_dir / 'dist/blacklist.txt'
        output_file = self.base_dir / 'dist/hosts.txt'
        
        if not input_file.exists():
            print("❌ 输入文件不存在")
            return 0
        
        print("🔍 提取Hosts规则...")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        hosts_rules = []
        invalid_rules = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # 尝试提取域名
            domain = self.extract_domain_from_rule(line)
            if domain:
                # 生成Hosts规则
                hosts_rule = f"0.0.0.0 {domain}"
                is_valid, message = self.validate_hosts_rule(hosts_rule)
                if is_valid:
                    hosts_rules.append(hosts_rule)
                else:
                    invalid_rules.append((line, message))
        
        # 去重排序
        hosts_rules = sorted(set(hosts_rules))
        
        # 生成文件头
        header = f"""# Hosts规则文件 - 用于系统hosts文件
# 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}
# 规则数量: {len(hosts_rules)} 条
# 说明: 使用 0.0.0.0 兼容所有操作系统
# ==================================================

"""
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(hosts_rules))
        
        print(f"✅ Hosts规则已生成: {len(hosts_rules)} 条")
        if invalid_rules:
            print(f"⚠️  跳过 {len(invalid_rules)} 条无效规则")
        
        return len(hosts_rules)
    
    def process_browser_file(self):
        """处理浏览器规则文件"""
        input_file = self.base_dir / 'dist/blacklist.txt'
        output_file = self.base_dir / 'dist/filter.txt'
        
        if not input_file.exists():
            print("❌ 输入文件不存在")
            return 0
        
        print("🔍 提取浏览器规则...")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        browser_rules = []
        invalid_rules = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            # 跳过DNS/Hosts规则
            if self.classify_rule_by_new_syntax(line) in ["DNS规则", "Hosts规则"]:
                continue
            
            # 验证浏览器规则
            is_valid, message = self.validate_browser_rule(line)
            if is_valid:
                browser_rules.append(line)
            else:
                invalid_rules.append((line, message))
        
        # 去重排序
        browser_rules = sorted(set(browser_rules))
        
        # 生成文件头
        header = f"""! 浏览器规则文件 - 用于uBlock Origin/AdBlock
! 生成时间: {self.now.strftime('%Y-%m-%d %H:%M:%S')}
! 规则数量: {len(browser_rules)} 条
! 语法: ||domain.com^  ##selector  @@||domain.com^
! ==================================================

"""
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(browser_rules))
        
        print(f"✅ 浏览器规则已生成: {len(browser_rules)} 条")
        if invalid_rules:
            print(f"⚠️  跳过 {len(invalid_rules)} 条无效规则")
        
        return len(browser_rules)
    
    def extract_domain_from_rule(self, rule):
        """从规则中提取域名"""
        rule = rule.strip()
        
        # 1. 纯域名
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return rule
        
        # 2. Hosts格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            return match.group(1)
        
        # 3. 浏览器规则格式
        match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        return None
    
    def run(self):
        """执行格式化流程"""
        print("=" * 60)
        print("🔄 规则格式化工具 - 新语法版")
        print("=" * 60)
        
        # 检查dist目录
        dist_dir = self.base_dir / 'dist'
        if not dist_dir.exists():
            print("❌ dist目录不存在，创建中...")
            dist_dir.mkdir(parents=True)
        
        # 1. 处理DNS规则
        print("\n📄 步骤1: 生成DNS规则")
        dns_count = self.process_dns_file()
        
        # 2. 处理Hosts规则
        print("\n📄 步骤2: 生成Hosts规则")
        hosts_count = self.process_hosts_file()
        
        # 3. 处理浏览器规则
        print("\n📄 步骤3: 生成浏览器规则")
        browser_count = self.process_browser_file()
        
        # 4. 生成统计报告
        print("\n📊 步骤4: 生成统计报告")
        self.generate_statistics_report(dns_count, hosts_count, browser_count)
        
        print("\n" + "=" * 60)
        print("🎯 新语法规则:")
        print("  • DNS规则: 纯域名 (ads.example.com)")
        print("  • Hosts规则: 0.0.0.0 ads.example.com")
        print("  • 浏览器规则: ||ads.example.com^  ##.ad-banner")
        print("  • 白名单规则: @@||trusted.example.com^")
        print("  • 禁止: 通配符(*)、正则表达式")
        print("=" * 60)
    
    def generate_statistics_report(self, dns_count, hosts_count, browser_count):
        """生成统计报告"""
        report = {
            "timestamp": self.now.strftime('%Y-%m-%d %H:%M:%S'),
            "rule_counts": {
                "dns_rules": dns_count,
                "hosts_rules": hosts_count,
                "browser_rules": browser_count,
                "total_rules": dns_count + hosts_count + browser_count
            },
            "files": [
                {"name": "dns.txt", "desc": "DNS/AdGuard Home规则", "count": dns_count},
                {"name": "hosts.txt", "desc": "系统hosts文件规则", "count": hosts_count},
                {"name": "filter.txt", "desc": "浏览器扩展规则", "count": browser_count},
                {"name": "whitelist.txt", "desc": "浏览器白名单规则", "count": "独立文件"}
            ]
        }
        
        # 保存报告
        report_file = self.base_dir / 'dist/format_report.json'
        import json
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"📊 格式化完成!")
        print(f"  ├── DNS规则: {dns_count} 条")
        print(f"  ├── Hosts规则: {hosts_count} 条")
        print(f"  ├── 浏览器规则: {browser_count} 条")
        print(f"  └── 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"📁 报告已保存: {report_file}")


if __name__ == "__main__":
    formatter = RuleFormatter()
    formatter.run()
