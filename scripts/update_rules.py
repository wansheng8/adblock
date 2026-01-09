#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - 新语法版
生成三层规则文件：DNS、Hosts、浏览器规则
"""

import json
import requests
import datetime
import re
import sys
import traceback
from pathlib import Path
from typing import Tuple, List, Dict, Any


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        
    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            with open(self.base_dir / self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            self.sources = self.config.get('sources', [])
            print(f"📋 已加载 {len(self.sources)} 个规则源")
            return True
        except FileNotFoundError:
            print(f"❌ 配置文件不存在: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ 配置文件JSON格式错误: {e}")
            return False
    
    def fetch_source(self, source: Dict[str, Any]) -> Tuple[bool, str]:
        """获取规则源内容"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"🌐 正在获取: {source['name']}")
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件（仅供调试）
            source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True, content
            
        except Exception as e:
            print(f"❌ 获取失败 {source['name']}: {str(e)}")
            return False, ""
    
    def extract_domain_from_rule(self, rule: str) -> str:
        """从各种规则格式中提取域名"""
        rule = rule.strip()
        
        # 1. 纯域名
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return rule
        
        # 2. Hosts格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            return match.group(1)
        
        # 3. 域名阻断规则
        match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 4. 白名单规则
        match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 5. 带修饰符的规则
        if '$' in rule:
            parts = rule.split('$')
            base_rule = parts[0]
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', base_rule)
            if match:
                return match.group(1)
        
        return ""
    
    def process_rule(self, rule: str) -> Tuple[str, str, str]:
        """处理单条规则，返回三层规则"""
        rule = rule.strip()
        
        # 跳过注释和空行
        if not rule or rule.startswith('!'):
            return "", "", ""
        
        dns_rule = ""
        hosts_rule = ""
        browser_rule = ""
        
        # 1. 如果是纯域名（DNS规则）
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            if '*' not in rule:  # 禁止通配符
                dns_rule = rule
                hosts_rule = f"0.0.0.0 {rule}"
                browser_rule = f"||{rule}^"
        
        # 2. 如果是Hosts规则
        elif re.match(r'^0\.0\.0\.0\s+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            hosts_rule = rule
            # 提取域名
            match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
            if match:
                domain = match.group(1)
                dns_rule = domain
                browser_rule = f"||{domain}^"
        
        # 3. 如果是浏览器域名阻断规则
        elif re.match(r'^\|\|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\^$', rule):
            browser_rule = rule
            # 提取域名
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$', rule)
            if match:
                domain = match.group(1)
                dns_rule = domain
                hosts_rule = f"0.0.0.0 {domain}"
        
        # 4. 如果是元素隐藏规则
        elif re.match(r'^##', rule):
            browser_rule = rule
        
        # 5. 如果是白名单规则
        elif re.match(r'^@@', rule):
            # 白名单规则只放在浏览器规则中
            browser_rule = rule
        
        # 6. 如果是带修饰符的规则
        elif '$' in rule:
            browser_rule = rule
            # 尝试提取域名
            domain = self.extract_domain_from_rule(rule)
            if domain:
                dns_rule = domain
                hosts_rule = f"0.0.0.0 {domain}"
        
        return dns_rule, hosts_rule, browser_rule
    
    def process_content(self, content: str) -> Tuple[List[str], List[str], List[str]]:
        """处理整个内容，返回三层规则列表"""
        dns_rules = []
        hosts_rules = []
        browser_rules = []
        
        lines = content.split('\n')
        
        for line in lines:
            dns_rule, hosts_rule, browser_rule = self.process_rule(line)
            
            if dns_rule:
                dns_rules.append(dns_rule)
            if hosts_rule:
                hosts_rules.append(hosts_rule)
            if browser_rule:
                browser_rules.append(browser_rule)
        
        return dns_rules, hosts_rules, browser_rules
    
    def write_file(self, filename: str, rules: List[str], header: str) -> int:
        """写入规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        # 写入文件
        output_file = self.base_dir / 'dist' / filename
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
        
        return len(unique_rules)
    
    def run(self) -> bool:
        """执行更新流程"""
        print("=" * 60)
        print("🚀 开始更新广告拦截规则 - 新语法版")
        print("=" * 60)
        
        if not self.load_config():
            return False
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(parents=True, exist_ok=True)
        
        all_dns_rules = []
        all_hosts_rules = []
        all_browser_rules = []
        successful_sources = 0
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                print(f"⏭️  跳过禁用源: {source['name']}")
                continue
            
            success, content = self.fetch_source(source)
            
            if success and content:
                dns_rules, hosts_rules, browser_rules = self.process_content(content)
                
                all_dns_rules.extend(dns_rules)
                all_hosts_rules.extend(hosts_rules)
                all_browser_rules.extend(browser_rules)
                
                print(f"  ✅ {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则")
                
                successful_sources += 1
            else:
                print(f"  ❌ {source['name']}: 失败")
        
        print(f"\n📊 规则获取完成: {successful_sources}/{len(sorted_sources)} 成功")
        
        # 生成时间
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        
        # 生成DNS规则文件
        print("\n📄 生成DNS规则文件...")
        dns_header = f"""# DNS规则文件 - 用于AdGuard Home/DNS服务
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(all_dns_rules)} 条
# 说明: 每行一个域名，无特殊符号
# 语法: 纯域名 (example.com)
# 禁止: 通配符(*)、正则表达式、特殊符号
# 用法: 导入到DNS过滤服务中
# ==================================================

"""
        dns_count = self.write_file("dns.txt", all_dns_rules, dns_header)
        
        # 生成Hosts规则文件
        print("📄 生成Hosts规则文件...")
        hosts_header = f"""# Hosts规则文件 - 用于系统hosts文件
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(all_hosts_rules)} 条
# 说明: 使用 0.0.0.0 兼容所有操作系统
# 语法: 0.0.0.0 example.com
# 用法: 复制到系统 hosts 文件中
# ==================================================

"""
        hosts_count = self.write_file("hosts.txt", all_hosts_rules, hosts_header)
        
        # 生成浏览器规则文件
        print("📄 生成浏览器规则文件...")
        browser_header = f"""! 浏览器规则文件 - 用于uBlock Origin/AdBlock
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(all_browser_rules)} 条
! 语法: ||domain.com^  ##selector  @@||domain.com^
! 说明: 避免使用通配符(*)和正则表达式
! 用法: 导入到浏览器广告拦截扩展中
! ==================================================

"""
        browser_count = self.write_file("filter.txt", all_browser_rules, browser_header)
        
        # 生成元数据
        metadata = {
            "last_updated": now.isoformat(),
            "rule_counts": {
                "dns_rules": dns_count,
                "hosts_rules": hosts_count,
                "browser_rules": browser_count,
                "total_rules": dns_count + hosts_count + browser_count
            },
            "sources_used": successful_sources,
            "sources_total": len(sorted_sources),
            "next_update": (now + datetime.timedelta(hours=8)).isoformat(),
            "syntax_version": "1.0",
            "notes": "新语法规则：DNS/Hosts只放域名，浏览器才用复杂语法"
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 DNS规则: {dns_count} 条 (dns.txt)")
        print(f"📊 Hosts规则: {hosts_count} 条 (hosts.txt)")
        print(f"📊 浏览器规则: {browser_count} 条 (filter.txt)")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"⏰ 下次更新: {(now + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}")
        print("\n🎯 新语法规则:")
        print("  • DNS: 纯域名 (example.com)")
        print("  • Hosts: 0.0.0.0 example.com")
        print("  • 浏览器: ||example.com^  ##.ad-banner  @@||example.com^")
        print("  • 禁止: 通配符(*)、正则表达式")
        print("=" * 60)
        
        return True


def main():
    updater = RuleUpdater()
    try:
        success = updater.run()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ 用户中断更新")
        sys.exit(130)
    except Exception as e:
        print(f"❌ 更新过程中发生错误: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
