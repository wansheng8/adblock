#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - 新语法版
生成 DNS、Hosts、浏览器三层规则
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
    
    def is_valid_dns_rule(self, rule: str) -> bool:
        """检查是否为有效DNS规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return False
        
        # 必须是纯域名
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return False
        
        # 禁止通配符
        if '*' in rule:
            return False
        
        # 禁止特殊符号
        if any(c in rule for c in ['^', '|', '$', '@', '#', '/']):
            return False
        
        return True
    
    def is_valid_hosts_rule(self, rule: str) -> bool:
        """检查是否为有效Hosts规则"""
        rule = rule.strip()
        
        # 必须是 0.0.0.0 + 域名格式
        match = re.match(r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if not match:
            return False
        
        # 验证域名部分
        domain = match.group(1)
        return self.is_valid_dns_rule(domain)
    
    def is_valid_browser_rule(self, rule: str) -> bool:
        """检查是否为有效浏览器规则"""
        rule = rule.strip()
        
        # 空行或注释
        if not rule or rule.startswith('!'):
            return False
        
        # 1. 域名阻断规则
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            return self.is_valid_dns_rule(domain)
        
        # 2. 元素隐藏规则
        elif rule.startswith('##'):
            selector = rule[2:]
            # 简单的CSS选择器验证
            if len(selector) > 200:
                return False
            if '*' in selector:  # 禁止通配符
                return False
            return True
        
        # 3. 白名单规则
        elif rule.startswith('@@||') and rule.endswith('^'):
            domain = rule[4:-1]
            return self.is_valid_dns_rule(domain)
        
        # 4. 简单修饰符规则（谨慎使用）
        elif '$' in rule and not any(c in rule for c in ['*', '/']):
            return True
        
        return False
    
    def extract_and_clean_rules(self, content: str) -> Tuple[List[str], List[str], List[str]]:
        """从内容中提取并清理规则"""
        dns_rules = []
        hosts_rules = []
        browser_rules = []
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 检查并分类规则
            if self.is_valid_dns_rule(line):
                dns_rules.append(line)
            elif self.is_valid_hosts_rule(line):
                hosts_rules.append(line)
            elif self.is_valid_browser_rule(line):
                browser_rules.append(line)
            else:
                # 尝试转换浏览器规则为DNS/Hosts规则
                domain = self.extract_domain_from_browser_rule(line)
                if domain and self.is_valid_dns_rule(domain):
                    dns_rules.append(domain)
                    hosts_rules.append(f"0.0.0.0 {domain}")
        
        return dns_rules, hosts_rules, browser_rules
    
    def extract_domain_from_browser_rule(self, rule: str) -> str:
        """从浏览器规则中提取域名"""
        # 域名阻断规则
        match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 白名单规则
        match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 带修饰符的规则
        if '$' in rule:
            parts = rule.split('$')
            base = parts[0]
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', base)
            if match:
                return match.group(1)
        
        return ""
    
    def generate_dns_file(self, rules: List[str]) -> int:
        """生成DNS规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        # 生成文件头
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        header = f"""# DNS规则文件 - 用于AdGuard Home/DNS服务
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(unique_rules)} 条
# 说明: 每行一个域名，无特殊符号
# 用法: 导入到DNS过滤服务中
# ==================================================

"""
        
        # 写入文件
        output_file = self.base_dir / 'dist/dns.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
        
        return len(unique_rules)
    
    def generate_hosts_file(self, rules: List[str]) -> int:
        """生成Hosts规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        # 生成文件头
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        header = f"""# Hosts规则文件 - 用于系统hosts文件
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(unique_rules)} 条
# 说明: 使用 0.0.0.0 兼容所有操作系统
# 用法: 复制到系统 hosts 文件中
# ==================================================

"""
        
        # 写入文件
        output_file = self.base_dir / 'dist/hosts.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
        
        return len(unique_rules)
    
    def generate_browser_file(self, rules: List[str]) -> int:
        """生成浏览器规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        # 生成文件头
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        header = f"""! 浏览器规则文件 - 用于uBlock Origin/AdBlock
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(unique_rules)} 条
! 语法: ||domain.com^  ##selector  @@||domain.com^
! 说明: 避免使用通配符(*)和正则表达式
! ==================================================

"""
        
        # 写入文件
        output_file = self.base_dir / 'dist/filter.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
        
        return len(unique_rules)
    
    def generate_whitelist_file(self):
        """生成白名单文件（单独处理）"""
        whitelist_file = self.base_dir / 'dist/whitelist.txt'
        if whitelist_file.exists():
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            whitelist_rules = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('!') and self.is_valid_browser_rule(line):
                    whitelist_rules.append(line)
            
            # 生成更新后的白名单
            now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
            header = f"""! 白名单规则文件 - 用于浏览器扩展
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(whitelist_rules)} 条
! 说明: 以下域名/元素不会被拦截
! ==================================================

"""
            
            with open(whitelist_file, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write('\n'.join(whitelist_rules))
            
            return len(whitelist_rules)
        return 0
    
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
                dns_rules, hosts_rules, browser_rules = self.extract_and_clean_rules(content)
                
                all_dns_rules.extend(dns_rules)
                all_hosts_rules.extend(hosts_rules)
                all_browser_rules.extend(browser_rules)
                
                print(f"  ✅ {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则")
                
                successful_sources += 1
            else:
                print(f"  ❌ {source['name']}: 失败")
        
        print(f"\n📊 规则获取完成: {successful_sources}/{len(sorted_sources)} 成功")
        
        # 生成各层规则文件
        print("\n📄 生成规则文件...")
        
        # DNS规则
        dns_count = self.generate_dns_file(all_dns_rules)
        print(f"  ├── DNS规则: {dns_count} 条")
        
        # Hosts规则
        hosts_count = self.generate_hosts_file(all_hosts_rules)
        print(f"  ├── Hosts规则: {hosts_count} 条")
        
        # 浏览器规则
        browser_count = self.generate_browser_file(all_browser_rules)
        print(f"  ├── 浏览器规则: {browser_count} 条")
        
        # 白名单规则
        whitelist_count = self.generate_whitelist_file()
        print(f"  ├── 白名单规则: {whitelist_count} 条")
        
        # 生成元数据
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        metadata = {
            "last_updated": now.isoformat(),
            "rule_counts": {
                "dns_rules": dns_count,
                "hosts_rules": hosts_count,
                "browser_rules": browser_count,
                "whitelist_rules": whitelist_count,
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
        print(f"📊 DNS规则: {dns_count} 条")
        print(f"📊 Hosts规则: {hosts_count} 条")
        print(f"📊 浏览器规则: {browser_count} 条")
        print(f"📊 白名单规则: {whitelist_count} 条")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"⏰ 下次更新: {(now + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}")
        print("\n🎯 新语法规则:")
        print("  • DNS: 纯域名 (example.com)")
        print("  • Hosts: 0.0.0.0 example.com")
        print("  • 浏览器: ||example.com^  ##.ad-banner")
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
