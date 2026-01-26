#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - 完整语法版
支持：白名单(@@)、精确域名、子域/通配(||+^)、CNAME拦截、分类规则、响应策略
"""

import json
import requests
import datetime
import re
import sys
import traceback
from pathlib import Path
from typing import Tuple, List, Dict, Any, Set
from urllib.parse import urlparse
import socket
import hashlib


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        
        # 支持的规则类型
        self.rule_patterns = {
            'whitelist': re.compile(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^?'),
            'domain_block': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^'),
            'exact_domain': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^?$'),
            'cname_block': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^\$dnstype=CNAME'),
            'hosts_rule': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'),
            'element_hiding': re.compile(r'^##'),
            'response_policy': re.compile(r'\$responsepolicy='),
            'category_rule': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^\$(\w+)=(.*)'),
            'simple_domain': re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        }
    
    def load_gz_sources(self) -> List[Dict[str, Any]]:
        """从 gz.txt 文件加载额外规则源"""
        gz_file = self.base_dir / 'sources' / 'gz.txt'
        gz_sources = []
        
        if not gz_file.exists():
            print("📂 gz.txt 文件不存在，跳过额外规则源")
            return gz_sources
        
        try:
            with open(gz_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = [line.strip() for line in content.split('\n')]
            lines = [line for line in lines if line and not line.startswith('#')]
            
            print(f"📄 读取 gz.txt 文件，发现 {len(lines)} 个有效链接")
            
            for idx, line in enumerate(lines):
                url = line.strip()
                
                if re.match(r'^https?://', url):
                    source = {
                        'name': f'gz_rule_{idx + 1:03d}',
                        'url': url,
                        'enabled': True,
                        'priority': 999 + idx,
                        'type': 'gz_txt',
                        'category': 'mixed'  # 混合规则
                    }
                    gz_sources.append(source)
                    print(f"  ├── [{idx+1:03d}] 额外规则源: {url[:80]}...")
                else:
                    print(f"  ⚠️  跳过无效链接: {url[:50]}")
            
            print(f"✅ 从 gz.txt 加载了 {len(gz_sources)} 个额外规则源")
            return gz_sources
            
        except Exception as e:
            print(f"❌ 读取 gz.txt 文件失败: {str(e)}")
            return gz_sources
    
    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            config_file = self.base_dir / self.config_path
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            self.sources = self.config.get('sources', [])
            print(f"📋 已加载 {len(self.sources)} 个规则源从 {self.config_path}")
            
            gz_sources = self.load_gz_sources()
            self.sources.extend(gz_sources)
            
            print(f"📋 总计 {len(self.sources)} 个规则源（主规则源: {len(self.sources) - len(gz_sources)}, 额外规则源: {len(gz_sources)}）")
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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/plain,*/*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            print(f"🌐 正在获取: {source['name']}")
            
            timeout = 45
            response = requests.get(source['url'], headers=headers, timeout=timeout)
            response.raise_for_status()
            
            response.encoding = response.apparent_encoding or 'utf-8'
            content = response.text
            
            # 保存原始文件（仅供调试）
            if 'type' not in source or source.get('type') != 'gz_txt':
                source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
                raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                raw_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(raw_file, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            return True, content
            
        except requests.exceptions.Timeout:
            print(f"⏱️  超时: {source['name']}")
            return False, ""
        except requests.exceptions.ConnectionError:
            print(f"🔌 连接错误: {source['name']}")
            return False, ""
        except requests.exceptions.HTTPError as e:
            print(f"🌐 HTTP错误 {e.response.status_code}: {source['name']}")
            return False, ""
        except Exception as e:
            print(f"❌ 获取失败 {source['name']}: {str(e)}")
            return False, ""
    
    def classify_rule_type(self, rule: str) -> Dict[str, Any]:
        """分类规则类型"""
        rule = rule.strip()
        
        # 跳过注释
        if not rule or rule.startswith(('!', '#', '[')):
            return {'type': 'comment', 'valid': False}
        
        result = {
            'type': 'unknown',
            'valid': True,
            'domain': '',
            'subdomain': False,
            'exact': False,
            'whitelist': False,
            'cname': False,
            'category': '',
            'response_policy': False,
            'raw_rule': rule
        }
        
        # 1. 白名单规则 (@@开头)
        if rule.startswith('@@'):
            result['type'] = 'whitelist'
            result['whitelist'] = True
            
            # 提取域名
            match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                result['domain'] = match.group(1)
                result['subdomain'] = rule.startswith('@@||') and rule.endswith('^')
                result['exact'] = '^$' in rule
            
            return result
        
        # 2. 域名阻断规则 (||开头 ^结尾)
        if rule.startswith('||') and '^' in rule:
            result['type'] = 'domain_block'
            result['subdomain'] = True
            
            # 提取域名
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
            if match:
                result['domain'] = match.group(1)
                result['exact'] = rule.endswith('^$')
            
            # 检查CNAME拦截
            if '$dnstype=CNAME' in rule:
                result['type'] = 'cname_block'
                result['cname'] = True
            
            # 检查分类规则
            if '$' in rule:
                parts = rule.split('$')
                if len(parts) > 1:
                    modifiers = parts[1]
                    if 'category=' in modifiers:
                        result['type'] = 'category_rule'
                        match = re.search(r'category=([^,]+)', modifiers)
                        if match:
                            result['category'] = match.group(1)
                    
                    if 'responsepolicy=' in modifiers:
                        result['response_policy'] = True
            
            return result
        
        # 3. Hosts规则
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            result['type'] = 'hosts_rule'
            result['domain'] = match.group(2)
            return result
        
        # 4. 元素隐藏规则
        if rule.startswith('##'):
            result['type'] = 'element_hiding'
            return result
        
        # 5. 精确域名
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            result['type'] = 'simple_domain'
            result['domain'] = rule
            result['exact'] = True
            return result
        
        # 6. 带修饰符的规则
        if '$' in rule and rule.startswith('||'):
            result['type'] = 'advanced_rule'
            
            # 提取域名
            base_part = rule.split('$')[0]
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', base_part)
            if match:
                result['domain'] = match.group(1)
                result['subdomain'] = True
            
            # 检查修饰符
            modifiers = rule.split('$')[1]
            if 'cname' in modifiers.lower():
                result['cname'] = True
            
            if 'responsepolicy=' in modifiers:
                result['response_policy'] = True
            
            return result
        
        # 7. 正则表达式规则（简化处理）
        if rule.startswith('/') and rule.endswith('/'):
            result['type'] = 'regex_rule'
            result['valid'] = False  # 不处理正则表达式
            return result
        
        return result
    
    def process_rule_for_dns(self, rule_info: Dict[str, Any]) -> str:
        """处理DNS规则"""
        if not rule_info['valid']:
            return ""
        
        # DNS规则只处理纯域名
        if rule_info['domain'] and not rule_info['whitelist']:
            return rule_info['domain']
        
        return ""
    
    def process_rule_for_hosts(self, rule_info: Dict[str, Any]) -> str:
        """处理Hosts规则"""
        if not rule_info['valid']:
            return ""
        
        # Hosts规则只处理纯域名（非白名单）
        if rule_info['domain'] and not rule_info['whitelist']:
            return f"0.0.0.0 {rule_info['domain']}"
        
        return ""
    
    def process_rule_for_browser(self, rule_info: Dict[str, Any]) -> str:
        """处理浏览器规则"""
        if not rule_info['valid']:
            return ""
        
        # 返回原始规则（浏览器支持所有规则类型）
        return rule_info['raw_rule']
    
    def process_content(self, content: str) -> Tuple[List[str], List[str], List[str]]:
        """处理整个内容，返回三层规则列表"""
        dns_rules = []
        hosts_rules = []
        browser_rules = []
        
        lines = content.split('\n')
        line_count = len(lines)
        
        print(f"  📄 处理 {line_count} 行...")
        
        for line in lines:
            rule_info = self.classify_rule_type(line)
            
            if rule_info['valid']:
                # DNS规则
                dns_rule = self.process_rule_for_dns(rule_info)
                if dns_rule:
                    dns_rules.append(dns_rule)
                
                # Hosts规则
                hosts_rule = self.process_rule_for_hosts(rule_info)
                if hosts_rule:
                    hosts_rules.append(hosts_rule)
                
                # 浏览器规则
                browser_rule = self.process_rule_for_browser(rule_info)
                if browser_rule and not browser_rule.startswith(('!', '#')):
                    browser_rules.append(browser_rule)
        
        return dns_rules, hosts_rules, browser_rules
    
    def write_file(self, filename: str, rules: List[str], header: str, deduplicate: bool = True) -> int:
        """写入规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        if deduplicate:
            unique_rules = sorted(set(rules))
        else:
            unique_rules = sorted(rules)
        
        # 写入文件
        output_file = self.base_dir / 'dist' / filename
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
            if not unique_rules[-1].endswith('\n'):
                f.write('\n')
        
        return len(unique_rules)
    
    def run(self) -> bool:
        """执行更新流程"""
        print("=" * 60)
        print("🚀 广告拦截规则更新器 - 完整语法版")
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
        failed_sources = []
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        print(f"\n📊 开始处理 {len(sorted_sources)} 个规则源...")
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                print(f"⏭️  跳过禁用源: {source['name']}")
                continue
            
            success, content = self.fetch_source(source)
            
            if success and content:
                try:
                    dns_rules, hosts_rules, browser_rules = self.process_content(content)
                    
                    all_dns_rules.extend(dns_rules)
                    all_hosts_rules.extend(hosts_rules)
                    all_browser_rules.extend(browser_rules)
                    
                    source_type = source.get('type', 'main')
                    if source_type == 'gz_txt':
                        print(f"  📄 {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则")
                    else:
                        print(f"  ✅ {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则")
                    
                    successful_sources += 1
                except Exception as e:
                    print(f"  ⚠️  {source['name']}: 处理失败 - {str(e)}")
                    traceback.print_exc()
                    failed_sources.append(source['name'])
            else:
                print(f"  ❌ {source['name']}: 获取失败")
                failed_sources.append(source['name'])
        
        print(f"\n📊 规则获取完成:")
        print(f"  ✅ 成功: {successful_sources}/{len(sorted_sources)}")
        if failed_sources:
            print(f"  ❌ 失败: {len(failed_sources)}")
            for name in failed_sources[:5]:
                print(f"    • {name}")
        
        # 生成时间
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        
        # 生成DNS规则文件
        print("\n📄 生成DNS规则文件...")
        dns_header = f"""# DNS规则文件 - 用于AdGuard Home/DNS服务
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(all_dns_rules)} 条
# 规则来源: sources/sources.json + sources/gz.txt
# 语法: 纯域名 (example.com)
# 支持: 域名拦截，CNAME拦截（通过DNS服务实现）
# 用法: 导入到DNS过滤服务中
# ==================================================

"""
        dns_count = self.write_file("dns.txt", all_dns_rules, dns_header)
        
        # 生成Hosts规则文件
        print("📄 生成Hosts规则文件...")
        hosts_header = f"""# Hosts规则文件 - 用于系统hosts文件
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(all_hosts_rules)} 条
# 规则来源: sources/sources.json + sources/gz.txt
# 语法: 0.0.0.0 example.com
# 支持: 系统级域名拦截
# 用法: 复制到系统 hosts 文件中
# ==================================================

"""
        hosts_count = self.write_file("hosts.txt", all_hosts_rules, hosts_header)
        
        # 生成浏览器规则文件
        print("📄 生成浏览器规则文件...")
        browser_header = f"""! 浏览器规则文件 - 用于uBlock Origin/AdBlock
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(all_browser_rules)} 条
! 规则来源: sources/sources.json + sources/gz.txt
! 支持语法:
!   • 白名单: @@||example.com^
!   • 精确域名: ||example.com^$domain=example.com
!   • 子域/通配: ||example.com^
!   • CNAME拦截: ||example.com^$dnstype=CNAME
!   • 分类规则: ||example.com^$category=ads
!   • 响应策略: ||example.com^$responsepolicy=block
! ==================================================

"""
        browser_count = self.write_file("filter.txt", all_browser_rules, browser_header, deduplicate=False)
        
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
            "sources_failed": len(failed_sources),
            "syntax_version": "2.0",
            "features": [
                "whitelist_support",
                "exact_domain",
                "subdomain_wildcard",
                "cname_blocking",
                "category_rules",
                "response_policy"
            ],
            "notes": "完整语法支持：白名单、精确域名、子域通配、CNAME拦截、分类规则、响应策略",
            "includes_gz_txt": any(s.get('type') == 'gz_txt' for s in sorted_sources)
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 DNS规则: {dns_count} 条 (dns.txt)")
        print(f"📊 Hosts规则: {hosts_count} 条 (hosts.txt)")
        print(f"📊 浏览器规则: {browser_count} 条 (filter.txt)")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"📋 规则源: {successful_sources} 成功, {len(failed_sources)} 失败")
        print("\n🎯 支持的语法:")
        print("  • 白名单: @@||example.com^")
        print("  • 精确域名: example.com 或 ||example.com^$domain=example.com")
        print("  • 子域/通配: ||example.com^")
        print("  • CNAME拦截: ||example.com^$dnstype=CNAME")
        print("  • 分类规则: ||example.com^$category=ads|tracking|malware")
        print("  • 响应策略: ||example.com^$responsepolicy=block|redirect|modify")
        print("=" * 60)
        
        return successful_sources > 0


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
