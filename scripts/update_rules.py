#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - Adblock语法版
支持完整Adblock语法，包含ping检查功能
"""

import json
import requests
import datetime
import re
import sys
import traceback
import socket
import time
import concurrent.futures
from pathlib import Path
from typing import Tuple, List, Dict, Any, Set
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        
        # Adblock语法模式
        self.adblock_patterns = {
            'comment': re.compile(r'^[!\[#]'),
            'whitelist': re.compile(r'^@@'),
            'domain_block': re.compile(r'^\|\|([^\/\^\$\s]+)\^'),
            'element_hiding': re.compile(r'^##'),
            'element_hiding_exception': re.compile(r'^#@#'),
            'scriptlet_injection': re.compile(r'^#\$#'),
            'html_filtering': re.compile(r'^#\$?#'),
            'regex_rule': re.compile(r'^/(.*)/$'),
            'hosts_rule': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^#\s]+)'),
            'cname_rule': re.compile(r'\$dnstype=CNAME'),
            'advanced_rule': re.compile(r'\$[a-z]+=')
        }
        
        # 域名验证缓存
        self.domain_cache = {}
        self.domain_lock = threading.Lock()
        
        # Ping统计
        self.ping_stats = {
            'total_domains': 0,
            'resolved_domains': 0,
            'failed_domains': 0,
            'valid_domains': 0,
            'invalid_domains': 0
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
                        'category': 'mixed'
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
    
    def is_valid_domain_format(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain or len(domain) > 253:
            return False
        
        # 允许通配符
        if '*' in domain:
            # 通配符必须在开头
            if not domain.startswith('*.'):
                return False
            # 移除通配符部分后验证
            domain = domain[2:]
        
        # 基本域名格式验证
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return False
        
        # 检查标签长度
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or not label:
                return False
        
        return True
    
    def ping_domain(self, domain: str) -> Tuple[bool, str]:
        """Ping检查域名是否存在"""
        if not domain:
            return False, "空域名"
        
        # 检查缓存
        with self.domain_lock:
            if domain in self.domain_cache:
                return self.domain_cache[domain]
        
        # 如果是通配符域名，不进行ping检查
        if domain.startswith('*.'):
            with self.domain_lock:
                self.domain_cache[domain] = (True, "通配符域名")
            return True, "通配符域名"
        
        # 移除可能的路径和参数
        clean_domain = domain.split('/')[0].split('?')[0].split(':')[0]
        
        try:
            # 方法1: 尝试DNS解析
            start_time = time.time()
            socket.setdefaulttimeout(5)
            ip_address = socket.gethostbyname(clean_domain)
            resolve_time = time.time() - start_time
            
            if ip_address:
                result = (True, f"DNS解析成功: {ip_address} ({resolve_time:.2f}s)")
            else:
                result = (False, "DNS解析失败")
                
        except socket.gaierror:
            # DNS解析失败，尝试HTTP请求
            try:
                test_url = f"http://{clean_domain}"
                start_time = time.time()
                response = requests.head(test_url, timeout=5, allow_redirects=True)
                http_time = time.time() - start_time
                
                if response.status_code < 500:
                    result = (True, f"HTTP可达: {response.status_code} ({http_time:.2f}s)")
                else:
                    result = (False, f"HTTP错误: {response.status_code}")
            except Exception as e:
                result = (False, f"连接失败: {str(e)}")
        except Exception as e:
            result = (False, f"检查失败: {str(e)}")
        
        # 更新缓存
        with self.domain_lock:
            self.domain_cache[domain] = result
        
        return result
    
    def extract_domain_from_rule(self, rule: str) -> str:
        """从Adblock规则中提取域名"""
        rule = rule.strip()
        
        if not rule or rule.startswith(('!', '#', '[')):
            return ""
        
        # 1. 域名阻断规则: ||example.com^
        match = re.match(r'^\|\|([^\/\^\$\s]+)\^', rule)
        if match:
            return match.group(1)
        
        # 2. 白名单规则: @@||example.com^
        match = re.match(r'^@@\|\|([^\/\^\$\s]+)\^', rule)
        if match:
            return match.group(1)
        
        # 3. Hosts规则: 0.0.0.0 example.com
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^#\s]+)', rule)
        if match:
            return match.group(2)
        
        # 4. 简单域名规则: example.com
        if re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', rule) and '/' not in rule and '$' not in rule:
            return rule
        
        # 5. 带修饰符的规则: ||example.com^$domain=example.com
        if '$' in rule:
            base_part = rule.split('$')[0]
            match = re.match(r'^\|\|([^\/\^\$\s]+)\^', base_part)
            if match:
                return match.group(1)
        
        return ""
    
    def classify_rule_type(self, rule: str) -> Dict[str, Any]:
        """分类规则类型"""
        rule = rule.strip()
        
        if not rule:
            return {'type': 'empty', 'valid': False}
        
        if rule.startswith('!'):
            return {'type': 'comment', 'valid': True}
        
        if rule.startswith('#'):
            if rule.startswith('##'):
                return {'type': 'element_hiding', 'valid': True}
            elif rule.startswith('#@#'):
                return {'type': 'element_hiding_exception', 'valid': True}
            elif rule.startswith('#$#'):
                return {'type': 'scriptlet_injection', 'valid': True}
            else:
                return {'type': 'comment', 'valid': True}
        
        result = {
            'type': 'unknown',
            'valid': False,
            'domain': '',
            'is_adblock': False,
            'raw_rule': rule
        }
        
        # 检查Adblock语法
        if rule.startswith('||') and '^' in rule:
            result['type'] = 'domain_block'
            result['is_adblock'] = True
            domain = self.extract_domain_from_rule(rule)
            if domain and self.is_valid_domain_format(domain):
                result['domain'] = domain
                result['valid'] = True
        
        elif rule.startswith('@@'):
            result['type'] = 'whitelist'
            result['is_adblock'] = True
            domain = self.extract_domain_from_rule(rule)
            if domain and self.is_valid_domain_format(domain):
                result['domain'] = domain
                result['valid'] = True
            else:
                result['valid'] = True  # 白名单规则可能没有域名
        
        elif rule.startswith('/') and rule.endswith('/'):
            result['type'] = 'regex'
            result['is_adblock'] = True
            result['valid'] = True
        
        elif '$' in rule and ('||' in rule or '@@' in rule):
            result['type'] = 'advanced'
            result['is_adblock'] = True
            domain = self.extract_domain_from_rule(rule)
            if domain and self.is_valid_domain_format(domain):
                result['domain'] = domain
                result['valid'] = True
            else:
                result['valid'] = True  # 高级规则可能没有域名
        
        elif re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+', rule):
            result['type'] = 'hosts'
            domain = self.extract_domain_from_rule(rule)
            if domain and self.is_valid_domain_format(domain):
                result['domain'] = domain
                result['valid'] = True
        
        elif re.match(r'^[a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$', rule):
            result['type'] = 'simple_domain'
            if self.is_valid_domain_format(rule):
                result['domain'] = rule
                result['valid'] = True
        
        return result
    
    def process_rule_with_ping(self, rule: str) -> Tuple[str, str, str, bool]:
        """处理单条规则，包含ping检查"""
        rule_info = self.classify_rule_type(rule)
        
        if not rule_info['valid']:
            return "", "", "", False
        
        dns_rule = ""
        hosts_rule = ""
        browser_rule = ""
        is_valid = True
        
        # 如果是域名规则，进行ping检查
        if rule_info.get('domain'):
            domain = rule_info['domain']
            self.ping_stats['total_domains'] += 1
            
            # 检查域名格式
            if not self.is_valid_domain_format(domain):
                self.ping_stats['invalid_domains'] += 1
                is_valid = False
            else:
                # 执行ping检查
                ping_result, ping_message = self.ping_domain(domain)
                if ping_result:
                    self.ping_stats['resolved_domains'] += 1
                    self.ping_stats['valid_domains'] += 1
                else:
                    self.ping_stats['failed_domains'] += 1
                    # 如果ping失败，标记为无效但可能仍然保留（根据规则类型）
                    if rule_info['type'] in ['domain_block', 'hosts', 'simple_domain']:
                        is_valid = False
        
        # 根据规则类型生成三层规则
        if is_valid:
            rule_type = rule_info['type']
            domain = rule_info.get('domain', '')
            
            if rule_type == 'simple_domain' and domain:
                dns_rule = domain
                hosts_rule = f"0.0.0.0 {domain}"
                browser_rule = f"||{domain}^"
            
            elif rule_type == 'domain_block':
                browser_rule = rule_info['raw_rule']
                if domain:
                    dns_rule = domain
                    hosts_rule = f"0.0.0.0 {domain}"
            
            elif rule_type == 'whitelist':
                browser_rule = rule_info['raw_rule']
                # 白名单规则不加入DNS和Hosts
            
            elif rule_type == 'hosts':
                hosts_rule = rule_info['raw_rule']
                if domain:
                    dns_rule = domain
                    # 转换为主机规则格式
                    if not hosts_rule.startswith('0.0.0.0'):
                        parts = hosts_rule.split()
                        if len(parts) >= 2:
                            hosts_rule = f"0.0.0.0 {parts[1]}"
            
            elif rule_type in ['element_hiding', 'element_hiding_exception', 'scriptlet_injection', 'regex', 'advanced']:
                browser_rule = rule_info['raw_rule']
            
            elif rule_info['is_adblock']:
                browser_rule = rule_info['raw_rule']
        
        return dns_rule, hosts_rule, browser_rule, is_valid
    
    def process_content(self, content: str) -> Tuple[List[str], List[str], List[str]]:
        """处理整个内容，返回三层规则列表"""
        dns_rules = []
        hosts_rules = []
        browser_rules = []
        
        lines = content.split('\n')
        total_lines = len(lines)
        
        print(f"  📄 处理 {total_lines} 行...")
        
        # 使用线程池并发处理ping检查
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for line in lines:
                futures.append(executor.submit(self.process_rule_with_ping, line))
            
            for i, future in enumerate(as_completed(futures)):
                dns_rule, hosts_rule, browser_rule, is_valid = future.result()
                
                if is_valid:
                    if dns_rule:
                        dns_rules.append(dns_rule)
                    if hosts_rule:
                        hosts_rules.append(hosts_rule)
                    if browser_rule:
                        browser_rules.append(browser_rule)
                
                # 显示进度
                if (i + 1) % 1000 == 0 or (i + 1) == total_lines:
                    print(f"    └── 进度: {i + 1}/{total_lines} 行")
        
        return dns_rules, hosts_rules, browser_rules
    
    def write_file(self, filename: str, rules: List[str], header: str) -> int:
        """写入规则文件"""
        if not rules:
            return 0
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        # 写入文件
        output_file = self.base_dir / 'dist' / filename
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
            if unique_rules and not unique_rules[-1].endswith('\n'):
                f.write('\n')
        
        return len(unique_rules)
    
    def run(self) -> bool:
        """执行更新流程"""
        print("=" * 60)
        print("🚀 Adblock规则更新器 - 支持Ping检查")
        print("=" * 60)
        
        if not self.load_config():
            return False
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(parents=True, exist_ok=True)
        
        # 重置ping统计
        self.ping_stats = {
            'total_domains': 0,
            'resolved_domains': 0,
            'failed_domains': 0,
            'valid_domains': 0,
            'invalid_domains': 0
        }
        
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
        
        # 显示ping统计
        print(f"\n📡 Ping检查统计:")
        print(f"  ├── 总域名数: {self.ping_stats['total_domains']}")
        print(f"  ├── 解析成功: {self.ping_stats['resolved_domains']}")
        print(f"  ├── 解析失败: {self.ping_stats['failed_domains']}")
        print(f"  ├── 有效域名: {self.ping_stats['valid_domains']}")
        print(f"  └── 无效域名: {self.ping_stats['invalid_domains']}")
        
        # 生成时间
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        
        # 生成DNS规则文件
        print("\n📄 生成DNS规则文件...")
        dns_header = f"""# DNS规则文件 - 用于AdGuard Home/DNS服务
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(all_dns_rules)} 条
# 规则来源: sources/sources.json + sources/gz.txt
# 语法: 纯域名 (example.com)
# Ping检查: 已执行域名验证
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
# Ping检查: 已执行域名验证
# ==================================================

"""
        hosts_count = self.write_file("hosts.txt", all_hosts_rules, hosts_header)
        
        # 生成浏览器规则文件
        print("📄 生成浏览器规则文件...")
        browser_header = f"""! 浏览器规则文件 - 用于uBlock Origin/AdBlock
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(all_browser_rules)} 条
! 规则来源: sources/sources.json + sources/gz.txt
! 语法: 完整Adblock语法
! Ping检查: 已执行域名验证
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
            "ping_statistics": self.ping_stats,
            "sources_used": successful_sources,
            "sources_total": len(sorted_sources),
            "sources_failed": len(failed_sources),
            "syntax_version": "adblock_2.0",
            "features": [
                "adblock_syntax",
                "domain_validation",
                "ping_check",
                "concurrent_processing"
            ],
            "notes": "Adblock语法规则，包含域名ping检查功能",
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
        print(f"📡 域名验证: {self.ping_stats['valid_domains']}/{self.ping_stats['total_domains']} 个域名有效")
        print("\n🎯 Adblock语法特性:")
        print("  • 域名阻断: ||example.com^")
        print("  • 白名单: @@||example.com^")
        print("  • 元素隐藏: ##.ad-banner")
        print("  • 脚本注入: #$#alert('Blocked!')")
        print("  • 正则表达式: /ads.*\\.com/")
        print("  • 高级修饰符: ||example.com^$domain=example.com")
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
