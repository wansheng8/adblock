#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - Adblock语法版
生成三层规则文件：DNS、Hosts、浏览器规则
支持Adblock语法，增加Ping检测
"""

import json
import requests
import datetime
import re
import sys
import traceback
import subprocess
import time
import socket
from pathlib import Path
from typing import Tuple, List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        self.valid_domains = set()
        self.failed_domains = set()
        
        # Adblock语法模式
        self.adblock_patterns = {
            'comment': re.compile(r'^[!|#].*'),
            'whitelist': re.compile(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^'),
            'domain_block': re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^'),
            'element_hiding': re.compile(r'^##'),
            'hosts_rule': re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'),
            'regex_rule': re.compile(r'^/.*/$'),
            'modifier_rule': re.compile(r'.*\$.+'),
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
                        'format': 'adblock'
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
            
            # 保存原始文件
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
    
    def extract_domain_from_rule(self, rule: str) -> str:
        """从Adblock规则中提取域名"""
        rule = rule.strip()
        
        # 跳过注释
        if not rule or rule.startswith(('!', '#')):
            return ""
        
        # 1. 白名单规则: @@||example.com^
        match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 2. 域名阻断规则: ||example.com^
        match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule)
        if match:
            return match.group(1)
        
        # 3. Hosts规则: 0.0.0.0 example.com
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', rule)
        if match:
            return match.group(2)
        
        # 4. 简单域名
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            return rule
        
        # 5. 带修饰符的规则: ||example.com^$... 
        if '$' in rule:
            base_part = rule.split('$')[0]
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', base_part)
            if match:
                return match.group(1)
        
        return ""
    
    def ping_domain(self, domain: str) -> bool:
        """Ping检测域名是否可达"""
        try:
            # 移除通配符
            domain = domain.replace('*', '')
            
            # 检查域名格式
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                return False
            
            # 使用socket进行DNS解析测试
            try:
                socket.gethostbyname(domain)
                return True
            except socket.gaierror:
                # DNS解析失败，尝试ping
                pass
            
            # 尝试ping（只发送1个包，超时2秒）
            if sys.platform == "win32":
                # Windows
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '2000', domain],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
            else:
                # Linux/Mac
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', domain],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def ping_domains_batch(self, domains: List[str]) -> Dict[str, bool]:
        """批量Ping检测域名"""
        print(f"🔍 开始Ping检测 {len(domains)} 个域名...")
        
        results = {}
        batch_size = 50  # 每批50个域名
        total_batches = (len(domains) + batch_size - 1) // batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min((batch_num + 1) * batch_size, len(domains))
            batch_domains = domains[start_idx:end_idx]
            
            print(f"  批次 {batch_num + 1}/{total_batches}: 检测 {len(batch_domains)} 个域名")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_domain = {executor.submit(self.ping_domain, domain): domain for domain in batch_domains}
                
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        is_reachable = future.result(timeout=3)
                        results[domain] = is_reachable
                        
                        if is_reachable:
                            self.valid_domains.add(domain)
                        else:
                            self.failed_domains.add(domain)
                        
                        # 显示进度
                        processed = len(results)
                        total = len(batch_domains)
                        if processed % 10 == 0:
                            print(f"    ...已检测 {processed}/{total}")
                    
                    except Exception:
                        results[domain] = False
                        self.failed_domains.add(domain)
            
            # 批次间延迟，避免过多请求
            if batch_num < total_batches - 1:
                time.sleep(1)
        
        print(f"✅ Ping检测完成: {len(self.valid_domains)} 个可达，{len(self.failed_domains)} 个不可达")
        return results
    
    def process_rule(self, rule: str, valid_domains: Set[str]) -> Tuple[str, str, str]:
        """处理单条Adblock规则，返回三层规则"""
        rule = rule.strip()
        
        # 跳过注释
        if not rule or rule.startswith(('!', '#')):
            return "", "", ""
        
        dns_rule = ""
        hosts_rule = ""
        browser_rule = ""
        
        # 提取域名
        domain = self.extract_domain_from_rule(rule)
        
        # 如果是域名规则，检查是否在有效域名列表中
        if domain and domain not in valid_domains:
            # 域名不可达，跳过
            return "", "", ""
        
        # 1. 如果是白名单规则 (@@开头)
        if rule.startswith('@@'):
            # 白名单规则只放在浏览器规则中
            browser_rule = rule
            return "", "", browser_rule
        
        # 2. 如果是域名阻断规则 (||开头 ^结尾)
        if re.match(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^', rule):
            browser_rule = rule
            if domain:
                dns_rule = domain
                hosts_rule = f"0.0.0.0 {domain}"
            return dns_rule, hosts_rule, browser_rule
        
        # 3. 如果是Hosts规则
        if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+', rule):
            hosts_rule = rule
            if domain:
                dns_rule = domain
                browser_rule = f"||{domain}^"
            return dns_rule, hosts_rule, browser_rule
        
        # 4. 如果是元素隐藏规则
        if rule.startswith('##'):
            browser_rule = rule
            return "", "", browser_rule
        
        # 5. 如果是带修饰符的规则
        if '$' in rule:
            browser_rule = rule
            if domain and rule.startswith('||'):
                dns_rule = domain
                hosts_rule = f"0.0.0.0 {domain}"
            return dns_rule, hosts_rule, browser_rule
        
        # 6. 如果是简单域名
        if domain and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', rule):
            dns_rule = domain
            hosts_rule = f"0.0.0.0 {domain}"
            browser_rule = f"||{domain}^"
            return dns_rule, hosts_rule, browser_rule
        
        # 7. 其他规则（正则表达式等）
        browser_rule = rule
        return "", "", browser_rule
    
    def process_content(self, content: str) -> Tuple[List[str], List[str], List[str]]:
        """处理整个内容，返回三层规则列表"""
        dns_rules = []
        hosts_rules = []
        browser_rules = []
        
        # 提取所有域名用于Ping检测
        all_domains = set()
        lines = content.split('\n')
        
        for line in lines:
            domain = self.extract_domain_from_rule(line)
            if domain:
                all_domains.add(domain)
        
        # Ping检测域名
        if all_domains:
            ping_results = self.ping_domains_batch(list(all_domains))
            valid_domains = {domain for domain, reachable in ping_results.items() if reachable}
        else:
            valid_domains = set()
        
        # 处理规则
        for line in lines:
            dns_rule, hosts_rule, browser_rule = self.process_rule(line, valid_domains)
            
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
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(unique_rules))
        
        return len(unique_rules)
    
    def run(self) -> bool:
        """执行更新流程"""
        print("=" * 60)
        print("🚀 广告拦截规则更新器 - Adblock语法版 (含Ping检测)")
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
                        print(f"  📄 {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则 (Ping检测后)")
                    else:
                        print(f"  ✅ {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则 (Ping检测后)")
                    
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
        print(f"  ✅ Ping检测: {len(self.valid_domains)} 个域名可达，{len(self.failed_domains)} 个域名不可达")
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
# 语法: Adblock语法提取的纯域名
# 说明: 所有域名已通过Ping检测
# Ping统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
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
# 语法: 0.0.0.0 + 域名
# 说明: 所有域名已通过Ping检测
# Ping统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
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
! 语法: Adblock完整语法
! 说明: 所有域名已通过Ping检测
! Ping统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
! 支持语法:
!   • 域名阻断: ||example.com^
!   • 白名单: @@||example.com^
!   • 元素隐藏: ##.ad-banner
!   • 高级规则: ||example.com^$script,third-party
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
            "ping_statistics": {
                "valid_domains": len(self.valid_domains),
                "failed_domains": len(self.failed_domains),
                "ping_success_rate": len(self.valid_domains) / max(1, len(self.valid_domains) + len(self.failed_domains))
            },
            "sources_used": successful_sources,
            "sources_total": len(sorted_sources),
            "sources_failed": len(failed_sources),
            "syntax_version": "adblock_1.0",
            "notes": "Adblock语法规则，所有域名已通过Ping检测",
            "includes_gz_txt": any(s.get('type') == 'gz_txt' for s in sorted_sources)
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # 保存Ping检测结果
        ping_results = {
            "timestamp": now.isoformat(),
            "valid_domains": sorted(list(self.valid_domains)),
            "failed_domains": sorted(list(self.failed_domains)),
            "statistics": {
                "total_tested": len(self.valid_domains) + len(self.failed_domains),
                "valid_count": len(self.valid_domains),
                "failed_count": len(self.failed_domains),
                "success_rate": len(self.valid_domains) / max(1, len(self.valid_domains) + len(self.failed_domains))
            }
        }
        
        with open(self.base_dir / 'dist/ping_results.json', 'w', encoding='utf-8') as f:
            json.dump(ping_results, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 DNS规则: {dns_count} 条 (dns.txt)")
        print(f"📊 Hosts规则: {hosts_count} 条 (hosts.txt)")
        print(f"📊 浏览器规则: {browser_count} 条 (filter.txt)")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"📋 规则源: {successful_sources} 成功, {len(failed_sources)} 失败")
        print(f"🔍 Ping检测: {len(self.valid_domains)} 个域名可达, {len(self.failed_domains)} 个域名不可达")
        print(f"📁 额外规则源: sources/gz.txt 已包含")
        print(f"⏰ 下次更新: {(now + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}")
        print("\n🎯 Adblock语法规则:")
        print("  • DNS: 纯域名 (example.com)")
        print("  • Hosts: 0.0.0.0 example.com")
        print("  • 浏览器: ||example.com^  ##.ad-banner  @@||example.com^")
        print("  • 所有域名已通过Ping检测")
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
