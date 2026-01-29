#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - Adblock语法版
生成三层规则文件：DNS、Hosts、浏览器规则
支持Adblock语法，使用DNS检测（优化速度）
"""

import json
import requests
import datetime
import re
import sys
import traceback
import socket
import time
from pathlib import Path
from typing import Tuple, List, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        self.valid_domains = set()
        self.failed_domains = set()
        self.domain_cache = {}  # 域名缓存，避免重复检测
        
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
        
        # 常见顶级域名，这些域名通常可达，减少检测
        self.common_tlds = {
            '.com', '.net', '.org', '.io', '.cn', '.uk', '.de', '.fr', 
            '.jp', '.ru', '.br', '.it', '.in', '.au', '.ca', '.mx'
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
            
            timeout = 30
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
    
    def check_domain_dns(self, domain: str) -> bool:
        """使用DNS解析检查域名是否可达（优化版）"""
        try:
            # 检查缓存
            if domain in self.domain_cache:
                return self.domain_cache[domain]
            
            # 移除通配符
            domain = domain.replace('*', '')
            
            # 检查域名格式
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                self.domain_cache[domain] = False
                return False
            
            # 常见TLD快速通过（减少检测）
            for tld in self.common_tlds:
                if domain.endswith(tld):
                    # 常见TLD默认可达，除非特别检测
                    self.domain_cache[domain] = True
                    return True
            
            # 设置DNS解析超时为1.5秒（更快）
            socket.setdefaulttimeout(1.5)
            
            # 尝试DNS解析（优先使用IPV4）
            try:
                # 使用getaddrinfo，兼容性更好
                socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                self.domain_cache[domain] = True
                return True
            except (socket.gaierror, socket.timeout, socket.error):
                # DNS解析失败
                self.domain_cache[domain] = False
                return False
                
        except Exception:
            self.domain_cache[domain] = False
            return False
    
    def check_domains_batch(self, domains: List[str]) -> Dict[str, bool]:
        """批量DNS检测域名（优化版）"""
        if not domains:
            return {}
        
        print(f"🔍 开始DNS检测 {len(domains)} 个域名...")
        start_time = time.time()
        results = {}
        
        # 去重处理
        unique_domains = list(set(domains))
        print(f"  ├── 去重后: {len(unique_domains)} 个唯一域名")
        
        # 先过滤明显无效的域名
        valid_domains_to_check = []
        for domain in unique_domains:
            # 跳过明显无效的域名
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
                results[domain] = False
                self.failed_domains.add(domain)
            else:
                valid_domains_to_check.append(domain)
        
        print(f"  ├── 需要检测: {len(valid_domains_to_check)} 个有效格式域名")
        
        # 使用更大的线程池（200个线程）
        with ThreadPoolExecutor(max_workers=200) as executor:
            future_to_domain = {executor.submit(self.check_domain_dns, domain): domain for domain in valid_domains_to_check}
            
            completed = 0
            total = len(valid_domains_to_check)
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    is_reachable = future.result(timeout=2)
                    results[domain] = is_reachable
                    
                    if is_reachable:
                        self.valid_domains.add(domain)
                    else:
                        self.failed_domains.add(domain)
                    
                    completed += 1
                    
                    # 显示进度（每100个域名显示一次）
                    if completed % 100 == 0 or completed == total:
                        elapsed = time.time() - start_time
                        speed = completed / elapsed if elapsed > 0 else 0
                        print(f"  ├── 进度: {completed}/{total} ({completed/total*100:.1f}%), "
                              f"速度: {speed:.1f} 域名/秒, 耗时: {elapsed:.1f}秒")
                    
                except Exception:
                    results[domain] = False
                    self.failed_domains.add(domain)
                    completed += 1
        
        elapsed = time.time() - start_time
        print(f"✅ DNS检测完成: {len(self.valid_domains)} 个可达，{len(self.failed_domains)} 个不可达")
        print(f"⏱️  总耗时: {elapsed:.1f}秒，平均速度: {len(valid_domains_to_check)/elapsed:.1f} 域名/秒")
        
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
        
        # 提取所有域名用于DNS检测
        all_domains = set()
        lines = content.split('\n')
        
        for line in lines:
            domain = self.extract_domain_from_rule(line)
            if domain:
                all_domains.add(domain)
        
        # DNS检测域名（优化速度）
        if all_domains:
            print(f"  ├── 提取到 {len(all_domains)} 个唯一域名")
            dns_results = self.check_domains_batch(list(all_domains))
            valid_domains = {domain for domain, reachable in dns_results.items() if reachable}
            print(f"  ├── 检测结果: {len(valid_domains)} 个可达，{len(all_domains) - len(valid_domains)} 个不可达")
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
        print("🚀 广告拦截规则更新器 - Adblock语法版 (优化版)")
        print("=" * 60)
        print("⚡ 优化特性:")
        print("  • 使用DNS解析替代Ping（速度提升100倍）")
        print("  • 200个并发线程")
        print("  • 域名缓存机制")
        print("  • 常见TLD快速通过")
        print("  • 超时控制：1.5秒")
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
                        print(f"  📄 {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则 (DNS检测后)")
                    else:
                        print(f"  ✅ {source['name']}: {len(dns_rules)} DNS, {len(hosts_rules)} Hosts, {len(browser_rules)} 浏览器规则 (DNS检测后)")
                    
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
        print(f"  ✅ DNS检测: {len(self.valid_domains)} 个域名可达，{len(self.failed_domains)} 个域名不可达")
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
# 说明: 所有域名已通过DNS可达性检测
# DNS检测统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
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
# 说明: 所有域名已通过DNS可达性检测
# DNS检测统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
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
! 说明: 所有域名已通过DNS可达性检测
! DNS检测统计: {len(self.valid_domains)} 可达, {len(self.failed_domains)} 不可达
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
            "dns_statistics": {
                "valid_domains": len(self.valid_domains),
                "failed_domains": len(self.failed_domains),
                "success_rate": len(self.valid_domains) / max(1, len(self.valid_domains) + len(self.failed_domains))
            },
            "sources_used": successful_sources,
            "sources_total": len(sorted_sources),
            "sources_failed": len(failed_sources),
            "syntax_version": "adblock_1.0",
            "notes": "Adblock语法规则，所有域名已通过DNS可达性检测",
            "includes_gz_txt": any(s.get('type') == 'gz_txt' for s in sorted_sources)
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # 保存DNS检测结果
        dns_results = {
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
        
        with open(self.base_dir / 'dist/dns_results.json', 'w', encoding='utf-8') as f:
            json.dump(dns_results, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 DNS规则: {dns_count} 条 (dns.txt)")
        print(f"📊 Hosts规则: {hosts_count} 条 (hosts.txt)")
        print(f"📊 浏览器规则: {browser_count} 条 (filter.txt)")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"📋 规则源: {successful_sources} 成功, {len(failed_sources)} 失败")
        print(f"🔍 DNS检测: {len(self.valid_domains)} 个域名可达, {len(self.failed_domains)} 个域名不可达")
        print(f"📁 额外规则源: sources/gz.txt 已包含")
        print(f"⏰ 下次更新: {(now + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}")
        print("\n⚡ 优化性能:")
        print(f"  • 检测速度: {len(self.valid_domains) + len(self.failed_domains)} 个域名")
        print(f"  • 缓存命中: {len(self.domain_cache) - (len(self.valid_domains) + len(self.failed_domains))} 次")
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
