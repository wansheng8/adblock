#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - 增强语法版
支持：白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略
"""

import json
import requests
import datetime
import re
import sys
import traceback
from pathlib import Path
from typing import Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class RuleType(Enum):
    """规则类型枚举"""
    WHITELIST = "whitelist"          # 白名单 @@
    EXACT_DOMAIN = "exact_domain"    # 精确域名 
    WILDCARD = "wildcard"            # 子域/通配 ||
    CNAME = "cname"                  # CNAME拦截
    ELEMENT_HIDING = "element_hiding" # 元素隐藏 ##
    RESPONSE_POLICY = "response_policy" # 响应策略 $important, $redirect, etc.
    CATEGORY = "category"            # 分类规则 $category=


@dataclass
class ParsedRule:
    """解析后的规则对象"""
    raw_rule: str
    rule_type: RuleType
    domain: str = ""
    cname_target: str = ""
    categories: List[str] = None
    response_policy: str = ""
    priority: int = 0
    enabled: bool = True
    
    def __post_init__(self):
        if self.categories is None:
            self.categories = []


class EnhancedRuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        
        # 分类定义
        self.categories = {
            "ad": "广告拦截",
            "tracking": "跟踪防护",
            "malware": "恶意软件防护",
            "phishing": "钓鱼网站防护",
            "social": "社交媒体屏蔽",
            "porn": "成人内容屏蔽",
            "annoyance": "烦人内容屏蔽",
            "cookie": "Cookie控制",
            "privacy": "隐私保护",
            "security": "安全防护"
        }
        
        # 响应策略定义
        self.response_policies = {
            "block": "拦截",
            "allow": "允许",
            "redirect": "重定向",
            "removeparam": "移除参数",
            "replace": "替换内容",
            "csp": "内容安全策略",
            "header": "修改HTTP头",
            "important": "高优先级",
            "badfilter": "禁用其他规则"
        }
    
    def load_config(self) -> bool:
        """加载配置文件"""
        try:
            config_file = self.base_dir / self.config_path
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            self.sources = self.config.get('sources', [])
            print(f"📋 已加载 {len(self.sources)} 个规则源")
            
            # 加载分类配置
            if 'categories' in self.config:
                self.categories.update(self.config['categories'])
            
            # 加载响应策略配置
            if 'response_policies' in self.config:
                self.response_policies.update(self.config['response_policies'])
            
            return True
        except FileNotFoundError:
            print(f"❌ 配置文件不存在: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ 配置文件JSON格式错误: {e}")
            return False
    
    def parse_rule(self, rule: str) -> ParsedRule:
        """解析单条规则，识别语法类型"""
        rule = rule.strip()
        
        if not rule or rule.startswith(('!', '#')) and not rule.startswith('##'):
            return ParsedRule(rule, RuleType.EXACT_DOMAIN, enabled=False)
        
        # 1. 白名单规则 (@@开头)
        if rule.startswith('@@'):
            # 提取域名
            domain_match = re.match(r'^@@\|\|([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)\^', rule)
            if domain_match:
                return ParsedRule(
                    raw_rule=rule,
                    rule_type=RuleType.WHITELIST,
                    domain=domain_match.group(1),
                    priority=100  # 白名单高优先级
                )
        
        # 2. 子域/通配规则 (||开头 ^结尾)
        if rule.startswith('||') and rule.endswith('^'):
            domain = rule[2:-1]
            if self.is_valid_domain(domain):
                return ParsedRule(
                    raw_rule=rule,
                    rule_type=RuleType.WILDCARD,
                    domain=domain,
                    priority=50
                )
        
        # 3. CNAME拦截规则 (包含$cname)
        if '$cname' in rule.lower():
            # 提取基础域名
            base_rule = rule.split('$')[0]
            if base_rule.startswith('||') and base_rule.endswith('^'):
                domain = base_rule[2:-1]
                
                # 提取CNAME目标
                cname_match = re.search(r'\$cname(?:=([^,\s]+))?', rule, re.IGNORECASE)
                cname_target = cname_match.group(1) if cname_match else ""
                
                return ParsedRule(
                    raw_rule=rule,
                    rule_type=RuleType.CNAME,
                    domain=domain,
                    cname_target=cname_target,
                    priority=80
                )
        
        # 4. 响应策略规则 (包含$important, $redirect等)
        response_policy = ""
        for policy in self.response_policies.keys():
            if f'${policy}' in rule.lower():
                response_policy = policy
                break
        
        if response_policy:
            # 提取基础规则
            base_rule = rule.split('$')[0]
            domain = ""
            
            if base_rule.startswith('||') and base_rule.endswith('^'):
                domain = base_rule[2:-1]
            elif self.is_valid_domain(base_rule):
                domain = base_rule
            
            return ParsedRule(
                raw_rule=rule,
                rule_type=RuleType.RESPONSE_POLICY,
                domain=domain,
                response_policy=response_policy,
                priority=70
            )
        
        # 5. 分类规则 (包含$category=)
        category_match = re.search(r'\$category=([^,\s]+)', rule)
        if category_match:
            categories = category_match.group(1).split('|')
            
            # 提取基础规则
            base_part = rule.split('$')[0]
            domain = ""
            
            if base_part.startswith('||') and base_part.endswith('^'):
                domain = base_part[2:-1]
            elif self.is_valid_domain(base_part):
                domain = base_part
            
            return ParsedRule(
                raw_rule=rule,
                rule_type=RuleType.CATEGORY,
                domain=domain,
                categories=categories,
                priority=60
            )
        
        # 6. 元素隐藏规则 (##开头)
        if rule.startswith('##'):
            return ParsedRule(
                raw_rule=rule,
                rule_type=RuleType.ELEMENT_HIDING,
                priority=30
            )
        
        # 7. 精确域名规则
        if self.is_valid_domain(rule) and not any(c in rule for c in ['^', '|', '$', '@', '#']):
            return ParsedRule(
                raw_rule=rule,
                rule_type=RuleType.EXACT_DOMAIN,
                domain=rule,
                priority=40
            )
        
        # 8. 其他规则 (可能是带修饰符的规则)
        # 尝试提取域名
        domain = self.extract_domain(rule)
        if domain:
            return ParsedRule(
                raw_rule=rule,
                rule_type=RuleType.EXACT_DOMAIN,
                domain=domain,
                priority=20
            )
        
        # 9. 无法识别的规则
        return ParsedRule(
            raw_rule=rule,
            rule_type=RuleType.EXACT_DOMAIN,
            enabled=False
        )
    
    def is_valid_domain(self, domain: str) -> bool:
        """验证域名格式"""
        if not domain:
            return False
        
        # 基本域名格式验证
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        # 允许顶级域名如 localhost, local
        if domain in ['localhost', 'local']:
            return True
        
        # 允许IP地址
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return True
        
        return bool(re.match(pattern, domain))
    
    def extract_domain(self, rule: str) -> str:
        """从规则中提取域名"""
        # 移除修饰符
        if '$' in rule:
            rule = rule.split('$')[0]
        
        # 尝试匹配各种域名模式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)\^',  # ||domain.com^
            r'^@@\|\|([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)\^', # @@||domain.com^
            r'^([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)$',        # domain.com
            r'^0\.0\.0\.0\s+([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+)$', # 0.0.0.0 domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                return match.group(1)
        
        return ""
    
    def fetch_source(self, source: Dict[str, Any]) -> Tuple[bool, str]:
        """获取规则源内容"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/plain,*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache'
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
    
    def process_content(self, content: str) -> Dict[str, List[ParsedRule]]:
        """处理内容，分类规则"""
        rules_by_type = {
            RuleType.WHITELIST: [],
            RuleType.EXACT_DOMAIN: [],
            RuleType.WILDCARD: [],
            RuleType.CNAME: [],
            RuleType.ELEMENT_HIDING: [],
            RuleType.RESPONSE_POLICY: [],
            RuleType.CATEGORY: []
        }
        
        lines = content.split('\n')
        rule_count = 0
        
        for line in lines:
            parsed = self.parse_rule(line)
            
            if parsed.enabled and parsed.raw_rule:
                rules_by_type[parsed.rule_type].append(parsed)
                rule_count += 1
        
        print(f"  📊 解析了 {rule_count} 条规则")
        
        # 统计各类型规则
        for rule_type, rules in rules_by_type.items():
            if rules:
                print(f"    ├── {rule_type.value}: {len(rules)} 条")
        
        return rules_by_type
    
    def generate_dns_rules(self, rules_by_type: Dict[str, List[ParsedRule]]) -> List[str]:
        """生成DNS规则"""
        dns_rules = []
        
        # 添加精确域名
        for rule in rules_by_type[RuleType.EXACT_DOMAIN]:
            if rule.domain:
                dns_rules.append(rule.domain)
        
        # 添加通配域名（转换为子域名）
        for rule in rules_by_type[RuleType.WILDCARD]:
            if rule.domain:
                dns_rules.append(rule.domain)
        
        # 添加CNAME拦截域名
        for rule in rules_by_type[RuleType.CNAME]:
            if rule.domain:
                dns_rules.append(rule.domain)
        
        # 添加分类域名
        for rule in rules_by_type[RuleType.CATEGORY]:
            if rule.domain:
                dns_rules.append(rule.domain)
        
        # 添加响应策略域名（排除白名单）
        for rule in rules_by_type[RuleType.RESPONSE_POLICY]:
            if rule.domain and rule.response_policy != 'allow':
                dns_rules.append(rule.domain)
        
        return sorted(set(dns_rules))
    
    def generate_hosts_rules(self, rules_by_type: Dict[str, List[ParsedRule]]) -> List[str]:
        """生成Hosts规则"""
        hosts_rules = []
        
        # 收集所有需要拦截的域名
        all_domains = set()
        
        # 添加精确域名
        for rule in rules_by_type[RuleType.EXACT_DOMAIN]:
            if rule.domain:
                all_domains.add(rule.domain)
        
        # 添加通配域名
        for rule in rules_by_type[RuleType.WILDCARD]:
            if rule.domain:
                all_domains.add(rule.domain)
        
        # 添加CNAME域名
        for rule in rules_by_type[RuleType.CNAME]:
            if rule.domain:
                all_domains.add(rule.domain)
        
        # 添加分类域名
        for rule in rules_by_type[RuleType.CATEGORY]:
            if rule.domain:
                all_domains.add(rule.domain)
        
        # 添加响应策略域名（排除白名单）
        for rule in rules_by_type[RuleType.RESPONSE_POLICY]:
            if rule.domain and rule.response_policy != 'allow':
                all_domains.add(rule.domain)
        
        # 排除白名单域名
        whitelist_domains = set()
        for rule in rules_by_type[RuleType.WHITELIST]:
            if rule.domain:
                whitelist_domains.add(rule.domain)
        
        filtered_domains = all_domains - whitelist_domains
        
        # 转换为hosts格式
        for domain in sorted(filtered_domains):
            hosts_rules.append(f"0.0.0.0 {domain}")
        
        return hosts_rules
    
    def generate_browser_rules(self, rules_by_type: Dict[str, List[ParsedRule]]) -> List[str]:
        """生成浏览器规则"""
        browser_rules = []
        
        # 按优先级排序所有规则
        all_parsed_rules = []
        for rule_list in rules_by_type.values():
            all_parsed_rules.extend(rule_list)
        
        # 按优先级降序排序（高优先级在前）
        all_parsed_rules.sort(key=lambda x: x.priority, reverse=True)
        
        # 转换为原始规则
        browser_rules = [rule.raw_rule for rule in all_parsed_rules]
        
        return browser_rules
    
    def write_rules_file(self, filename: str, rules: List[str], header: str) -> int:
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
    
    def generate_metadata(self, dns_count: int, hosts_count: int, browser_count: int) -> Dict[str, Any]:
        """生成元数据"""
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        
        return {
            "last_updated": now.isoformat(),
            "syntax_version": "2.0-enhanced",
            "rule_counts": {
                "dns_rules": dns_count,
                "hosts_rules": hosts_count,
                "browser_rules": browser_count,
                "total_rules": dns_count + hosts_count + browser_count
            },
            "rule_types_supported": [
                "whitelist (@@)",
                "exact_domain (pure domain)",
                "wildcard (||domain^)",
                "cname_intercept ($cname)",
                "element_hiding (##)",
                "category_based ($category=)",
                "response_policy ($important, $redirect, etc.)"
            ],
            "categories_available": list(self.categories.keys()),
            "response_policies_available": list(self.response_policies.keys()),
            "next_update": (now + datetime.timedelta(hours=8)).isoformat(),
            "generator": "Enhanced Rule Updater v2.0"
        }
    
    def run(self) -> bool:
        """执行更新流程"""
        print("=" * 60)
        print("🚀 增强版广告拦截规则更新器")
        print("支持：白名单、精确域名、子域/通配、CNAME拦截、分类规则、响应策略")
        print("=" * 60)
        
        if not self.load_config():
            return False
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(parents=True, exist_ok=True)
        
        all_rules_by_type = {
            RuleType.WHITELIST: [],
            RuleType.EXACT_DOMAIN: [],
            RuleType.WILDCARD: [],
            RuleType.CNAME: [],
            RuleType.ELEMENT_HIDING: [],
            RuleType.RESPONSE_POLICY: [],
            RuleType.CATEGORY: []
        }
        
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
                    rules_by_type = self.process_content(content)
                    
                    # 合并规则
                    for rule_type in all_rules_by_type.keys():
                        all_rules_by_type[rule_type].extend(rules_by_type[rule_type])
                    
                    successful_sources += 1
                    print(f"  ✅ {source['name']}: 处理完成")
                except Exception as e:
                    print(f"  ⚠️  {source['name']}: 处理失败 - {str(e)}")
                    failed_sources.append(source['name'])
            else:
                print(f"  ❌ {source['name']}: 获取失败")
                failed_sources.append(source['name'])
        
        print(f"\n📊 规则获取完成:")
        print(f"  ✅ 成功: {successful_sources}/{len(sorted_sources)}")
        
        if failed_sources:
            print(f"  ❌ 失败: {len(failed_sources)}")
        
        # 生成三层规则
        print("\n📄 生成三层规则文件...")
        
        # 生成DNS规则
        dns_rules = self.generate_dns_rules(all_rules_by_type)
        # 生成Hosts规则
        hosts_rules = self.generate_hosts_rules(all_rules_by_type)
        # 生成浏览器规则
        browser_rules = self.generate_browser_rules(all_rules_by_type)
        
        # 生成时间
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        
        # 1. 生成DNS规则文件
        dns_header = f"""# DNS规则文件 - 增强语法版
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(dns_rules)} 条
# 语法: 纯域名格式，用于DNS层面拦截
# 包含: 精确域名、通配域名、CNAME域名、分类域名
# 排除: 白名单域名
# ==================================================

"""
        dns_count = self.write_rules_file("dns.txt", dns_rules, dns_header)
        
        # 2. 生成Hosts规则文件
        hosts_header = f"""# Hosts规则文件 - 增强语法版
# 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
# 规则数量: {len(hosts_rules)} 条
# 语法: 0.0.0.0 + 域名格式，用于系统hosts文件
# 包含: 所有需要拦截的域名
# 排除: 白名单域名
# ==================================================

"""
        hosts_count = self.write_rules_file("hosts.txt", hosts_rules, hosts_header)
        
        # 3. 生成浏览器规则文件
        browser_header = f"""! 浏览器规则文件 - 增强语法版
! 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (北京时间)
! 规则数量: {len(browser_rules)} 条
! 语法支持:
!   • 白名单: @@||domain.com^
!   • 精确域名: domain.com
!   • 子域/通配: ||domain.com^
!   • CNAME拦截: ||domain.com^$cname=target.com
!   • 元素隐藏: ##.ad-banner
!   • 分类规则: ||domain.com^$category=ad|tracking
!   • 响应策略: ||domain.com^$important, $redirect, etc.
! ==================================================

"""
        browser_count = self.write_rules_file("filter.txt", browser_rules, browser_header)
        
        # 生成元数据
        metadata = self.generate_metadata(dns_count, hosts_count, browser_count)
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # 生成规则类型统计
        stats = {}
        for rule_type, rules in all_rules_by_type.items():
            if rules:
                stats[rule_type.value] = len(rules)
        
        with open(self.base_dir / 'dist/rule_stats.json', 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 DNS规则: {dns_count} 条 (dns.txt)")
        print(f"📊 Hosts规则: {hosts_count} 条 (hosts.txt)")
        print(f"📊 浏览器规则: {browser_count} 条 (filter.txt)")
        print(f"📊 总计: {dns_count + hosts_count + browser_count} 条")
        print(f"📋 规则源: {successful_sources} 成功, {len(failed_sources)} 失败")
        print("\n🎯 增强语法规则:")
        print("  • 白名单: @@||example.com^")
        print("  • 精确域名: example.com")
        print("  • 子域/通配: ||example.com^")
        print("  • CNAME拦截: ||example.com^$cname=target.com")
        print("  • 元素隐藏: ##.ad-banner")
        print("  • 分类规则: ||example.com^$category=ad|tracking")
        print("  • 响应策略: ||example.com^$important, $redirect")
        print("=" * 60)
        
        return successful_sources > 0


def main():
    updater = EnhancedRuleUpdater()
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
