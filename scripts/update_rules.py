#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
去广告规则自动更新脚本 - 集成白名单提取功能
作者: wansheng8
创建时间: 2024
"""

import os
import sys
import json
import time
import hashlib
import requests
import datetime
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


class RuleUpdater:
    def __init__(self, config_path: str = "sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        self.load_config()
        
    def load_config(self):
        """加载配置文件"""
        with open(self.base_dir / self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.update_freq = self.config.get('update_frequency', 8)
        self.timezone = self.config.get('timezone', 'Asia/Shanghai')
        self.language = self.config.get('language', 'zh-CN')
        self.sources = self.config.get('sources', [])
        
    def fetch_source(self, source: Dict) -> Tuple[bool, str, Dict]:
        """获取单个规则源"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/plain, */*',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(source['url'], headers=headers, timeout=45)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件
            source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 返回元数据
            meta = {
                'name': source['name'],
                'type': source.get('type', 'blacklist'),
                'url': source['url'],
                'file': str(raw_file),
                'size': len(content),
                'lines': len(content.split('\n'))
            }
            
            return True, content, meta
            
        except Exception as e:
            print(f"获取规则源 {source['name']} 失败: {str(e)}")
            return False, "", {'name': source['name'], 'error': str(e)}
    
    def parse_whitelist_rules(self, content: str) -> List[str]:
        """专门解析白名单规则"""
        whitelist_rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 提取白名单规则
            if line.startswith('@@'):
                # 验证白名单规则格式
                if self.validate_whitelist_rule(line):
                    whitelist_rules.append(line)
            elif line.startswith('#@?#'):
                # 元素隐藏白名单
                whitelist_rules.append(line)
            elif '##' in line and 'whitelist' in line.lower():
                # 包含"whitelist"的元素隐藏规则
                whitelist_rules.append(line)
        
        return whitelist_rules
    
    def parse_blacklist_rules(self, content: str) -> List[str]:
        """解析黑名单规则"""
        blacklist_rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 跳过白名单规则（会被单独处理）
            if line.startswith('@@'):
                continue
            
            # 验证黑名单规则格式
            if self.validate_rule(line):
                blacklist_rules.append(line)
        
        return blacklist_rules
    
    def extract_whitelist_from_sources(self, sources_data: List[Tuple[Dict, str, Dict]]) -> List[str]:
        """从所有规则源中提取白名单规则"""
        all_whitelist_rules = []
        
        for source, content, meta in sources_data:
            if content:
                print(f"  从 {source['name']} 提取白名单规则...")
                whitelist_rules = self.parse_whitelist_rules(content)
                
                if whitelist_rules:
                    print(f"    找到 {len(whitelist_rules)} 条白名单规则")
                    all_whitelist_rules.extend(whitelist_rules)
        
        return all_whitelist_rules
    
    def generate_header(self, rule_count: int, source_count: int, whitelist_count: int = 0) -> str:
        """生成规则文件头部信息"""
        now_beijing = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now_beijing.strftime('%Y-%m-%d %H:%M:%S')
        
        header = f"""! 标题: 去广告合并规则 - 中文版
! 描述: 自动合并的多源广告拦截规则，包含开屏广告、弹窗广告、内嵌广告等过滤
! 版本: {now_beijing.strftime('%Y%m%d.%H%M')}
! 生成时间: {update_time} (北京时间)
! 总规则数量: {rule_count}
! 黑名单规则: {rule_count - whitelist_count}
! 白名单规则: {whitelist_count}
! 规则源数量: {source_count}
! 建议更新周期: {self.update_freq} 小时
! 项目地址: https://github.com/wansheng8/adblock.git
! 作者: wansheng8
! 许可证: MIT
! 支持类型: 
!   - URL过滤规则
!   - 域名过滤规则
!   - 元素隐藏规则(CSS)
!   - 脚本过滤规则
!   - 隐私保护规则
!   - 重定向拦截规则
!   - 反跟踪规则
!   - 恶意网站拦截
!   - 挖矿脚本拦截
!   - 社交媒体插件过滤
!   - 弹窗过滤规则
!   - 视音频广告过滤
! 
! 注意: 本文件由自动化脚本生成，请勿手动修改
! 最后更新时间: {update_time}
!
"""
        return header
    
    def generate_faq_section(self) -> str:
        """生成FAQ部分"""
        faq = """
! 常见问题解答:
! 1. 规则添加后不生效？
!    - 请确保规则语法正确，浏览器已重新加载规则
!    - 检查规则是否被其他白名单规则覆盖
!    - 清除浏览器缓存后重试
!
! 2. 遇到误拦截（正常网站无法访问）？
!    - 请访问 https://github.com/wansheng8/adblock.git 提交问题
!    - 临时解决方案：添加网站到白名单 @@||example.com^
!    - 检查是否有冲突的规则
!
! 3. Hosts规则生效慢？
!    - Hosts规则需要刷新DNS缓存：Windows(ipconfig /flushdns)，macOS(sudo dscacheutil -flushcache)
!    - 重启网络服务或设备
!    - 考虑使用DNS级别的广告拦截
!
! 4. 如何自定义规则？
!    - 在规则前加感叹号 ! 注释掉不需要的规则
!    - 添加自定义规则在文件末尾
!    - 使用 @@ 前缀创建白名单例外
!
"""
        return faq
    
    def remove_duplicates(self, rules: List[str]) -> List[str]:
        """移除重复规则并排序"""
        unique_rules = []
        seen = set()
        
        for rule in rules:
            # 规范化规则进行比较（忽略大小写）
            normalized = rule.strip().lower()
            if normalized not in seen and normalized:
                seen.add(normalized)
                unique_rules.append(rule)
        
        # 排序：白名单优先，然后是域名规则，最后是复杂规则
        def rule_sort_key(r):
            if r.startswith('@@'):
                return (0, r)
            elif r.startswith('||') and '^' in r:
                return (1, r)
            elif r.startswith('|'):
                return (2, r)
            elif r.startswith('/') and r.endswith('/'):
                return (3, r)
            else:
                return (4, r)
        
        return sorted(unique_rules, key=rule_sort_key)
    
    def validate_rule(self, rule: str) -> bool:
        """检查规则是否有效"""
        # 空规则
        if not rule or rule.strip() == '':
            return False
        
        # 注释
        if rule.startswith('!'):
            return False
        
        # 检查基本语法
        patterns = [
            r'^@@?\|',  # 域名规则
            r'^\/.*\/$',  # 正则表达式
            r'^\|\|',  # 域名开始
            r'^\|',  # URL开始
            r'^\$',  # 规则选项
            r'^@@',  # 白名单
            r'^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$',  # 简单主机名
            r'^#@?#',  # 元素隐藏规则
            r'^##',  # CSS选择器
            r'^%',  # 扩展语法
            r'^\|\|.*\^$',  # 完整域名规则
            r'^\|\|.*\^.*\$',  # 带选项的规则
            r'^0\.0\.0\.0\s+',  # hosts格式
            r'^127\.0\.0\.1\s+',  # hosts格式
            r'^::1\s+',  # IPv6 hosts格式
            r'^::\s+',  # IPv6 hosts格式
            r'^#',  # 注释或CSS
        ]
        
        for pattern in patterns:
            if re.match(pattern, rule):
                return True
        
        return False
    
    def validate_whitelist_rule(self, rule: str) -> bool:
        """验证白名单规则格式"""
        # 基本验证
        if not rule or rule.startswith('!'):
            return False
        
        # 白名单规则必须以下列之一开头
        valid_prefixes = ['@@', '#@?#']
        
        if any(rule.startswith(prefix) for prefix in valid_prefixes):
            return True
        
        # 检查是否可能是修复后的规则
        if '##' in rule and ('whitelist' in rule.lower() or 'exception' in rule.lower()):
            return True
        
        return False
    
    def optimize_whitelist_rules(self, rules: List[str]) -> List[str]:
        """优化白名单规则"""
        optimized = []
        
        for rule in rules:
            # 移除不必要的通配符
            if rule.startswith('@@||*.'):
                # 将 @@||*.example.com^ 转换为 @@||example.com^
                domain = rule[6:-1] if rule.endswith('^') else rule[6:]
                if domain.startswith('*.'):
                    domain = domain[2:]
                optimized_rule = f'@@||{domain}^'
                optimized.append(optimized_rule)
            else:
                optimized.append(rule)
        
        return optimized
    
    def load_custom_whitelist(self) -> List[str]:
        """加载自定义白名单规则"""
        custom_file = self.base_dir / 'rules/whitelist_custom.txt'
        if custom_file.exists():
            with open(custom_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            rules = []
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('!'):
                    # 确保是白名单格式
                    if line.startswith('@@') or line.startswith('#@?#'):
                        rules.append(line)
                    elif line.startswith('||'):
                        rules.append(f'@@{line}')
            
            return rules
        return []
    
    def process_hosts_format(self, content: str) -> List[str]:
        """处理hosts格式规则"""
        rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            # 解析hosts格式: IP domain [domain2 ...]
            parts = line.split()
            if len(parts) >= 2:
                # 跳过IP部分，取域名
                for domain in parts[1:]:
                    if domain and not domain.startswith('#'):
                        # 转换为AdBlock格式
                        if '*' in domain:
                            # 通配符域名
                            rules.append(f'||{domain}^')
                        else:
                            rules.append(f'||{domain}^')
        
        return rules
    
    def convert_dns_to_adblock(self, content: str) -> List[str]:
        """将DNS规则转换为AdBlock格式"""
        rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            # DNS规则格式: 域名
            if re.match(r'^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$', line):
                rules.append(f'||{line}^')
            elif line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
                # hosts格式
                domain = line.split()[1]
                rules.append(f'||{domain}^')
        
        return rules
    
    def fetch_all_sources(self) -> Tuple[List[Dict], List[Tuple[Dict, str, Dict]]]:
        """获取所有规则源"""
        print("开始获取规则源...")
        
        successful_sources = []
        failed_sources = []
        sources_data = []
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        # 使用线程池并行获取
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_source = {executor.submit(self.fetch_source, source): source for source in sorted_sources}
            
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    success, content, meta = future.result()
                    if success:
                        successful_sources.append(source)
                        sources_data.append((source, content, meta))
                        print(f"✓ {source['name']}: 获取成功 ({len(content.splitlines())} 行)")
                    else:
                        failed_sources.append((source, meta.get('error', '未知错误')))
                        print(f"✗ {source['name']}: 获取失败 - {meta.get('error', '未知错误')}")
                except Exception as e:
                    failed_sources.append((source, str(e)))
                    print(f"✗ {source['name']}: 获取异常 - {str(e)}")
        
        return successful_sources, sources_data
    
    def run(self):
        """执行更新流程"""
        print(f"开始更新规则 (北京时间: {datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))})")
        print(f"规则源数量: {len([s for s in self.sources if s.get('enabled', True)])}")
        
        # 获取所有规则源
        successful_sources, sources_data = self.fetch_all_sources()
        
        if not successful_sources:
            print("错误: 所有规则源获取失败!")
            sys.exit(1)
        
        print(f"\n规则获取完成: {len(successful_sources)}/{len([s for s in self.sources if s.get('enabled', True)])} 成功")
        
        # 处理规则
        print("\n正在处理规则...")
        
        all_black_rules = []
        all_whitelist_rules = []
        
        # 从所有源中提取白名单规则
        print("1. 提取白名单规则...")
        all_whitelist_rules = self.extract_whitelist_from_sources(sources_data)
        
        # 加载自定义白名单
        custom_whitelist = self.load_custom_whitelist()
        if custom_whitelist:
            print(f"  加载自定义白名单: {len(custom_whitelist)} 条规则")
            all_whitelist_rules.extend(custom_whitelist)
        
        # 处理各类型规则
        print("2. 处理黑名单规则...")
        for source, content, meta in sources_data:
            source_type = source.get('type', 'blacklist')
            
            if source_type == 'whitelist':
                continue  # 白名单已处理
            
            print(f"  处理 {source['name']} ({source_type})...")
            
            if source_type == 'hosts':
                rules = self.process_hosts_format(content)
            elif source_type == 'dns':
                rules = self.convert_dns_to_adblock(content)
            else:
                rules = self.parse_blacklist_rules(content)
            
            # 根据类型添加到相应列表
            if source_type == 'whitelist':
                all_whitelist_rules.extend(rules)
            else:
                all_black_rules.extend(rules)
            
            print(f"    提取到 {len(rules)} 条规则")
        
        print(f"\n规则提取完成:")
        print(f"  - 黑名单规则: {len(all_black_rules)} 条")
        print(f"  - 白名单规则: {len(all_whitelist_rules)} 条")
        
        # 去重
        print("\n3. 去重和优化规则...")
        black_rules = self.remove_duplicates(all_black_rules)
        whitelist_rules = self.remove_duplicates(all_whitelist_rules)
        
        # 优化白名单规则
        whitelist_rules = self.optimize_whitelist_rules(whitelist_rules)
        
        # 验证规则
        print("4. 验证规则语法...")
        valid_black_rules = []
        invalid_black_rules = []
        
        for rule in black_rules:
            if self.validate_rule(rule):
                valid_black_rules.append(rule)
            else:
                invalid_black_rules.append(rule)
        
        valid_whitelist_rules = []
        invalid_whitelist_rules = []
        
        for rule in whitelist_rules:
            if self.validate_whitelist_rule(rule):
                valid_whitelist_rules.append(rule)
            else:
                invalid_whitelist_rules.append(rule)
        
        # 记录无效规则
        if invalid_black_rules or invalid_whitelist_rules:
            log_file = self.base_dir / 'rules/invalid_rules.log'
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"检查时间: {datetime.datetime.now()}\n")
                if invalid_black_rules:
                    f.write(f"无效黑名单规则 ({len(invalid_black_rules)}条):\n")
                    for rule in invalid_black_rules[:20]:
                        f.write(f"  {rule}\n")
                if invalid_whitelist_rules:
                    f.write(f"无效白名单规则 ({len(invalid_whitelist_rules)}条):\n")
                    for rule in invalid_whitelist_rules[:20]:
                        f.write(f"  {rule}\n")
                f.write("\n")
        
        print(f"  有效黑名单规则: {len(valid_black_rules)}/{len(black_rules)}")
        print(f"  有效白名单规则: {len(valid_whitelist_rules)}/{len(whitelist_rules)}")
        
        # 生成文件头部
        total_rules = len(valid_black_rules) + len(valid_whitelist_rules)
        header = self.generate_header(total_rules, len(successful_sources), len(valid_whitelist_rules))
        faq_section = self.generate_faq_section()
        
        # 生成黑名单文件（包含所有规则）
        print(f"\n5. 生成黑名单文件: {len(valid_black_rules)} 条规则")
        blacklist_content = header + faq_section + '\n'.join(valid_black_rules)
        
        # 生成白名单文件
        print(f"6. 生成白名单文件: {len(valid_whitelist_rules)} 条规则")
        whitelist_header = self.generate_header(len(valid_whitelist_rules), 
                                               len([s for s in successful_sources if s.get('type') == 'whitelist']),
                                               len(valid_whitelist_rules))
        
        # 添加白名单说明
        whitelist_help = """
! =============== 白名单使用说明 ===============
! 白名单规则用于避免误拦截正常网站
! 格式说明:
!   @@||example.com^          - 允许整个域名
!   @@||example.com^$script   - 仅允许脚本
!   #@?#div.ad-banner         - 允许特定元素显示
! 
! 如需添加自定义白名单，请编辑 rules/whitelist_custom.txt
! ============================================

"""
        whitelist_content = whitelist_header + whitelist_help + '\n'.join(valid_whitelist_rules)
        
        # 确保dist目录存在
        dist_dir = self.base_dir / 'dist'
        dist_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存文件
        blacklist_file = dist_dir / 'blacklist.txt'
        whitelist_file = dist_dir / 'whitelist.txt'
        
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write(blacklist_content)
        
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            f.write(whitelist_content)
        
        # 生成元数据
        metadata = {
            "last_updated": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "total_rules": total_rules,
            "blacklist_rules": len(valid_black_rules),
            "whitelist_rules": len(valid_whitelist_rules),
            "sources_used": len(successful_sources),
            "sources_failed": len(self.sources) - len(successful_sources),
            "next_update": (datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))) + 
                          datetime.timedelta(hours=self.update_freq)).isoformat(),
            "version": datetime.datetime.now().strftime('%Y%m%d.%H%M'),
            "file_sizes": {
                "blacklist.txt": os.path.getsize(blacklist_file),
                "whitelist.txt": os.path.getsize(whitelist_file)
            }
        }
        
        with open(dist_dir / 'metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # 生成统计报告
        self.generate_statistics_report(successful_sources, valid_black_rules, valid_whitelist_rules)
        
        print(f"\n✅ 更新完成!")
        print(f"📁 黑名单: {blacklist_file} ({len(valid_black_rules)} 条规则)")
        print(f"📁 白名单: {whitelist_file} ({len(valid_whitelist_rules)} 条规则)")
        print(f"📊 总规则数: {total_rules}")
        print(f"⏰ 下次更新: {metadata['next_update']}")
        
        return True
    
    def generate_statistics_report(self, successful_sources, black_rules, whitelist_rules):
        """生成统计报告"""
        report_file = self.base_dir / 'dist/statistics.md'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# 规则统计报告\n\n")
            f.write(f"生成时间: {datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))}\n\n")
            
            f.write("## 总体统计\n\n")
            f.write(f"- 总规则数: {len(black_rules) + len(whitelist_rules)}\n")
            f.write(f"- 黑名单规则: {len(black_rules)}\n")
            f.write(f"- 白名单规则: {len(whitelist_rules)}\n")
            f.write(f"- 成功规则源: {len(successful_sources)}\n\n")
            
            f.write("## 规则源详情\n\n")
            f.write("| 名称 | 类型 | 状态 |\n")
            f.write("|------|------|------|\n")
            
            for source in self.sources:
                enabled = source.get('enabled', True)
                if not enabled:
                    status = "禁用"
                else:
                    # 检查是否在成功列表中
                    is_success = any(s['name'] == source['name'] for s in successful_sources)
                    status = "成功" if is_success else "失败"
                
                f.write(f"| {source['name']} | {source.get('type', 'blacklist')} | {status} |\n")
            
            f.write("\n## 规则类型分布\n\n")
            
            # 分析规则类型
            rule_types = {
                '域名规则': 0,
                'URL规则': 0,
                '元素隐藏': 0,
                '正则表达式': 0,
                '其他': 0
            }
            
            for rule in black_rules:
                if rule.startswith('||') and '^' in rule:
                    rule_types['域名规则'] += 1
                elif rule.startswith('|'):
                    rule_types['URL规则'] += 1
                elif rule.startswith('##'):
                    rule_types['元素隐藏'] += 1
                elif rule.startswith('/') and rule.endswith('/'):
                    rule_types['正则表达式'] += 1
                else:
                    rule_types['其他'] += 1
            
            for rule_type, count in rule_types.items():
                if count > 0:
                    percentage = (count / len(black_rules)) * 100
                    f.write(f"- {rule_type}: {count} ({percentage:.1f}%)\n")
            
            f.write("\n## 常见域名统计\n\n")
            
            # 统计常见域名
            domain_pattern = r'\|\|([a-zA-Z0-9*.-]+)\.[a-zA-Z]{2,}\^'
            domains = {}
            
            for rule in black_rules:
                match = re.search(domain_pattern, rule)
                if match:
                    domain = match.group(1)
                    if domain not in ['*', 'www']:
                        if domain in domains:
                            domains[domain] += 1
                        else:
                            domains[domain] = 1
            
            # 取前20个最常见的域名
            top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:20]
            
            f.write("| 域名 | 出现次数 |\n")
            f.write("|------|----------|\n")
            for domain, count in top_domains:
                f.write(f"| {domain} | {count} |\n")


def main():
    """主函数"""
    updater = RuleUpdater()
    try:
        success = updater.run()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"更新过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
