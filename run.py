#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则集合器 - 优化版
自动从多个源收集广告过滤规则，合并去重后生成统一的过滤规则文件
"""

import os
import re
import time
import requests
import threading
import queue
from datetime import datetime, timedelta, timezone
from typing import List, Set, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import hashlib
import gzip
import json

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdBlockRuleCollector:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.sources_dir = os.path.join(self.base_dir, "rules", "sources")
        self.outputs_dir = os.path.join(self.base_dir, "rules", "outputs")
        self.white_sources_file = os.path.join(self.sources_dir, "white.txt")
        self.black_sources_file = os.path.join(self.sources_dir, "black.txt")
        self.output_file = os.path.join(self.outputs_dir, "adblock.txt")
        self.stats_file = os.path.join(self.outputs_dir, "stats.json")
        
        # 确保目录存在
        os.makedirs(self.sources_dir, exist_ok=True)
        os.makedirs(self.outputs_dir, exist_ok=True)
        
        # 用户代理
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # 规则统计
        self.stats = {
            'white_rules': 0,
            'black_rules': 0,
            'total_rules': 0,
            'sources_processed': 0,
            'sources_failed': 0,
            'duplicate_removed': 0,
            'white_sources': [],
            'black_sources': []
        }
        
        # 内存优化：使用集合存储规则哈希，而不是完整规则
        self.white_rules_hashes = set()
        self.black_rules_hashes = set()
        self.lock = threading.Lock()
        
        # 临时文件存储
        self.temp_dir = os.path.join(self.base_dir, "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
        
    def load_sources(self, source_type: str) -> List[Tuple[str, str]]:
        """加载规则源URL列表，返回(名称, URL)元组列表"""
        source_file = self.white_sources_file if source_type == 'white' else self.black_sources_file
        
        if not os.path.exists(source_file):
            # 创建默认源文件
            default_sources = self._get_default_sources(source_type)
            with open(source_file, 'w', encoding='utf-8') as f:
                for name, url in default_sources:
                    f.write(f"{name} {url}\n")
            return default_sources
        
        sources = []
        with open(source_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        name, url = parts
                        sources.append((name.strip(), url.strip()))
                    else:
                        # 如果没有名称，使用URL的一部分作为名称
                        url = line
                        name = self._extract_name_from_url(url)
                        sources.append((name, url))
        return sources
    
    def _extract_name_from_url(self, url: str) -> str:
        """从URL提取名称"""
        # 移除协议
        if '://' in url:
            url = url.split('://')[1]
        
        # 移除路径中的通用部分
        name = url.replace('raw.githubusercontent.com/', '') \
                 .replace('github.com/', '') \
                 .replace('easylist-downloads.adblockplus.org/', '') \
                 .replace('easylist.to/', '') \
                 .replace('secure.fanboy.co.nz/', '')
        
        # 限制长度
        if len(name) > 50:
            name = name[:50] + "..."
        
        return name
    
    def _get_default_sources(self, source_type: str) -> List[Tuple[str, str]]:
        """获取默认规则源"""
        if source_type == 'white':
            return [
                ("Annoyances", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt"),
                ("EasyList China", "https://easylist-downloads.adblockplus.org/easylistchina.txt"),
                ("CJX Annoyance", "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt")
            ]
        else:  # black
            return [
                ("AdGuard Base", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt"),
                ("EasyList", "https://easylist.to/easylist/easylist.txt"),
                ("Spyware Filter", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt"),
                ("Fanboy Annoyance", "https://secure.fanboy.co.nz/fanboy-annoyance.txt"),
                ("Anti-AD", "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt"),
                ("REIJI AD Collection", "https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DNS.txt")
            ]
    
    def fetch_rules(self, source_name: str, url: str, source_type: str) -> Dict:
        """从URL获取规则"""
        temp_file = os.path.join(self.temp_dir, f"{hashlib.md5(url.encode()).hexdigest()}.txt")
        
        try:
            # 先尝试从缓存读取（如果文件存在且小于1小时）
            if os.path.exists(temp_file):
                file_age = time.time() - os.path.getmtime(temp_file)
                if file_age < 3600:  # 1小时缓存
                    with open(temp_file, 'r', encoding='utf-8') as f:
                        rules = [line.strip() for line in f if line.strip()]
                    
                    with self.lock:
                        if source_type == 'white':
                            self.stats['white_rules'] += len(rules)
                        else:
                            self.stats['black_rules'] += len(rules)
                        self.stats['sources_processed'] += 1
                    
                    print(f"✓ 从缓存读取: {source_name} ({len(rules)} 条规则)")
                    return {'name': source_name, 'url': url, 'count': len(rules), 'rules': rules}
            
            # 从网络获取
            print(f"正在获取: {source_name}")
            response = requests.get(url, headers=self.headers, timeout=60, verify=False)
            response.raise_for_status()
            
            rules = []
            seen_hashes = set()
            
            for line in response.text.splitlines():
                line = line.strip()
                if self._is_valid_rule(line):
                    # 计算哈希用于去重
                    rule_hash = hashlib.md5(line.encode()).hexdigest()
                    
                    # 检查是否已存在
                    with self.lock:
                        if source_type == 'white':
                            if rule_hash in self.white_rules_hashes:
                                self.stats['duplicate_removed'] += 1
                                continue
                            self.white_rules_hashes.add(rule_hash)
                        else:
                            if rule_hash in self.black_rules_hashes:
                                self.stats['duplicate_removed'] += 1
                                continue
                            self.black_rules_hashes.add(rule_hash)
                    
                    rules.append(line)
            
            # 保存到缓存
            with open(temp_file, 'w', encoding='utf-8') as f:
                for rule in rules:
                    f.write(rule + '\n')
            
            with self.lock:
                if source_type == 'white':
                    self.stats['white_rules'] += len(rules)
                else:
                    self.stats['black_rules'] += len(rules)
                self.stats['sources_processed'] += 1
            
            print(f"✓ 成功获取: {source_name} ({len(rules)} 条规则)")
            return {'name': source_name, 'url': url, 'count': len(rules), 'rules': rules}
            
        except requests.exceptions.Timeout:
            error_msg = "请求超时"
        except requests.exceptions.ConnectionError:
            error_msg = "连接错误"
        except Exception as e:
            error_msg = str(e)
        
        with self.lock:
            self.stats['sources_failed'] += 1
        print(f"✗ 获取失败: {source_name} - {error_msg}")
        return {'name': source_name, 'url': url, 'count': 0, 'rules': [], 'error': error_msg}
    
    def _is_valid_rule(self, rule: str) -> bool:
        """检查是否为有效的广告过滤规则"""
        if not rule or len(rule) > 1000:  # 防止过长的规则
            return False
        
        # 跳过注释和元数据
        if rule.startswith('!'):
            return False
        if rule.startswith('[') or rule.startswith('#'):
            return False
        if '[' in rule and ']' in rule:  # 可能包含无效字符
            return False
        
        # 检查规则类型
        rule_lower = rule.lower()
        
        # 元素隐藏规则
        if '##' in rule:
            return True
        
        # 域名规则
        if rule.startswith('||') or rule.startswith('@@'):
            return True
        
        # URL过滤规则
        if '^' in rule or '$' in rule:
            return True
        
        # 包含特定广告关键词
        ad_keywords = ['ad', 'ads', 'advert', 'banner', 'popup', 'track', 'analytics', 
                      'cookie', 'sponsor', 'promo', 'doubleclick', 'googlead']
        for keyword in ad_keywords:
            if keyword in rule_lower:
                return True
        
        return False
    
    def _is_domain_rule(self, rule: str) -> bool:
        """检查是否为域名规则"""
        return rule.startswith('||') or rule.startswith('@@')
    
    def _is_element_hiding_rule(self, rule: str) -> bool:
        """检查是否为元素隐藏规则"""
        return '##' in rule
    
    def _is_url_filter_rule(self, rule: str) -> bool:
        """检查是否为URL过滤规则"""
        return '^' in rule or '$' in rule
    
    def process_and_write_rules(self, all_rules_data: List[Dict]):
        """处理和写入规则文件"""
        print("\n⚙️ 处理和合并规则...")
        
        # 分阶段处理规则
        white_rules = []
        black_rules = []
        
        for source_data in all_rules_data:
            if 'rules' in source_data:
                for rule in source_data['rules']:
                    if rule.startswith('@@'):  # 白名单规则
                        white_rules.append(rule)
                    else:  # 黑名单规则
                        black_rules.append(rule)
        
        # 去重
        white_rules = list(dict.fromkeys(white_rules))  # 保持顺序的去重
        black_rules = list(dict.fromkeys(black_rules))
        
        # 分组排序：域名规则 -> URL规则 -> 元素隐藏规则
        white_domain_rules = [r for r in white_rules if self._is_domain_rule(r)]
        white_url_rules = [r for r in white_rules if self._is_url_filter_rule(r) and not self._is_domain_rule(r)]
        white_element_rules = [r for r in white_rules if self._is_element_hiding_rule(r)]
        
        black_domain_rules = [r for r in black_rules if self._is_domain_rule(r)]
        black_url_rules = [r for r in black_rules if self._is_url_filter_rule(r) and not self._is_domain_rule(r)]
        black_element_rules = [r for r in black_rules if self._is_element_hiding_rule(r)]
        
        # 合并规则
        final_rules = []
        final_rules.extend(white_domain_rules)
        final_rules.extend(white_url_rules)
        final_rules.extend(white_element_rules)
        final_rules.extend(black_domain_rules)
        final_rules.extend(black_url_rules)
        final_rules.extend(black_element_rules)
        
        self.stats['total_rules'] = len(final_rules)
        
        print(f"白名单规则: {len(white_rules)} 条")
        print(f"黑名单规则: {len(black_rules)} 条")
        print(f"总规则数: {len(final_rules)} 条")
        
        # 生成规则文件头
        shanghai_tz = timezone(timedelta(hours=8))
        update_time = datetime.now(shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        file_header = f"""! Title: AdBlock 综合过滤规则
! Description: 综合多个优质规则源，包含元素隐藏、错误拦截、横幅广告拦截、分析工具拦截、弹窗广告拦截等
! Version: {datetime.now().strftime('%Y%m%d')}
! TimeUpdated: {update_time} (上海时间)
! Homepage: https://github.com/wansheng8/adblock
! Expires: 1 days
! Total rules: {len(final_rules)}
! Memory optimized: yes
!
! 规则来源:
"""
        
        # 添加规则源信息
        for source in all_rules_data:
            if 'rules' in source:
                file_header += f"! - {source['name']}: {source['count']} 条规则\n"
        
        file_header += "\n! 白名单规则 (放行规则)\n"
        
        # 写入混合规则文件
        print(f"\n💾 写入规则文件: {self.output_file}")
        
        # 分批写入，避免内存问题
        batch_size = 50000
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(file_header)
            
            # 分批写入规则
            for i in range(0, len(final_rules), batch_size):
                batch = final_rules[i:i + batch_size]
                for rule in batch:
                    f.write(rule + '\n')
                
                if i + batch_size < len(final_rules):
                    print(f"  已写入 {i + batch_size}/{len(final_rules)} 条规则...")
        
        # 写入压缩版本
        self._create_compressed_version()
        
        # 写入单独的规则文件
        print("\n📁 生成其他格式规则文件...")
        
        with open(os.path.join(self.outputs_dir, "white_only.txt"), 'w', encoding='utf-8') as f:
            f.write("! 仅白名单规则\n")
            for rule in white_rules:
                f.write(rule + '\n')
        
        with open(os.path.join(self.outputs_dir, "black_only.txt"), 'w', encoding='utf-8') as f:
            f.write("! 仅黑名单规则\n")
            for rule in black_rules:
                f.write(rule + '\n')
        
        # 写入统计文件
        with open(self.stats_file, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, ensure_ascii=False, indent=2)
    
    def _create_compressed_version(self):
        """创建压缩版本"""
        try:
            with open(self.output_file, 'rb') as f_in:
                with gzip.open(self.output_file + '.gz', 'wb') as f_out:
                    f_out.writelines(f_in)
            print(f"✓ 已创建压缩版本: {self.output_file}.gz")
        except Exception as e:
            print(f"✗ 创建压缩版本失败: {e}")
    
    def generate_readme(self, all_rules_data: List[Dict]) -> str:
        """生成README.md文件"""
        # 获取上海时间
        shanghai_tz = timezone(timedelta(hours=8))
        update_time = datetime.now(shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        # 生成表格
        table_lines = []
        table_lines.append("| 类型 | 源名称 | 规则数量 | 状态 | 链接 |")
        table_lines.append("|------|--------|----------|------|------|")
        
        # 统计成功的源
        success_count = 0
        fail_count = 0
        
        for source in all_rules_data:
            if 'error' in source:
                status = "❌ 失败"
                count_str = "0"
                fail_count += 1
            else:
                status = "✅ 成功"
                count_str = str(source['count'])
                success_count += 1
            
            # 缩短URL显示
            display_url = source['url']
            if len(display_url) > 50:
                display_url = display_url[:50] + "..."
            
            source_type = "白名单" if any(x in source['name'].lower() for x in ['annoy', 'whitelist']) else "黑名单"
            
            table_lines.append(f"| {source_type} | {source['name']} | {count_str} | {status} | [{display_url}]({source['url']}) |")
        
        table_content = "\n".join(table_lines)
        
        # 生成README内容
        readme_content = f"""# 🛡️ AdBlock 规则集合器

一个精准、高效的广告过滤规则集合器，自动从多个优质规则源收集和合并广告过滤规则。

## 📊 规则订阅

{table_content}

## 📅 最新更新时间

**{update_time}** (上海时间)

## 📈 统计信息

- ✅ 成功源: **{success_count}** 个
- ❌ 失败源: **{fail_count}** 个
- 📝 总规则数: **{self.stats['total_rules']:,}** 条
- 🎯 白名单规则: {self.stats['white_rules']:,} 条
- 🛡️ 黑名单规则: {self.stats['black_rules']:,} 条
- 🔄 重复移除: {self.stats['duplicate_removed']:,} 条

## 🔗 订阅链接

### 主要订阅
- **混合规则 (推荐)**: [adblock.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/adblock.txt)
- **压缩版本**: [adblock.txt.gz](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/adblock.txt.gz)

### 专用订阅
- **仅黑名单**: [black_only.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black_only.txt)
- **仅白名单**: [white_only.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white_only.txt)

### 📊 统计文件
- [stats.json](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/stats.json)

## ⚡ 使用说明

1. 安装广告过滤扩展（如 uBlock Origin、AdGuard）
2. 添加订阅链接到过滤器
3. 建议使用压缩版本以减少流量
4. 享受清爽的上网体验

## 🔄 自动更新

规则每天自动更新，确保最新的广告过滤效果。

## 🚀 性能优化

- 使用多线程下载
- 智能规则去重
- 内存优化处理
- 支持超大规则集
- 提供压缩版本

---

*本项目仅用于学习和研究目的，请合理使用广告过滤功能。*
"""
        
        return readme_content
    
    def run(self):
        """主运行函数"""
        print("=" * 70)
        print("🛡️  AdBlock 规则集合器 v2.0 - 优化版")
        print("=" * 70)
        
        # 清理临时文件（超过1天的）
        self._cleanup_temp_files()
        
        # 加载源
        print("\n📁 加载规则源...")
        white_sources = self.load_sources('white')
        black_sources = self.load_sources('black')
        
        print(f"白名单源: {len(white_sources)} 个")
        print(f"黑名单源: {len(black_sources)} 个")
        
        # 多线程获取规则
        print("\n🌐 开始获取规则...")
        all_rules_data = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:  # 减少线程数以避免限制
            futures = []
            
            # 提交白名单任务
            for name, url in white_sources:
                futures.append(executor.submit(self.fetch_rules, name, url, 'white'))
            
            # 提交黑名单任务
            for name, url in black_sources:
                futures.append(executor.submit(self.fetch_rules, name, url, 'black'))
            
            # 等待所有任务完成，显示进度
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    all_rules_data.append(result)
                    completed += 1
                    print(f"进度: {completed}/{total} ({completed/total*100:.1f}%)")
                except Exception as e:
                    print(f"任务执行错误: {e}")
                    completed += 1
        
        # 处理并写入规则
        self.process_and_write_rules(all_rules_data)
        
        # 生成README
        print("\n📄 生成README.md...")
        readme_content = self.generate_readme(all_rules_data)
        
        try:
            with open(os.path.join(self.base_dir, "README.md"), 'w', encoding='utf-8') as f:
                f.write(readme_content)
            print("✅ README.md 生成成功")
        except Exception as e:
            print(f"❌ 生成README.md失败: {e}")
            # 尝试创建简化的README
            with open(os.path.join(self.base_dir, "README.md"), 'w', encoding='utf-8') as f:
                f.write(f"# AdBlock Rules\n\n更新于: {datetime.now().strftime('%Y-%m-%d')}\n")
        
        # 打印统计信息
        print("\n" + "=" * 70)
        print("🎉 执行完成！")
        print("=" * 70)
        print(f"📊 统计信息:")
        print(f"  总规则数: {self.stats['total_rules']:,}")
        print(f"  成功源: {self.stats['sources_processed']}")
        print(f"  失败源: {self.stats['sources_failed']}")
        print(f"  重复移除: {self.stats['duplicate_removed']:,}")
        print(f"📁 输出文件:")
        print(f"  {self.output_file}")
        print(f"  {self.output_file}.gz")
        print("=" * 70)
    
    def _cleanup_temp_files(self):
        """清理临时文件"""
        try:
            for filename in os.listdir(self.temp_dir):
                filepath = os.path.join(self.temp_dir, filename)
                if os.path.isfile(filepath):
                    file_age = time.time() - os.path.getmtime(filepath)
                    if file_age > 86400:  # 24小时
                        os.remove(filepath)
        except Exception as e:
            print(f"清理临时文件时出错: {e}")

def main():
    """主函数"""
    try:
        collector = AdBlockRuleCollector()
        collector.run()
        return 0
    except MemoryError:
        print("❌ 内存不足，请减少规则源或增加内存")
        return 1
    except Exception as e:
        print(f"❌ 程序执行出错: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
