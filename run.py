#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则集合器
自动从多个源收集广告过滤规则，合并去重后生成统一的过滤规则文件
"""

import os
import re
import time
import requests
import threading
import queue
from datetime import datetime
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

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
            'sources_processed': 0,
            'sources_failed': 0
        }
        
        # 线程安全的集合和队列
        self.white_rules_set = set()
        self.black_rules_set = set()
        self.lock = threading.Lock()
        
    def load_sources(self, source_type: str) -> List[str]:
        """加载规则源URL列表"""
        source_file = self.white_sources_file if source_type == 'white' else self.black_sources_file
        
        if not os.path.exists(source_file):
            # 创建默认源文件
            default_sources = self._get_default_sources(source_type)
            with open(source_file, 'w', encoding='utf-8') as f:
                for source in default_sources:
                    f.write(source + '\n')
            return default_sources
        
        sources = []
        with open(source_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    sources.append(line)
        return sources
    
    def _get_default_sources(self, source_type: str) -> List[str]:
        """获取默认规则源"""
        if source_type == 'white':
            return [
                'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt',
                'https://easylist-downloads.adblockplus.org/easylistchina.txt',
                'https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt'
            ]
        else:  # black
            return [
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt',
                'https://easylist-downloads.adblockplus.org/easylist.txt',
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt',
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt',
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt',
                'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/PopupBlocker/sections/popup.txt'
            ]
    
    def fetch_rules(self, url: str, source_type: str) -> List[str]:
        """从URL获取规则"""
        try:
            response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            response.raise_for_status()
            
            rules = []
            for line in response.text.splitlines():
                line = line.strip()
                if self._is_valid_rule(line):
                    rules.append(line)
            
            with self.lock:
                if source_type == 'white':
                    self.white_rules_set.update(rules)
                    self.stats['white_rules'] = len(self.white_rules_set)
                else:
                    self.black_rules_set.update(rules)
                    self.stats['black_rules'] = len(self.black_rules_set)
                self.stats['sources_processed'] += 1
            
            print(f"✓ 成功获取: {url} ({len(rules)} 条规则)")
            return rules
            
        except Exception as e:
            with self.lock:
                self.stats['sources_failed'] += 1
            print(f"✗ 获取失败: {url} - {str(e)}")
            return []
    
    def _is_valid_rule(self, rule: str) -> bool:
        """检查是否为有效的广告过滤规则"""
        if not rule:
            return False
        if rule.startswith('!'):  # 注释
            return False
        if rule.startswith('['):  # 头部信息
            return False
        if '##' in rule:  # 元素隐藏规则
            return True
        if rule.startswith('||') or rule.startswith('@@'):  # 域名规则
            return True
        if '^' in rule or '$' in rule:  # 包含特殊字符的规则
            return True
        if '/' in rule and '#' not in rule:  # URL路径规则
            return True
        return False
    
    def optimize_rules(self) -> List[str]:
        """优化和合并规则"""
        print("正在优化规则...")
        
        # 将集合转为列表
        white_rules = list(self.white_rules_set)
        black_rules = list(self.black_rules_set)
        
        # 去重（基于规则内容）
        unique_rules = set()
        final_rules = []
        
        # 处理白名单规则（放行规则）
        for rule in white_rules:
            if rule.startswith('@@'):
                if rule not in unique_rules:
                    unique_rules.add(rule)
                    final_rules.append(rule)
        
        # 处理黑名单规则（拦截规则）
        for rule in black_rules:
            if not rule.startswith('@@'):  # 避免重复添加放行规则
                if rule not in unique_rules:
                    unique_rules.add(rule)
                    final_rules.append(rule)
        
        print(f"规则优化完成: 总计 {len(final_rules)} 条规则")
        return final_rules
    
    def generate_readme(self, rules_count: int, sources_info: Dict) -> str:
        """生成README.md文件"""
        # 获取上海时间
        shanghai_time = datetime.utcnow().replace(tzinfo=time.utc)
        from datetime import timezone, timedelta
        shanghai_tz = timezone(timedelta(hours=8))
        update_time = shanghai_time.astimezone(shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        # 生成表格
        table_lines = []
        table_lines.append("| 类型 | 源名称 | 规则数量 | 链接 |")
        table_lines.append("|------|--------|----------|------|")
        
        # 白名单源
        for source in sources_info.get('white', []):
            table_lines.append(f"| 白名单 | {source['name']} | {source['count']} | {source['url']} |")
        
        # 黑名单源
        for source in sources_info.get('black', []):
            table_lines.append(f"| 黑名单 | {source['name']} | {source['count']} | {source['url']} |")
        
        table_content = "\n".join(table_lines)
        
        # 生成README内容
        readme_content = f"""# 🛡️ AdBlock 规则集合器

一个精准、高效的广告过滤规则集合器，自动从多个优质规则源收集和合并广告过滤规则。

## 📊 规则订阅

{table_content}

## 📅 最新更新时间

**{update_time}** (上海时间)

---

### 🔗 订阅链接

- **混合规则**: [adblock.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/adblock.txt)
- **仅黑名单**: [black_only.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black_only.txt)
- **仅白名单**: [white_only.txt](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white_only.txt)

### 📈 规则统计

- 总规则数: **{rules_count}** 条
- 白名单规则: {self.stats['white_rules']} 条
- 黑名单规则: {self.stats['black_rules']} 条
- 规则源: {self.stats['sources_processed']} 个成功, {self.stats['sources_failed']} 个失败

### ⚡ 使用说明

1. 安装广告过滤扩展（如 uBlock Origin、AdGuard）
2. 添加订阅链接到过滤器
3. 享受清爽的上网体验

### 🔄 自动更新

规则每天自动更新，确保最新的广告过滤效果。

---

*本项目仅用于学习和研究目的，请合理使用广告过滤功能。*
"""
        
        return readme_content
    
    def run(self):
        """主运行函数"""
        print("=" * 60)
        print("🛡️ AdBlock 规则集合器")
        print("=" * 60)
        
        # 加载源
        print("\n📁 加载规则源...")
        white_sources = self.load_sources('white')
        black_sources = self.load_sources('black')
        
        print(f"白名单源: {len(white_sources)} 个")
        print(f"黑名单源: {len(black_sources)} 个")
        
        # 多线程获取规则
        print("\n🌐 开始获取规则...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            # 提交白名单任务
            for url in white_sources:
                futures.append(executor.submit(self.fetch_rules, url, 'white'))
            
            # 提交黑名单任务
            for url in black_sources:
                futures.append(executor.submit(self.fetch_rules, url, 'black'))
            
            # 等待所有任务完成
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"任务执行错误: {e}")
        
        # 优化规则
        print("\n⚙️ 优化和合并规则...")
        final_rules = self.optimize_rules()
        
        # 生成规则文件头
        file_header = """! Title: AdBlock 综合过滤规则
! Description: 综合多个优质规则源，包含元素隐藏、错误拦截、横幅广告拦截、分析工具拦截、弹窗广告拦截等
! Version: {version}
! TimeUpdated: {time}
! Homepage: https://github.com/wansheng8/adblock
! Expires: 1 days
!
! 白名单规则 (放行规则)
""".format(
    version=datetime.now().strftime('%Y%m%d'),
    time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
)
        
        # 写入混合规则文件
        print(f"\n💾 写入规则文件: {self.output_file}")
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(file_header)
            f.write('\n')
            for rule in final_rules:
                f.write(rule + '\n')
        
        # 写入单独的规则文件
        white_only_file = os.path.join(self.outputs_dir, "white_only.txt")
        black_only_file = os.path.join(self.outputs_dir, "black_only.txt")
        
        with open(white_only_file, 'w', encoding='utf-8') as f:
            f.write("! 仅白名单规则\n")
            for rule in self.white_rules_set:
                f.write(rule + '\n')
        
        with open(black_only_file, 'w', encoding='utf-8') as f:
            f.write("! 仅黑名单规则\n")
            for rule in self.black_rules_set:
                if not rule.startswith('@@'):
                    f.write(rule + '\n')
        
        # 生成README
        print("\n📄 生成README.md...")
        sources_info = {
            'white': [
                {'name': 'Annoyances', 'url': 'https://github.com/AdguardTeam/FiltersRegistry', 'count': len([r for r in self.white_rules_set if r])},
                {'name': 'EasyList China', 'url': 'https://easylist-downloads.adblockplus.org/easylistchina.txt', 'count': 0},
                {'name': 'CJX Annoyance', 'url': 'https://github.com/cjx82630/cjxlist', 'count': 0}
            ],
            'black': [
                {'name': 'AdGuard Base', 'url': 'https://github.com/AdguardTeam/AdguardFilters', 'count': len([r for r in self.black_rules_set if r])},
                {'name': 'EasyList', 'url': 'https://easylist-downloads.adblockplus.org/easylist.txt', 'count': 0},
                {'name': 'Spyware Filter', 'url': 'https://github.com/AdguardTeam/AdguardFilters', 'count': 0},
                {'name': 'Mobile Ads', 'url': 'https://github.com/AdguardTeam/AdguardFilters', 'count': 0},
                {'name': 'Popup Blocker', 'url': 'https://github.com/AdguardTeam/AdguardFilters', 'count': 0}
            ]
        }
        
        readme_content = self.generate_readme(len(final_rules), sources_info)
        with open(os.path.join(self.base_dir, "README.md"), 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        # 打印统计信息
        print("\n" + "=" * 60)
        print("📊 执行完成！")
        print("=" * 60)
        print(f"✅ 白名单规则: {self.stats['white_rules']} 条")
        print(f"✅ 黑名单规则: {self.stats['black_rules']} 条")
        print(f"✅ 总规则数: {len(final_rules)} 条")
        print(f"✅ 成功源: {self.stats['sources_processed']}")
        print(f"❌ 失败源: {self.stats['sources_failed']}")
        print(f"📁 输出文件: rules/outputs/adblock.txt")
        print("=" * 60)

def main():
    """主函数"""
    collector = AdBlockRuleCollector()
    collector.run()

if __name__ == "__main__":
    main()
