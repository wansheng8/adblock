#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则集合器 - 主程序
自动收集、合并、去重广告过滤规则
"""

import os
import re
import json
import time
import requests
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置时区为上海时间
os.environ['TZ'] = 'Asia/Shanghai'
try:
    time.tzset()
except:
    pass  # Windows系统忽略

class AdblockRuleAggregator:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.sources_dir = os.path.join(self.base_dir, 'rules', 'sources')
        self.outputs_dir = os.path.join(self.base_dir, 'rules', 'outputs')
        
        # 规则分类正则表达式
        self.rule_patterns = {
            'adblock': [
                r'^!.*',  # 注释
                r'^\|\|.*\^',  # 域名规则
                r'^@@\|\|.*\^',  # 白名单
                r'^/.*/',  # 正则表达式
                r'^##.*',  # 元素隐藏
                r'^#@#.*',  # 元素隐藏白名单
                r'^\|\|.*\$.*',  # 带选项的规则
            ],
            'dns': [
                r'^0\.0\.0\.0\s+',
                r'^127\.0\.0\.1\s+',
                r'^::1\s+',
                r'^address=/.*/0\.0\.0\.0$',
                r'^server=/.*/0\.0\.0\.0$',
                r'^[a-zA-Z0-9.-]+\s+IN\s+A\s+0\.0\.0\.0',
            ],
            'hosts': [
                r'^\s*0\.0\.0\.0\s+[a-zA-Z0-9.-]+',
                r'^\s*127\.0\.0\.1\s+[a-zA-Z0-9.-]+',
                r'^\s*::1\s+[a-zA-Z0-9.-]+',
            ]
        }
        
        # 广告过滤分类
        self.ad_categories = {
            'banner': [
                r'banner', r'广告', r'ad', r'ads', r'advert',
                r'gg', r'guanggao', r'推广', r'sponsor'
            ],
            'popup': [
                r'popup', r'pop-up', r'弹窗', r'modal',
                r'overlay', r'lightbox', r'弹出'
            ],
            'tracker': [
                r'track', r'analytic', r'stat', r'监测',
                r'beacon', r'pixel', r'log', r'collect'
            ],
            'malware': [
                r'malware', r'virus', r'恶意', r'欺诈',
                r'phishing', r'钓鱼', r'exploit'
            ],
            'social': [
                r'share', r'like', r'comment', r'社交',
                r'facebook', r'twitter', r'weibo'
            ]
        }
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
    def fetch_url(self, url):
        """获取URL内容"""
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            # 检测编码
            if response.encoding is None or response.encoding == 'ISO-8859-1':
                response.encoding = 'utf-8'
                
            return response.text
        except Exception as e:
            print(f"❌ 获取 {url} 失败: {e}")
            return None
    
    def load_sources(self, filename):
        """加载规则源"""
        sources_file = os.path.join(self.sources_dir, filename)
        sources = []
        
        if os.path.exists(sources_file):
            with open(sources_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        sources.append(line)
        
        return sources
    
    def parse_rules(self, content, source_url):
        """解析规则内容"""
        rules = {
            'adblock': [],
            'dns': [],
            'hosts': [],
            'black': [],
            'white': []
        }
        
        if not content:
            return rules
            
        lines = content.split('\n')
        domain = urlparse(source_url).netloc if source_url else 'unknown'
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('!'):
                continue
                
            # 判断规则类型
            rule_added = False
            
            # Adblock规则
            for pattern in self.rule_patterns['adblock']:
                if re.match(pattern, line):
                    rules['adblock'].append(line)
                    rule_added = True
                    break
            
            if not rule_added:
                # DNS规则
                for pattern in self.rule_patterns['dns']:
                    if re.match(pattern, line):
                        rules['dns'].append(line)
                        rule_added = True
                        break
            
            if not rule_added:
                # Hosts规则
                for pattern in self.rule_patterns['hosts']:
                    if re.match(pattern, line):
                        rules['hosts'].append(line)
                        rule_added = True
                        break
            
            # 分类为黑名单或白名单
            if line.startswith('@@'):
                if line not in rules['white']:
                    rules['white'].append(line)
            else:
                if line and line not in rules['black']:
                    rules['black'].append(line)
        
        return rules
    
    def deduplicate_rules(self, rules_dict):
        """去重规则"""
        deduplicated = {}
        for rule_type, rules in rules_dict.items():
            # 去重并保持顺序
            seen = set()
            deduplicated[rule_type] = []
            for rule in rules:
                if rule not in seen:
                    seen.add(rule)
                    deduplicated[rule_type].append(rule)
        return deduplicated
    
    def categorize_ad_rules(self, rules):
        """分类广告规则"""
        categorized = {cat: [] for cat in self.ad_categories.keys()}
        categorized['other'] = []
        
        for rule in rules:
            rule_lower = rule.lower()
            matched = False
            
            for category, keywords in self.ad_categories.items():
                for keyword in keywords:
                    if re.search(keyword, rule_lower, re.IGNORECASE):
                        categorized[category].append(rule)
                        matched = True
                        break
                if matched:
                    break
            
            if not matched:
                categorized['other'].append(rule)
        
        return categorized
    
    def save_rules(self, rules_dict):
        """保存规则到文件"""
        # 确保输出目录存在
        os.makedirs(self.outputs_dir, exist_ok=True)
        
        # 保存各类型规则
        for rule_type, rules in rules_dict.items():
            if rule_type in ['adblock', 'dns', 'hosts', 'black', 'white']:
                filename = os.path.join(self.outputs_dir, f"{rule_type}.txt")
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"! Title: AdBlock {rule_type.upper()} Rules\n")
                    f.write(f"! Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"! Total rules: {len(rules)}\n")
                    f.write("! Project: https://github.com/wansheng8/adblock\n")
                    f.write("!\n")
                    
                    if rule_type == 'adblock':
                        f.write("! 元素隐藏规则\n! 横幅广告拦截\n! 弹窗广告拦截\n! 分析工具拦截\n! 错误拦截\n")
                    
                    for rule in rules:
                        f.write(f"{rule}\n")
                
                print(f"✅ 保存 {rule_type}.txt: {len(rules)} 条规则")
        
        # 保存分类统计信息
        ad_rules = rules_dict.get('adblock', [])
        categorized = self.categorize_ad_rules(ad_rules)
        
        info = {
            'update_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_rules': {
                'adblock': len(rules_dict.get('adblock', [])),
                'dns': len(rules_dict.get('dns', [])),
                'hosts': len(rules_dict.get('hosts', [])),
                'black': len(rules_dict.get('black', [])),
                'white': len(rules_dict.get('white', []))
            },
            'ad_categories': {
                category: len(rules) 
                for category, rules in categorized.items()
            },
            'source_count': {
                'black_sources': len(self.load_sources('black.txt')),
                'white_sources': len(self.load_sources('white.txt'))
            }
        }
        
        info_file = os.path.join(self.outputs_dir, 'info.json')
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 保存 info.json: {json.dumps(info, ensure_ascii=False)}")
        
        return info
    
    def generate_readme(self, info):
        """生成README.md文件"""
        readme_path = os.path.join(self.base_dir, 'README.md')
        
        # 加载源文件
        black_sources = self.load_sources('black.txt')
        white_sources = self.load_sources('white.txt')
        
        # 生成订阅链接表格
        subscription_table = "## 📥 订阅链接\n\n"
        subscription_table += "| 规则类型 | 文件 | 订阅链接 | 规则数量 |\n"
        subscription_table += "|----------|------|----------|----------|\n"
        
        raw_base = "https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs"
        
        files = [
            ("Adblock 规则", "ad.txt", "广告拦截、元素隐藏"),
            ("DNS 规则", "dns.txt", "DNS层面拦截"),
            ("Hosts 规则", "hosts.txt", "系统hosts文件"),
            ("黑名单规则", "black.txt", "完整黑名单"),
            ("白名单规则", "white.txt", "例外规则")
        ]
        
        for name, filename, desc in files:
            count = info['total_rules'].get(filename.replace('.txt', ''), 0)
            url = f"{raw_base}/{filename}"
            subscription_table += f"| {name} | `{filename}` | [订阅链接]({url}) | {count} 条 |\n"
        
        # 生成README内容
        readme_content = f"""# 🛡️ 精准超级智能广告过滤规则集合器

一个高效的广告过滤规则集合器，自动收集、合并、去重来自多个源的广告过滤规则，提供全面的广告拦截解决方案。

## ✨ 特性

- 🔄 **自动更新**：每天自动更新规则
- 🧹 **智能去重**：自动去除重复规则
- 🏷️ **规则分类**：按类型（Adblock、DNS、Hosts）分类
- ⚡ **高性能**：并发下载，快速处理
- 📊 **详细统计**：规则数量、分类统计
- 🌐 **多源支持**：支持多个规则源

{subscription_table}

## 📊 规则统计

| 分类 | 数量 | 说明 |
|------|------|------|
| 广告拦截规则 | {info['total_rules']['adblock']} | 元素隐藏、URL拦截 |
| DNS 拦截规则 | {info['total_rules']['dns']} | DNS层面广告拦截 |
| Hosts 规则 | {info['total_rules']['hosts']} | 系统hosts文件 |
| 黑名单总数 | {info['total_rules']['black']} | 总拦截规则 |
| 白名单例外 | {info['total_rules']['white']} | 不拦截规则 |

## 🎯 广告拦截类型

| 拦截类型 | 规则数量 | 说明 |
|----------|----------|------|
| 横幅广告 | {info['ad_categories']['banner']} | 页面横幅、侧边栏广告 |
| 弹窗广告 | {info['ad_categories']['popup']} | 弹窗、浮层广告 |
| 跟踪分析 | {info['ad_categories']['tracker']} | 统计、分析工具 |
| 恶意网站 | {info['ad_categories']['malware']} | 恶意软件、钓鱼网站 |
| 社交插件 | {info['ad_categories']['social']} | 社交分享按钮 |
| 其他规则 | {info['ad_categories']['other']} | 未分类规则 |

## 🔄 更新信息

**最新更新时间：** {info['update_time']} (上海时间)

规则源：{info['source_count']['black_sources']} 个黑名单源 + {info['source_count']['white_sources']} 个白名单源

---
**项目地址：** [https://github.com/wansheng8/adblock](https://github.com/wansheng8/adblock)

*⚠️ 注意：使用前请测试规则兼容性，部分规则可能影响网站正常功能*
"""
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        print(f"✅ 生成 README.md 完成")
    
    def run(self):
        """主运行函数"""
        print("🚀 开始收集广告过滤规则...")
        print(f"📁 工作目录: {self.base_dir}")
        
        # 加载源
        black_sources = self.load_sources('black.txt')
        white_sources = self.load_sources('white.txt')
        
        print(f"📥 找到 {len(black_sources)} 个黑名单源")
        print(f"📤 找到 {len(white_sources)} 个白名单源")
        
        all_rules = {
            'adblock': [],
            'dns': [],
            'hosts': [],
            'black': [],
            'white': []
        }
        
        # 并发获取规则
        with ThreadPoolExecutor(max_workers=10) as executor:
            # 获取黑名单规则
            future_to_url = {}
            for url in black_sources:
                future = executor.submit(self.fetch_url, url)
                future_to_url[future] = ('black', url)
            
            for url in white_sources:
                future = executor.submit(self.fetch_url, url)
                future_to_url[future] = ('white', url)
            
            # 处理结果
            for future in as_completed(future_to_url):
                source_type, url = future_to_url[future]
                content = future.result()
                
                if content:
                    print(f"✅ 获取成功: {url}")
                    rules = self.parse_rules(content, url)
                    
                    # 合并规则
                    for rule_type in all_rules.keys():
                        all_rules[rule_type].extend(rules[rule_type])
                else:
                    print(f"❌ 获取失败: {url}")
        
        # 去重
        print("🧹 去重处理中...")
        deduplicated_rules = self.deduplicate_rules(all_rules)
        
        # 保存规则
        print("💾 保存规则文件中...")
        info = self.save_rules(deduplicated_rules)
        
        # 生成README
        print("📝 生成README文档...")
        self.generate_readme(info)
        
        print(f"🎉 任务完成！总计处理 {sum(len(r) for r in deduplicated_rules.values())} 条规则")
        print(f"🕐 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """主函数"""
    aggregator = AdblockRuleAggregator()
    aggregator.run()

if __name__ == '__main__':
    main()
