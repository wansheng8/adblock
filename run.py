#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdBlock 规则集合器 - 美化版
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
        }
        
        # 内存优化
        self.white_rules_hashes = set()
        self.black_rules_hashes = set()
        self.lock = threading.Lock()
        
        # 临时文件存储
        self.temp_dir = os.path.join(self.base_dir, "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def load_sources(self, source_type: str) -> List[Tuple[str, str]]:
        """加载规则源URL列表"""
        source_file = self.white_sources_file if source_type == 'white' else self.black_sources_file
        
        if not os.path.exists(source_file):
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
                        url = line
                        name = self._extract_name_from_url(url)
                        sources.append((name, url))
        return sources
    
    def _extract_name_from_url(self, url: str) -> str:
        """从URL提取名称"""
        if '://' in url:
            url = url.split('://')[1]
        
        name = url.replace('raw.githubusercontent.com/', '') \
                 .replace('github.com/', '') \
                 .replace('easylist-downloads.adblockplus.org/', '') \
                 .replace('easylist.to/', '') \
                 .replace('secure.fanboy.co.nz/', '')
        
        if len(name) > 50:
            name = name[:50] + "..."
        
        return name
    
    def _get_default_sources(self, source_type: str) -> List[Tuple[str, str]]:
        """获取默认规则源"""
        if source_type == 'white':
            return [
                ("Annoyances", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt"),
                ("EasyList China", "https://easylist-downloads.adblockplus.org/easylistchina.txt"),
            ]
        else:
            return [
                ("AdGuard Base", "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt"),
                ("EasyList", "https://easylist.to/easylist/easylist.txt"),
                ("Anti-AD", "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt"),
            ]
    
    def fetch_rules(self, source_name: str, url: str, source_type: str) -> Dict:
        """从URL获取规则"""
        temp_file = os.path.join(self.temp_dir, f"{hashlib.md5(url.encode()).hexdigest()}.txt")
        
        try:
            # 缓存检查
            if os.path.exists(temp_file):
                file_age = time.time() - os.path.getmtime(temp_file)
                if file_age < 3600:
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
            
            # 网络获取
            print(f"正在获取: {source_name}")
            response = requests.get(url, headers=self.headers, timeout=60, verify=False)
            response.raise_for_status()
            
            rules = []
            for line in response.text.splitlines():
                line = line.strip()
                if self._is_valid_rule(line):
                    rule_hash = hashlib.md5(line.encode()).hexdigest()
                    
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
            
            # 保存缓存
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
            
        except Exception as e:
            with self.lock:
                self.stats['sources_failed'] += 1
            print(f"✗ 获取失败: {source_name} - {str(e)}")
            return {'name': source_name, 'url': url, 'count': 0, 'rules': [], 'error': str(e)}
    
    def _is_valid_rule(self, rule: str) -> bool:
        """检查是否为有效的广告过滤规则"""
        if not rule or len(rule) > 1000:
            return False
        
        if rule.startswith('!') or rule.startswith('[') or rule.startswith('#'):
            return False
        
        if '##' in rule:
            return True
        
        if rule.startswith('||') or rule.startswith('@@'):
            return True
        
        if '^' in rule or '$' in rule:
            return True
        
        return False
    
    def process_and_write_rules(self, all_rules_data: List[Dict]):
        """处理和写入规则文件"""
        print("\n⚙️ 处理和合并规则...")
        
        white_rules = []
        black_rules = []
        
        for source_data in all_rules_data:
            if 'rules' in source_data:
                for rule in source_data['rules']:
                    if rule.startswith('@@'):
                        white_rules.append(rule)
                    else:
                        black_rules.append(rule)
        
        white_rules = list(dict.fromkeys(white_rules))
        black_rules = list(dict.fromkeys(black_rules))
        
        final_rules = []
        final_rules.extend(white_rules)
        final_rules.extend(black_rules)
        
        self.stats['total_rules'] = len(final_rules)
        
        print(f"白名单规则: {len(white_rules)} 条")
        print(f"黑名单规则: {len(black_rules)} 条")
        print(f"总规则数: {len(final_rules)} 条")
        
        # 生成规则文件头
        shanghai_tz = timezone(timedelta(hours=8))
        update_time = datetime.now(shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
        
        file_header = f"""! Title: AdBlock 综合过滤规则
! Description: 精准超级智能广告过滤规则集合器
! Version: {datetime.now().strftime('%Y%m%d')}
! TimeUpdated: {update_time} (上海时间)
! Homepage: https://github.com/wansheng8/adblock
! Expires: 1 days
! Total rules: {len(final_rules)}
!
"""
        
        # 写入混合规则文件
        print(f"\n💾 写入规则文件...")
        
        batch_size = 50000
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(file_header)
            
            for i in range(0, len(final_rules), batch_size):
                batch = final_rules[i:i + batch_size]
                for rule in batch:
                    f.write(rule + '\n')
        
        # 写入压缩版本
        try:
            with open(self.output_file, 'rb') as f_in:
                with gzip.open(self.output_file + '.gz', 'wb') as f_out:
                    f_out.writelines(f_in)
            print(f"✓ 已创建压缩版本")
        except Exception as e:
            print(f"✗ 创建压缩版本失败: {e}")
        
        # 写入单独的规则文件
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
    
    def generate_readme(self, all_rules_data: List[Dict]) -> str:
        """生成美化的README.md文件 - 只有三个部分"""
        # 获取上海时间
        shanghai_tz = timezone(timedelta(hours=8))
        update_time = datetime.now(shanghai_tz).strftime('%Y年%m月%d日 %H:%M:%S')
        total_rules = self.stats['total_rules']
        
        # 第一部分：名称介绍
        intro = f"""# 🚀 AdBlock 超级智能广告过滤规则

<div align="center">

## 精准 • 智能 • 高效 • 自动更新

**一个自动收集、合并和优化多源广告过滤规则的智能工具集合器**

✨ **核心特性** ✨

- 🛡️ **全面防护**: 广告拦截、隐私保护、恶意网站防护
- ⚡ **智能优化**: 自动去重、规则分类、性能优化
- 🔄 **自动更新**: 每日自动同步最新规则源
- 📊 **规则丰富**: 当前包含 **{total_rules:,}** 条过滤规则
- 🎯 **精准过滤**: 元素隐藏、域名拦截、弹窗屏蔽、分析工具拦截

</div>
"""
        
        # 第二部分：订阅链接（美化表格）
        subscriptions = """## 📥 订阅链接

<div align="center">

| 规则类型 | 说明 | 订阅链接 |
|:---|:---|:---|
| 🎯 **混合规则** | 完整过滤规则集<br>（白名单在前，黑名单在后） | [`adblock.txt`](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/adblock.txt) |
| 🗜️ **压缩版本** | GZIP压缩格式<br>节省流量，加载更快 | [`adblock.txt.gz`](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/adblock.txt.gz) |
| ⚫ **仅黑名单** | 只包含拦截规则<br>（广告域名、跟踪器等） | [`black_only.txt`](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black_only.txt) |
| ⚪ **仅白名单** | 只包含放行规则<br>（误拦截修复、必要功能） | [`white_only.txt`](https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white_only.txt) |

</div>

<div align="center">

**💡 使用建议**: 普通用户推荐使用 **混合规则**，专业用户可根据需要选择其他版本

</div>
"""
        
        # 第三部分：更新时间
        update_time_section = f"""## 🕐 最新更新时间

<div align="center">

### 🎯 最后更新时间

**{update_time}** (上海时间)

---

### 📊 更新状态

![规则总数](https://img.shields.io/badge/规则总数-{total_rules:,}-blue)
![更新时间](https://img.shields.io/badge/最后更新-{update_time.split()[0]}-green)
![自动更新](https://img.shields.io/badge/自动更新-已启用-success)

</div>

<div align="center">

*✨ 规则每日自动更新，确保广告过滤效果始终最佳 ✨*

</div>
"""
        
        # 组合三个部分
        readme_content = f"""{intro}

{subscriptions}

{update_time_section}
"""
        
        return readme_content
    
    def run(self):
        """主运行函数"""
        print("=" * 70)
        print("🛡️  AdBlock 规则集合器 - 美化版")
        print("=" * 70)
        
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
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for name, url in white_sources:
                futures.append(executor.submit(self.fetch_rules, name, url, 'white'))
            
            for name, url in black_sources:
                futures.append(executor.submit(self.fetch_rules, name, url, 'black'))
            
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    all_rules_data.append(result)
                    completed += 1
                    print(f"进度: {completed}/{total}")
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
        
        # 打印统计信息
        print("\n" + "=" * 70)
        print("🎉 执行完成！")
        print("=" * 70)
        print(f"📊 总规则数: {self.stats['total_rules']:,}")
        print(f"📁 输出文件已生成")
        print("=" * 70)
    
    def _cleanup_temp_files(self):
        """清理临时文件"""
        try:
            for filename in os.listdir(self.temp_dir):
                filepath = os.path.join(self.temp_dir, filename)
                if os.path.isfile(filepath):
                    file_age = time.time() - os.path.getmtime(filepath)
                    if file_age > 86400:
                        os.remove(filepath)
        except:
            pass

def main():
    """主函数"""
    try:
        collector = AdBlockRuleCollector()
        collector.run()
        return 0
    except Exception as e:
        print(f"❌ 程序执行出错: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
