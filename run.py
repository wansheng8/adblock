#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 确保黑白名单生成
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime, timedelta
from typing import Set, List, Tuple, Optional, Dict
import requests

# 配置信息
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 5,
    'TIMEOUT': 30,
    'RETRY': 2,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    'PROTECTED_DOMAINS': {
        'google.com', 'github.com', 'microsoft.com', 'apple.com',
        'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'weibo.com',
        'zhihu.com', 'bilibili.com', '163.com', '126.com'
    }
}

class AdBlockGenerator:
    def __init__(self):
        # 核心数据集合
        self.all_black_domains = set()       # 所有黑名单域名
        self.all_white_domains = set()       # 所有白名单域名
        self.all_black_rules = []            # 所有黑名单规则（保持顺序）
        self.all_white_rules = []            # 所有白名单规则（保持顺序）
        
        # 最终输出集合
        self.final_black_domains = set()     # 最终黑名单域名（应用白名单后）
        self.final_white_rules = []          # 最终白名单规则
        
        # 统计
        self.stats = {
            'total_lines_processed': 0,
            'black_domains_found': 0,
            'white_domains_found': 0,
            'black_rules_found': 0,
            'white_rules_found': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 1. AdGuard基础广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# 2. EasyList规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 3. 中文规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n\n")
                f.write("# 4. EasyPrivacy规则\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
        
        # 白名单源
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含白名单规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 重要网站白名单\n")
                f.write("@@||google.com^\n")
                f.write("@@||github.com^\n")
                f.write("@@||baidu.com^\n")
                f.write("@@||qq.com^\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain, */*',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                print(f"  ⚠️ 下载失败 {url} (尝试 {i+1}/{CONFIG['RETRY']}): {str(e)[:100]}")
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(2)
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        local_domains = {
            'localhost', 'local', 'broadcasthost',
            '0.0.0.0', '127.0.0.1', '::1',
            'ip6-localhost', 'ip6-loopback'
        }
        if domain in local_domains:
            return False
        
        # 排除IP地址
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # 检查域名格式
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 检查每个部分
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def extract_domain_from_rule(self, rule: str) -> Tuple[Optional[str], bool]:
        """从规则中提取域名并判断是否为白名单"""
        rule = rule.strip()
        if not rule:
            return None, False
        
        # 判断是否是白名单规则
        is_whitelist = rule.startswith('@@')
        
        # 尝试匹配域名模式
        patterns = [
            # AdBlock格式
            (r'^@@\|\|([a-zA-Z0-9.-]+)\^', True),   # @@||domain.com^
            (r'^\|\|([a-zA-Z0-9.-]+)\^', False),    # ||domain.com^
            
            # 简单域名格式
            (r'^@@([a-zA-Z0-9.-]+)$', True),        # @@domain.com
            (r'^([a-zA-Z0-9.-]+)$', False),         # domain.com
            
            # Hosts格式
            (r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)', False),  # 0.0.0.0 domain.com
            
            # 通配符格式
            (r'^@@\*\.([a-zA-Z0-9.-]+)', True),     # @@*.domain.com
            (r'^\*\.([a-zA-Z0-9.-]+)', False),      # *.domain.com
        ]
        
        for pattern, is_wl in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = match.group(1).lower().strip()
                
                # 标准化域名
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, False
    
    def is_whitelist_rule(self, rule: str) -> bool:
        """判断是否是白名单规则"""
        rule = rule.strip()
        
        # 简单判断：以@@开头的规则通常是白名单
        if rule.startswith('@@'):
            return True
        
        # 特殊白名单格式
        whitelist_patterns = [
            r'^@@\|\|',
            r'^@@\*\.',
            r'^@@http',
            r'^@@https',
            r'^@@/.*/$'  # CSS白名单规则
        ]
        
        for pattern in whitelist_patterns:
            if re.match(pattern, rule):
                return True
        
        return False
    
    def process_rule(self, rule: str, source_url: str = "") -> Tuple[bool, Optional[str]]:
        """处理单条规则"""
        self.stats['total_lines_processed'] += 1
        
        rule = rule.strip()
        if not rule:
            return False, None
        
        # 跳过注释
        if rule.startswith('!') or rule.startswith('#'):
            return False, None
        
        # 判断是否是白名单规则
        is_whitelist = self.is_whitelist_rule(rule)
        
        # 尝试提取域名
        domain, extracted_is_whitelist = self.extract_domain_from_rule(rule)
        
        # 如果提取成功
        if domain:
            if is_whitelist or extracted_is_whitelist:
                # 白名单域名
                self.all_white_domains.add(domain)
                self.all_white_rules.append(rule)
                self.stats['white_domains_found'] += 1
                return True, domain
            else:
                # 黑名单域名
                self.all_black_domains.add(domain)
                self.stats['black_domains_found'] += 1
                return False, domain
        else:
            # 无法提取域名的规则
            if is_whitelist:
                # 复杂白名单规则
                self.all_white_rules.append(rule)
                self.stats['white_rules_found'] += 1
                return True, None
            else:
                # 复杂黑名单规则
                if len(rule) > 3:
                    self.all_black_rules.append(rule)
                    self.stats['black_rules_found'] += 1
                return False, None
        
        return False, None
    
    def process_url(self, url: str, is_whitelist_source: bool = False):
        """处理单个规则源URL"""
        print(f"  📥 处理: {url}")
        content = self.download_content(url)
        if not content:
            print(f"  ❌ 下载失败: {url}")
            return
        
        lines_processed = 0
        domains_found = 0
        
        for line in content.split('\n'):
            lines_processed += 1
            processed, domain = self.process_rule(line, url)
            if processed and domain:
                domains_found += 1
        
        print(f"  ✓ 完成: {lines_processed} 行, 提取 {domains_found} 个域名")
    
    def load_and_process_sources(self):
        """加载并处理所有规则源"""
        print("🔍 加载规则源...")
        
        # 读取黑名单源
        blacklist_urls = []
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist_urls.append(line)
        
        # 读取白名单源
        whitelist_urls = []
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 如果是URL，则下载
                        if line.startswith('http'):
                            whitelist_urls.append(line)
                        else:
                            # 直接处理白名单规则
                            self.process_rule(line, "local_whitelist")
        
        print(f"  黑名单源: {len(blacklist_urls)} 个")
        print(f"  白名单源: {len(whitelist_urls)} 个")
        
        # 并行处理所有URL
        all_urls = [(url, False) for url in blacklist_urls] + [(url, True) for url in whitelist_urls]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url, is_whitelist in all_urls:
                future = executor.submit(self.process_url, url, is_whitelist)
                futures.append(future)
            
            # 等待所有任务完成
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=30)
                    completed += 1
                    print(f"  ✅ [{completed}/{len(all_urls)}] 处理完成")
                except Exception as e:
                    print(f"  ❌ 处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.all_black_domains):,} 个")
        print(f"   白名单域名: {len(self.all_white_domains):,} 个")
        print(f"   黑名单规则: {len(self.all_black_rules):,} 条")
        print(f"   白名单规则: {len(self.all_white_rules):,} 条")
    
    def apply_whitelist(self):
        """应用白名单"""
        print("🔄 应用白名单...")
        
        # 最终黑名单 = 所有黑名单 - 所有白名单
        self.final_black_domains = self.all_black_domains.copy()
        self.final_white_rules = self.all_white_rules.copy()
        
        original_count = len(self.final_black_domains)
        
        # 移除完全匹配的白名单域名
        domains_to_remove = set()
        for domain in self.final_black_domains:
            if domain in self.all_white_domains:
                domains_to_remove.add(domain)
        
        self.final_black_domains -= domains_to_remove
        
        # 保护重要域名（不会被白名单移除）
        for protected in CONFIG['PROTECTED_DOMAINS']:
            if protected in self.all_white_domains and protected in domains_to_remove:
                domains_to_remove.remove(protected)
                self.final_black_domains.add(protected)
                print(f"  🛡️  保护重要域名: {protected}")
        
        removed = original_count - len(self.final_black_domains)
        print(f"  移除 {removed} 个白名单域名")
        print(f"  最终黑名单域名: {len(self.final_black_domains):,} 个")
    
    def generate_adblock_file(self):
        """生成AdBlock格式规则文件"""
        print("📄 生成AdBlock规则 (ad.txt)...")
        
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            # 头部信息
            f.write(f"! 广告过滤规则 - 版本 {version}\n")
            f.write(f"! 更新时间: {timestamp} (北京时间)\n")
            f.write(f"! 黑名单域名: {len(self.final_black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.all_white_domains):,} 个\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.final_white_rules:
                f.write("! ====== 白名单规则 ======\n")
                # 去重并排序
                unique_white_rules = sorted(set(self.final_white_rules))
                for rule in unique_white_rules:
                    f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单域名规则
            f.write("! ====== 域名黑名单 ======\n")
            for domain in sorted(self.final_black_domains):
                f.write(f"||{domain}^\n")
            
            # 复杂黑名单规则
            if self.all_black_rules:
                f.write("\n! ====== 复杂规则 ======\n")
                # 去重并排序
                unique_black_rules = sorted(set(self.all_black_rules))
                for rule in unique_black_rules:
                    f.write(f"{rule}\n")
    
    def generate_dns_file(self):
        """生成DNS格式规则文件"""
        print("📄 生成DNS规则 (dns.txt)...")
        
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            
            for domain in sorted(self.final_black_domains):
                f.write(f"{domain}\n")
    
    def generate_hosts_file(self):
        """生成Hosts格式规则文件"""
        print("📄 生成Hosts规则 (hosts.txt)...")
        
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            f.write("# 本地域名\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n\n")
            
            # 分批写入
            batch_size = 1000
            domains = sorted(self.final_black_domains)
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                f.write(f"# 第 {i//batch_size + 1} 组 ({len(batch)}个域名)\n")
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("\n")
    
    def generate_blacklist_file(self):
        """生成纯黑名单文件"""
        print("📄 生成黑名单规则 (black.txt)...")
        
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 黑名单规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 域名数量: {len(self.final_black_domains):,} 个\n")
            f.write("#\n\n")
            
            for domain in sorted(self.final_black_domains):
                f.write(f"||{domain}^\n")
    
    def generate_whitelist_file(self):
        """生成纯白名单文件"""
        print("📄 生成白名单规则 (white.txt)...")
        
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # 去重并排序白名单规则
        unique_white_rules = sorted(set(self.final_white_rules))
        
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp} (北京时间)\n")
            f.write(f"# 规则数量: {len(unique_white_rules):,} 条\n")
            f.write("#\n\n")
            
            # 先写域名白名单
            domain_whitelist = [r for r in unique_white_rules if r.startswith('@@||') and r.endswith('^')]
            other_whitelist = [r for r in unique_white_rules if r not in domain_whitelist]
            
            if domain_whitelist:
                f.write("# 域名白名单\n")
                for rule in domain_whitelist:
                    f.write(f"{rule}\n")
                f.write("\n")
            
            if other_whitelist:
                f.write("# 其他白名单规则\n")
                for rule in other_whitelist:
                    f.write(f"{rule}\n")
    
    def generate_info_file(self):
        """生成信息文件"""
        print("📄 生成规则信息 (info.json)...")
        
        beijing_time = self.get_beijing_time()
        
        info = {
            'version': beijing_time.strftime('%Y%m%d'),
            'updated_at': beijing_time.strftime('%Y-%m-%d %H:%M:%S'),
            'timezone': 'Asia/Shanghai (UTC+8)',
            'statistics': {
                'total_lines_processed': self.stats['total_lines_processed'],
                'blacklist_domains_found': self.stats['black_domains_found'],
                'whitelist_domains_found': self.stats['white_domains_found'],
                'blacklist_rules_found': self.stats['black_rules_found'],
                'whitelist_rules_found': self.stats['white_rules_found'],
                'final_blacklist_domains': len(self.final_black_domains),
                'final_whitelist_rules': len(set(self.final_white_rules))
            },
            'files': {
                'ad.txt': 'AdBlock格式规则',
                'dns.txt': 'DNS过滤规则',
                'hosts.txt': 'Hosts格式规则',
                'black.txt': '纯黑名单规则',
                'white.txt': '纯白名单规则'
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_readme(self):
        """生成README.md文件"""
        print("📖 生成README.md...")
        
        # 读取规则信息
        with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        # 生成订阅链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        # 生成README内容
        readme = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于AdGuard、uBlock Origin、AdBlock Plus、AdGuard Home、Pi-hole等。

---

## 订阅地址

| 规则类型 | 规则说明 | 原始链接 | 加速链接 |
|:---------|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| **白名单规则** | 排除误拦域名 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 统计：**
- 黑名单域名：{info['statistics']['final_blacklist_domains']:,} 个
- 白名单规则：{info['statistics']['final_whitelist_rules']:,} 条

---

## 最新更新时间

**{info['updated_at']}** (北京时间)

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
    
    def get_beijing_time(self) -> datetime:
        """获取北京时间"""
        try:
            from datetime import timezone
            utc_now = datetime.now(timezone.utc)
            beijing_time = utc_now + timedelta(hours=8)
            return beijing_time
        except:
            return datetime.now()
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载并处理规则源
            self.load_and_process_sources()
            
            # 2. 应用白名单
            self.apply_whitelist()
            
            # 3. 生成所有规则文件
            self.generate_adblock_file()
            self.generate_dns_file()
            self.generate_hosts_file()
            self.generate_blacklist_file()
            self.generate_whitelist_file()
            self.generate_info_file()
            
            # 4. 生成README
            self.generate_readme()
            
            # 统计信息
            end_time = time.time()
            elapsed = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 最终黑名单域名: {len(self.final_black_domains):,}个")
            print(f"📊 白名单规则: {len(set(self.final_white_rules)):,}条")
            print("📁 生成的规则文件:")
            print("  - rules/outputs/ad.txt")
            print("  - rules/outputs/dns.txt")
            print("  - rules/outputs/hosts.txt")
            print("  - rules/outputs/black.txt")
            print("  - rules/outputs/white.txt")
            print("  - rules/outputs/info.json")
            print("📖 使用说明: README.md")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    # 运行生成器
    generator = AdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
