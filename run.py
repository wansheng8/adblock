#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 极简版
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime
from typing import Set
import requests

# 配置
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 10,
    'TIMEOUT': 15,
    'RETRY': 2,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt'
}

class RuleGenerator:
    def __init__(self):
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建示例源文件
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
    
    def download(self, url):
        """下载规则"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                r = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                r.raise_for_status()
                return r.text
            except:
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(1)
        return None
    
    def parse_domain(self, line):
        """提取域名"""
        line = line.strip()
        if not line or line.startswith('!'):
            return None
        
        # 移除注释
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # 匹配域名格式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',
            r'^@@\|\|([a-zA-Z0-9.-]+)\^',
            r'^([a-zA-Z0-9.-]+)$',
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',
            r'^\*\.([a-zA-Z0-9.-]+)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(1).lower()
                domain = re.sub(r'^www\.', '', domain)
                
                # 验证域名
                if self.is_domain(domain):
                    return domain
        
        return None
    
    def is_domain(self, domain):
        """检查是否为有效域名"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        bad_domains = ['localhost', 'local', 'broadcasthost', '0.0.0.0']
        if domain in bad_domains:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def process_url(self, url):
        """处理单个URL"""
        content = self.download(url)
        if not content:
            return set(), set(), set(), set()
        
        black_domains = set()
        white_domains = set()
        black_lines = set()
        white_lines = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # 白名单
            if line.startswith('@@'):
                domain = self.parse_domain(line)
                if domain:
                    white_domains.add(domain)
                    white_lines.add(f"@@||{domain}^")
                else:
                    if len(line) > 5:
                        white_lines.add(line)
            
            # 黑名单
            else:
                domain = self.parse_domain(line)
                if domain:
                    black_domains.add(domain)
                else:
                    if len(line) > 3 and re.search(r'[a-zA-Z0-9]', line):
                        black_lines.add(line)
        
        return black_domains, white_domains, black_lines, white_lines
    
    def load_sources(self):
        """加载规则源"""
        urls = []
        
        # 黑名单源
        with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(('black', line))
        
        # 白名单源
        with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(('white', line))
        
        print(f"📥 加载 {len(urls)} 个规则源")
        return urls
    
    def run(self):
        """主流程"""
        print("=" * 50)
        print("广告过滤规则生成器")
        print("=" * 50)
        
        start = time.time()
        
        try:
            # 加载源
            urls = self.load_sources()
            
            # 并行处理
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
                futures = []
                for type_, url in urls:
                    future = executor.submit(self.process_url, url)
                    futures.append((type_, future))
                
                for type_, future in futures:
                    try:
                        bd, wd, bl, wl = future.result(timeout=20)
                        self.black_domains.update(bd)
                        self.white_domains.update(wd)
                        self.black_rules.update(bl)
                        self.white_rules.update(wl)
                    except Exception as e:
                        print(f"⚠️  处理失败: {e}")
            
            # 应用白名单
            if self.white_domains:
                self.black_domains -= self.white_domains
                # 子域名匹配
                to_remove = set()
                for black in self.black_domains:
                    for white in self.white_domains:
                        if black.endswith(f".{white}"):
                            to_remove.add(black)
                            break
                self.black_domains -= to_remove
            
            # 生成文件
            self.generate_files()
            
            # 生成README
            self.generate_readme()
            
            # 统计
            end = time.time()
            print(f"\n✅ 完成! 耗时: {end-start:.1f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print("📁 文件已保存到 rules/outputs/")
            
            return True
            
        except Exception as e:
            print(f"\n❌ 错误: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def generate_files(self):
        """生成规则文件"""
        version = datetime.now().strftime('%Y%m%d')
        time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 1. ad.txt - Adblock格式
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! Adblock Rules v{version}\n")
            f.write(f"! Updated: {time_str}\n")
            f.write(f"! Domains: {len(self.black_domains):,}\n")
            f.write("!\n")
            # 白名单
            for rule in sorted(self.white_rules):
                if 'domain=' not in rule:
                    f.write(f"{rule}\n")
            # 黑名单
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 2. dns.txt - DNS格式
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS Block List v{version}\n")
            f.write(f"# Updated: {time_str}\n")
            f.write(f"# Domains: {len(self.black_domains):,}\n\n")
            for domain in sorted(self.black_domains):
                f.write(f"{domain}\n")
        
        # 3. hosts.txt - Hosts格式
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts Block List v{version}\n")
            f.write(f"# Updated: {time_str}\n")
            f.write(f"# Domains: {len(self.black_domains):,}\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            for domain in sorted(self.black_domains):
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. black.txt - 黑名单
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. white.txt - 白名单
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
        
        # 6. info.json - 信息文件
        info = {
            'version': version,
            'updated': time_str,
            'stats': {
                'black_domains': len(self.black_domains),
                'white_domains': len(self.white_domains),
                'black_rules': len(self.black_rules),
                'white_rules': len(self.white_rules)
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
    
    def generate_readme(self):
        """生成README.md"""
        # 读取信息
        with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        # 生成README
        content = f"""# 广告过滤规则

自动更新的广告过滤规则，适用于AdGuard、AdBlock Plus、uBlock Origin、AdGuard Home、Pi-hole等。

---

## 订阅地址

| 规则类型 | 原始链接 | 加速链接 |
|:----------|:----------|:----------|
| **AdBlock规则** | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| **DNS过滤规则** | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| **Hosts规则** | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| **黑名单规则** | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| **白名单规则** | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 统计：**
- 黑名单域名：{info['stats']['black_domains']:,} 个
- 白名单域名：{info['stats']['white_domains']:,} 个

---

## 最新更新时间

**{info['updated']}**

*每日自动更新，北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(content)

if __name__ == '__main__':
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("请安装依赖: pip install requests")
        exit(1)
    
    # 运行生成器
    gen = RuleGenerator()
    success = gen.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("📄 查看 README.md 获取订阅链接")
    else:
        print("\n❌ 规则生成失败！")
