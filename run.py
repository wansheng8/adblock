#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime
import requests

# 配置信息
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

class AdBlockGenerator:
    def __init__(self):
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 1. AdGuard基础广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# 2. NoCoin - 阻止挖矿脚本\n")
                f.write("https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt\n\n")
                f.write("# 3. EasyList - 主要广告规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 4. EasyPrivacy - 隐私保护\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 用于排除误拦的网站\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 可手动添加白名单域名（格式：@@||domain.com^）\n")
                f.write("# @@||google.com^\n")
                f.write("# @@||bing.com^\n")
    
    def download_content(self, url):
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                print(f"  第{i+1}次下载失败: {url}")
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(1)
        return None
    
    def extract_domain(self, line):
        """从规则行中提取域名"""
        line = line.strip()
        if not line or line.startswith('!'):
            return None
        
        # 移除注释
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # 匹配域名模式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',          # ||domain.com^
            r'^@@\|\|([a-zA-Z0-9.-]+)\^',        # @@||domain.com^
            r'^([a-zA-Z0-9.-]+)$',               # domain.com
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',  # 0.0.0.0 domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',            # *.domain.com
            r'^([a-zA-Z0-9.-]+)\s*#',            # domain.com # comment
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(1).lower()
                domain = re.sub(r'^www\.', '', domain)
                
                # 验证域名格式
                if self.is_valid_domain(domain):
                    return domain
        
        return None
    
    def is_valid_domain(self, domain):
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        bad_domains = ['localhost', 'local', 'broadcasthost', '0.0.0.0', '127.0.0.1']
        if domain in bad_domains:
            return False
        
        # 检查域名格式
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def parse_rule(self, line):
        """解析单条规则"""
        line = line.strip()
        if not line:
            return None, None
        
        # 白名单规则（以@@开头）
        if line.startswith('@@'):
            domain = self.extract_domain(line)
            if domain:
                return 'white', domain, line
            else:
                return 'white_rule', None, line
        
        # 黑名单规则
        else:
            domain = self.extract_domain(line)
            if domain:
                return 'black', domain, f"||{domain}^"
            elif len(line) > 3 and re.search(r'[a-zA-Z0-9]', line):
                return 'black_rule', None, line
        
        return None, None, None
    
    def process_url(self, url):
        """处理单个规则源URL"""
        print(f"  下载: {url}")
        content = self.download_content(url)
        if not content:
            return set(), set(), set(), set()
        
        black_domains = set()
        white_domains = set()
        black_lines = set()
        white_lines = set()
        
        for line in content.split('\n'):
            rule_type, domain, rule = self.parse_rule(line)
            
            if rule_type == 'black':
                black_domains.add(domain)
            elif rule_type == 'white':
                white_domains.add(domain)
                white_lines.add(rule)
            elif rule_type == 'black_rule':
                black_lines.add(rule)
            elif rule_type == 'white_rule':
                white_lines.add(rule)
        
        return black_domains, white_domains, black_lines, white_lines
    
    def load_and_process(self):
        """加载并处理所有规则源"""
        print("🔍 加载规则源...")
        
        # 读取规则源URL
        urls = []
        
        # 读取黑名单源
        with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(('black', line))
        
        # 读取白名单源
        with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(('white', line))
        
        print(f"  找到 {len(urls)} 个规则源")
        
        # 并行处理所有规则源
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for source_type, url in urls:
                future = executor.submit(self.process_url, url)
                futures.append((source_type, future))
            
            # 收集结果
            for source_type, future in futures:
                try:
                    bd, wd, bl, wl = future.result(timeout=20)
                    self.black_domains.update(bd)
                    self.white_domains.update(wd)
                    self.black_rules.update(bl)
                    self.white_rules.update(wl)
                except Exception as e:
                    print(f"  处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.black_domains):,} 个")
        print(f"   白名单域名: {len(self.white_domains):,} 个")
    
    def apply_whitelist(self):
        """应用白名单，排除误拦"""
        if not self.white_domains:
            return
        
        original_count = len(self.black_domains)
        
        # 1. 直接移除白名单中的域名
        self.black_domains -= self.white_domains
        
        # 2. 移除白名单域名的子域名
        to_remove = set()
        for black_domain in self.black_domains:
            for white_domain in self.white_domains:
                if black_domain == white_domain or black_domain.endswith(f".{white_domain}"):
                    to_remove.add(black_domain)
                    break
        
        self.black_domains -= to_remove
        
        removed = original_count - len(self.black_domains)
        if removed > 0:
            print(f"🔄 应用白名单: 移除 {removed} 个域名")
    
    def generate_files(self):
        """生成各种格式的规则文件"""
        print("📁 生成规则文件...")
        
        version = datetime.now().strftime('%Y%m%d')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 1. AdBlock格式规则 (ad.txt)
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 版本 {version}\n")
            f.write(f"! 更新时间: {timestamp}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n")
            f.write(f"! 适用于: AdGuard, uBlock Origin, AdBlock Plus\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.white_rules:
                f.write("! ========== 白名单规则 ==========\n")
                for rule in sorted(self.white_rules):
                    f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单规则
            f.write("! ========== 黑名单规则 ==========\n")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
            
            # 其他规则
            if self.black_rules:
                f.write("\n! ========== 其他规则 ==========\n")
                for rule in sorted(self.black_rules):
                    f.write(f"{rule}\n")
        
        # 2. DNS过滤规则 (dns.txt)
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write(f"# 适用于: AdGuard Home, Pi-hole, SmartDNS\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            
            for domain in sorted(self.black_domains):
                f.write(f"{domain}\n")
        
        # 3. Hosts格式规则 (hosts.txt)
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write(f"# 适用于: 系统hosts文件\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            f.write("# 本地域名\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n")
            
            for domain in sorted(self.black_domains):
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 纯黑名单规则 (black.txt)
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
        
        # 6. 规则信息文件 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'statistics': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains),
                'blacklist_rules': len(self.black_rules),
                'whitelist_rules': len(self.white_rules)
            },
            'files': {
                'ad.txt': 'AdBlock格式规则',
                'dns.txt': 'DNS过滤规则',
                'hosts.txt': 'Hosts格式规则',
                'black.txt': '纯黑名单规则',
                'white.txt': '白名单规则'
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print(f"📄 规则文件生成完成:")
        print(f"   ad.txt - AdBlock格式 ({len(self.black_domains):,}个域名)")
        print(f"   dns.txt - DNS格式 ({len(self.black_domains):,}个域名)")
        print(f"   hosts.txt - Hosts格式 ({len(self.black_domains):,}个域名)")
        print(f"   black.txt - 黑名单规则")
        print(f"   white.txt - 白名单规则")
        print(f"   info.json - 规则信息")
    
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
- 黑名单域名：{info['statistics']['blacklist_domains']:,} 个
- 白名单域名：{info['statistics']['whitelist_domains']:,} 个

---

## 最新更新时间

**{info['updated_at']}**

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("📄 README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载并处理规则源
            self.load_and_process()
            
            # 2. 应用白名单
            self.apply_whitelist()
            
            # 3. 生成规则文件
            self.generate_files()
            
            # 4. 生成README
            self.generate_readme()
            
            # 统计信息
            end_time = time.time()
            elapsed = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print("📁 规则文件: rules/outputs/")
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
        print("🔗 查看 README.md 获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
