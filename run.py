#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 修复版
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
        self.black_domains = set()      # 黑名单域名
        self.white_domains = set()      # 白名单域名
        self.black_rules = set()        # 复杂黑名单规则
        self.white_rules = set()        # 复杂白名单规则
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源示例
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# AdGuard基础广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# EasyList规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# EasyPrivacy规则\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n")
        
        # 白名单源示例
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含以@@开头的规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
    
    def download_content(self, url):
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                print(f"  ⚠️ 第{i+1}次下载失败: {url}")
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(1)
        return None
    
    def extract_domain_from_rule(self, rule):
        """从规则中提取域名（更精确的方法）"""
        rule = rule.strip()
        
        # 如果是白名单规则，移除@@
        is_whitelist = rule.startswith('@@')
        if is_whitelist:
            rule = rule[2:]
        
        # 移除常见的前缀
        if rule.startswith('||'):
            rule = rule[2:]
        if rule.startswith('|'):
            rule = rule[1:]
        
        # 移除常见的后缀
        if rule.endswith('^'):
            rule = rule[:-1]
        if rule.endswith('|'):
            rule = rule[:-1]
        
        # 提取域名部分（到第一个特殊字符为止）
        domain_match = re.match(r'^([a-zA-Z0-9.-]+)', rule)
        if domain_match:
            domain = domain_match.group(1).lower()
            
            # 移除www前缀
            domain = re.sub(r'^www\.', '', domain)
            
            # 验证域名格式
            if self.is_valid_domain(domain):
                return domain, is_whitelist
        
        return None, is_whitelist
    
    def is_valid_domain(self, domain):
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
    
    def classify_rule(self, line):
        """分类规则类型"""
        line = line.strip()
        if not line:
            return None, None
        
        # 跳过注释和空行
        if line.startswith('!') or line.startswith('#'):
            return None, None
        
        # 白名单规则
        if line.startswith('@@'):
            domain, _ = self.extract_domain_from_rule(line)
            if domain:
                return 'white_domain', domain
            else:
                # 复杂白名单规则（如CSS规则等）
                return 'white_rule', line
        
        # 黑名单规则
        else:
            domain, _ = self.extract_domain_from_rule(line)
            if domain:
                return 'black_domain', domain
            else:
                # 复杂黑名单规则
                if len(line) > 3 and re.search(r'[a-zA-Z0-9]', line):
                    return 'black_rule', line
        
        return None, None
    
    def process_url(self, url, source_type):
        """处理单个规则源URL"""
        print(f"  下载: {url}")
        content = self.download_content(url)
        if not content:
            return {}, {}, {}, {}
        
        black_domains = set()
        white_domains = set()
        black_rules = set()
        white_rules = set()
        
        for line in content.split('\n'):
            rule_type, value = self.classify_rule(line)
            
            if rule_type == 'black_domain':
                black_domains.add(value)
            elif rule_type == 'white_domain':
                white_domains.add(value)
            elif rule_type == 'black_rule':
                # 确保不是白名单规则
                if not value.startswith('@@'):
                    black_rules.add(value)
            elif rule_type == 'white_rule':
                white_rules.add(value)
        
        return black_domains, white_domains, black_rules, white_rules
    
    def load_and_process_sources(self):
        """加载并处理所有规则源"""
        print("🔍 加载规则源...")
        
        # 读取所有规则源URL
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
                future = executor.submit(self.process_url, url, source_type)
                futures.append((source_type, future))
            
            # 收集结果
            processed_count = 0
            for source_type, future in futures:
                try:
                    bd, wd, br, wr = future.result(timeout=20)
                    
                    # 合并结果
                    self.black_domains.update(bd)
                    self.white_domains.update(wd)
                    self.black_rules.update(br)
                    self.white_rules.update(wr)
                    
                    processed_count += 1
                    print(f"  ✓ 处理完成 {processed_count}/{len(urls)}")
                    
                except Exception as e:
                    print(f"  ✗ 处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.black_domains):,} 个")
        print(f"   白名单域名: {len(self.white_domains):,} 个")
        print(f"   复杂规则: 黑名单 {len(self.black_rules):,} 条, 白名单 {len(self.white_rules):,} 条")
    
    def apply_whitelist(self):
        """应用白名单规则"""
        if not self.white_domains:
            print("ℹ️  没有白名单域名")
            return
        
        original_count = len(self.black_domains)
        
        # 方法1：直接移除完全匹配的白名单域名（性能最好）
        self.black_domains -= self.white_domains
        
        removed = original_count - len(self.black_domains)
        if removed > 0:
            print(f"🔄 应用白名单: 移除 {removed} 个完全匹配的域名")
    
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
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.white_rules:
                f.write("! ========== 白名单规则 ==========\n")
                for rule in sorted(self.white_rules):
                    if rule.startswith('@@'):
                        f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单域名规则
            f.write("! ========== 域名黑名单 ==========\n")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
            
            # 复杂黑名单规则
            if self.black_rules:
                f.write("\n! ========== 复杂规则 ==========\n")
                for rule in sorted(self.black_rules):
                    if not rule.startswith('@@'):  # 确保不是白名单规则
                        f.write(f"{rule}\n")
        
        # 2. DNS过滤规则 (dns.txt) - 只包含域名
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
            
            # 分组写入，每1000个域名加一个注释
            domains = sorted(self.black_domains)
            for i, domain in enumerate(domains):
                if i % 1000 == 0:
                    f.write(f"# 第 {i//1000 + 1} 组\n")
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 纯黑名单规则 (black.txt)
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 - 版本 {version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 规则数量: {len(self.white_rules):,} 条\n")
            f.write("#\n\n")
            
            for rule in sorted(self.white_rules):
                if rule.startswith('@@'):
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
            'generated_files': [
                {'name': 'ad.txt', 'description': 'AdBlock格式规则', 'domains': len(self.black_domains)},
                {'name': 'dns.txt', 'description': 'DNS过滤规则', 'domains': len(self.black_domains)},
                {'name': 'hosts.txt', 'description': 'Hosts格式规则', 'domains': len(self.black_domains)},
                {'name': 'black.txt', 'description': '纯黑名单规则', 'domains': len(self.black_domains)},
                {'name': 'white.txt', 'description': '白名单规则', 'rules': len(self.white_rules)}
            ]
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("📄 规则文件生成完成:")
        for file_info in info['generated_files']:
            if 'domains' in file_info:
                print(f"   {file_info['name']} - {file_info['description']} ({file_info['domains']:,}个域名)")
            else:
                print(f"   {file_info['name']} - {file_info['description']} ({file_info['rules']:,}条规则)")
    
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
            self.load_and_process_sources()
            
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
