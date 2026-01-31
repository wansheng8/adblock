#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 简化白名单版
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime
from typing import Set, List, Optional
import requests

# 配置信息
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 5,
    'TIMEOUT': 25,
    'RETRY': 2,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 真正的白名单域名（只放行这些）
    'TRUE_WHITELIST_DOMAINS': {
        'google.com',
        'github.com',
        'microsoft.com',
        'apple.com',
        'baidu.com',
        'qq.com',
        'zhihu.com',
        'bilibili.com',
        'weibo.com',
        'taobao.com'
    }
}

class SimpleAdBlockGenerator:
    def __init__(self):
        self.black_domains = set()      # 黑名单域名
        self.final_blacklist = set()    # 最终黑名单
        
        # 统计
        self.stats = {
            'lines_processed': 0,
            'domains_found': 0,
            'whitelist_ignored': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源 - 只使用2-3个主要源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源\n")
                f.write("# 只使用2-3个主要源\n\n")
                f.write("# AdGuard广告规则（主要源）\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# EasyList规则（主要源）\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 中文规则（可选）\n")
                f.write("# https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n")
        
        # 白名单源 - 只放行真正需要的
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只放行真正需要的域名\n\n")
                f.write("# 重要网站主域名\n")
                f.write("google.com\n")
                f.write("github.com\n")
                f.write("baidu.com\n")
                f.write("qq.com\n")
                f.write("zhihu.com\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain, */*'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(2)
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        if domain in ['localhost', 'local', 'broadcasthost', '0.0.0.0', '127.0.0.1', '::1']:
            return False
        
        # 排除IP地址
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # 基本域名格式
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 检查每部分
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def extract_domain_from_line(self, line: str) -> Optional[str]:
        """从行中提取域名"""
        line = line.strip()
        if not line:
            return None
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#'):
            return None
        
        # 如果是白名单规则（以@@开头），直接跳过
        if line.startswith('@@'):
            self.stats['whitelist_ignored'] += 1
            return None
        
        # 简单的域名提取
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',    # ||domain.com^
            r'^([a-zA-Z0-9.-]+)\^$',       # domain.com^
            r'^([a-zA-Z0-9.-]+)$',         # domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',      # *.domain.com
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',  # 0.0.0.0 domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(1).lower().strip()
                
                # 移除www前缀
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                if self.is_valid_domain(domain):
                    return domain
        
        return None
    
    def process_blacklist_url(self, url: str):
        """处理黑名单URL"""
        print(f"  📥 处理黑名单: {url}")
        content = self.download_content(url)
        if not content:
            return
        
        domains_found = 0
        for line in content.split('\n'):
            self.stats['lines_processed'] += 1
            
            domain = self.extract_domain_from_line(line)
            if domain:
                # 如果这个域名在我们的白名单中，跳过
                if domain in CONFIG['TRUE_WHITELIST_DOMAINS']:
                    continue
                
                # 检查是否是白名单域名的子域名
                is_whitelist_subdomain = False
                for white_domain in CONFIG['TRUE_WHITELIST_DOMAINS']:
                    if domain == white_domain or domain.endswith(f".{white_domain}"):
                        is_whitelist_subdomain = True
                        break
                
                if not is_whitelist_subdomain:
                    self.black_domains.add(domain)
                    domains_found += 1
        
        print(f"  ✓ 找到 {domains_found} 个域名")
    
    def load_whitelist(self):
        """加载白名单"""
        print("✅ 加载白名单...")
        
        whitelist_domains = set(CONFIG['TRUE_WHITELIST_DOMAINS'])
        
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 如果是URL，下载并处理
                        if line.startswith('http'):
                            print(f"  📥 下载白名单源: {line}")
                            content = self.download_content(line)
                            if content:
                                for content_line in content.split('\n'):
                                    domain = self.extract_domain_from_line(content_line)
                                    if domain:
                                        whitelist_domains.add(domain)
                        else:
                            # 直接添加域名
                            domain = self.extract_domain_from_line(line)
                            if domain:
                                whitelist_domains.add(domain)
        
        print(f"  白名单域名: {len(whitelist_domains)} 个")
        if whitelist_domains:
            print("  白名单示例:", list(whitelist_domains)[:5])
        
        return whitelist_domains
    
    def apply_whitelist(self, whitelist_domains: Set[str]):
        """应用白名单"""
        print("🔄 应用白名单...")
        
        original_count = len(self.black_domains)
        
        # 移除完全匹配的白名单域名
        domains_to_remove = set()
        for domain in self.black_domains:
            if domain in whitelist_domains:
                domains_to_remove.add(domain)
        
        self.final_blacklist = self.black_domains - domains_to_remove
        
        removed = original_count - len(self.final_blacklist)
        print(f"  移除 {removed} 个白名单域名")
        print(f"  最终黑名单: {len(self.final_blacklist):,} 个域名")
    
    def generate_files(self, whitelist_domains: Set[str]):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d')
        
        # 排序域名
        sorted_blacklist = sorted(self.final_blacklist)
        
        # 1. AdBlock规则 (ad.txt)
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 v{version}\n")
            f.write(f"! 更新时间: {timestamp}\n")
            f.write(f"! 黑名单域名: {len(self.final_blacklist):,} 个\n")
            f.write(f"! 白名单域名: {len(whitelist_domains)} 个\n")
            f.write("!\n\n")
            
            # 黑名单规则
            f.write("! ====== 黑名单 ======\n")
            for domain in sorted_blacklist:
                f.write(f"||{domain}^\n")
        
        # 2. DNS规则 (dns.txt)
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.final_blacklist):,} 个\n")
            f.write("#\n\n")
            
            for domain in sorted_blacklist:
                f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.final_blacklist):,} 个\n")
            f.write("#\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n\n")
            
            for i in range(0, len(sorted_blacklist), 1000):
                batch = sorted_blacklist[i:i+1000]
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("\n")
        
        # 4. 纯黑名单 (black.txt)
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            for domain in sorted_blacklist:
                f.write(f"||{domain}^\n")
        
        # 5. 纯白名单 (white.txt)
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(whitelist_domains)} 个\n")
            f.write("#\n\n")
            
            for domain in sorted(whitelist_domains):
                f.write(f"@@||{domain}^\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'statistics': {
                'lines_processed': self.stats['lines_processed'],
                'final_blacklist_domains': len(self.final_blacklist),
                'whitelist_domains': len(whitelist_domains),
                'whitelist_ignored': self.stats['whitelist_ignored']
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print(f"📄 文件生成完成:")
        print(f"   黑名单域名: {len(self.final_blacklist):,} 个")
        print(f"   白名单域名: {len(whitelist_domains)} 个")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器 - 简化版")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载白名单（先做，用于过滤）
            whitelist_domains = self.load_whitelist()
            
            # 2. 处理黑名单源
            print("\n🔍 处理黑名单源...")
            
            blacklist_urls = []
            if os.path.exists(CONFIG['BLACK_SOURCE']):
                with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            blacklist_urls.append(line)
            
            if not blacklist_urls:
                print("  ⚠️ 未找到黑名单源")
                return False
            
            print(f"  找到 {len(blacklist_urls)} 个黑名单源")
            
            # 并行处理黑名单URL
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
                futures = []
                for url in blacklist_urls:
                    future = executor.submit(self.process_blacklist_url, url)
                    futures.append(future)
                
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result(timeout=30)
                        completed += 1
                        print(f"  ✅ [{completed}/{len(blacklist_urls)}] 完成")
                    except Exception as e:
                        print(f"  ❌ 处理失败: {e}")
            
            # 3. 应用白名单
            self.apply_whitelist(whitelist_domains)
            
            # 4. 生成文件
            self.generate_files(whitelist_domains)
            
            # 5. 生成README
            self.generate_readme()
            
            # 6. 运行验证
            self.run_validation(whitelist_domains)
            
            elapsed = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 黑名单域名: {len(self.final_blacklist):,}个")
            print(f"📊 白名单域名: {len(whitelist_domains)}个")
            print("📁 规则文件: rules/outputs/")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def generate_readme(self):
        """生成README.md"""
        print("📖 生成README.md...")
        
        with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
            info = json.load(f)
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        readme = f"""# 广告过滤规则

简洁高效的广告过滤规则，专注于拦截广告域名。

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
- 白名单域名：{info['statistics']['whitelist_domains']} 个

---

## 最新更新时间

**{info['updated_at']}**

*规则每天自动更新*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
    
    def run_validation(self, whitelist_domains: Set[str]):
        """运行验证"""
        print("\n🔍 运行验证...")
        
        # 检查关键广告域名是否被包含
        critical_domains = [
            'doubleclick.net',
            'google-analytics.com',
            'googlesyndication.com',
            'googleadservices.com',
            'adservice.google.com'
        ]
        
        missing = []
        for domain in critical_domains:
            if domain not in self.final_blacklist:
                missing.append(domain)
        
        if missing:
            print(f"⚠️  警告: 缺失 {len(missing)} 个关键广告域名")
            for domain in missing:
                print(f"   - {domain}")
        else:
            print("✅ 所有关键广告域名已包含")
        
        # 检查白名单数量
        white_count = len(whitelist_domains)
        if white_count > 100:
            print(f"⚠️  警告: 白名单过多 ({white_count} 个)")
        else:
            print(f"✅ 白名单数量合理 ({white_count} 个)")

def main():
    """主函数"""
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    generator = SimpleAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
