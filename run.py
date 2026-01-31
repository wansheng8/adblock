#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 精简优化版
"""

import os
import re
import json
import time
import concurrent.futures
from datetime import datetime, timedelta
from typing import Set, List, Tuple, Optional
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
    
    # 必须拦截的关键广告域名
    'CRITICAL_AD_DOMAINS': {
        'doubleclick.net',
        'google-analytics.com',
        'googlesyndication.com',
        'googleadservices.com',
        'adservice.google.com',
        'ads.google.com',
        'scorecardresearch.com',
        'outbrain.com',
        'taboola.com',
        'criteo.com',
        'adnxs.com',
        'amazon-adsystem.com',
        'facebook.com',  # 广告相关子域名会被处理
        'ads.facebook.com',
        'analytics.google.com',
        'tracking.google.com'
    },
    
    # 真正的白名单（只放行这些）
    'TRUE_WHITELIST_DOMAINS': {
        'google.com',          # 主域名
        'github.com',
        'microsoft.com',
        'apple.com',
        'baidu.com',
        'qq.com',
        'zhihu.com',
        'bilibili.com'
    }
}

class OptimizedAdBlockGenerator:
    def __init__(self):
        # 精简的数据结构
        self.black_domains = set()      # 黑名单域名
        self.true_white_domains = set() # 真正的白名单域名
        self.final_blacklist = set()    # 最终黑名单
        
        # 统计
        self.stats = {
            'lines_processed': 0,
            'black_domains_found': 0,
            'whitelist_lines_ignored': 0,
            'critical_domains_added': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源 - 使用有效的规则源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# AdGuard广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# EasyList规则\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 中文广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n")
        
        # 白名单源 - 只放行真正需要的
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只放行重要的主域名\n\n")
                f.write("# 重要网站主域名\n")
                f.write("@@||google.com^\n")
                f.write("@@||github.com^\n")
                f.write("@@||baidu.com^\n")
                f.write("@@||qq.com^\n")
                f.write("@@||zhihu.com^\n")
                f.write("@@||bilibili.com^\n")
    
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
                else:
                    print(f"  ⚠️ 下载失败: {url}")
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效（简化版）"""
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
    
    def extract_domain_simple(self, rule: str) -> Tuple[Optional[str], bool]:
        """简化域名提取，只提取域名，不处理复杂规则"""
        rule = rule.strip()
        if not rule:
            return None, False
        
        # 跳过注释和空行
        if rule.startswith('!') or rule.startswith('#'):
            return None, False
        
        # 判断是否是白名单
        is_whitelist = rule.startswith('@@')
        
        # 如果是白名单规则，移除@@前缀
        if is_whitelist:
            rule = rule[2:]
        
        # 简单的域名提取
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',          # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)/',           # ||domain.com/
            r'^([a-zA-Z0-9.-]+)\^$',             # domain.com^
            r'^([a-zA-Z0-9.-]+)$',               # domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',            # *.domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = match.group(1).lower().strip()
                
                # 移除www前缀
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, False
    
    def process_blacklist_content(self, content: str, url: str):
        """处理黑名单内容（只提取域名）"""
        lines = content.split('\n')
        domains_found = 0
        
        for line in lines:
            self.stats['lines_processed'] += 1
            
            domain, is_whitelist = self.extract_domain_simple(line)
            
            if domain:
                if is_whitelist:
                    # 黑名单源中的白名单：如果是我们定义的白名单，就记录；否则忽略
                    if domain in CONFIG['TRUE_WHITELIST_DOMAINS']:
                        self.true_white_domains.add(domain)
                    else:
                        self.stats['whitelist_lines_ignored'] += 1
                else:
                    # 黑名单域名
                    self.black_domains.add(domain)
                    domains_found += 1
        
        return domains_found
    
    def process_whitelist_content(self, content: str, url: str):
        """处理白名单内容"""
        lines = content.split('\n')
        
        for line in lines:
            self.stats['lines_processed'] += 1
            
            domain, is_whitelist = self.extract_domain_simple(line)
            
            if domain and is_whitelist:
                # 只添加我们认可的白名单域名
                self.true_white_domains.add(domain)
    
    def process_url(self, url: str, is_whitelist_source: bool = False):
        """处理单个URL"""
        print(f"  📥 处理: {url}")
        content = self.download_content(url)
        if not content:
            return
        
        if is_whitelist_source:
            self.process_whitelist_content(content, url)
            print(f"  ✓ 白名单处理完成")
        else:
            domains_found = self.process_blacklist_content(content, url)
            print(f"  ✓ 找到 {domains_found} 个域名")
    
    def load_and_process(self):
        """加载并处理规则源"""
        print("🔍 加载规则源...")
        
        # 读取黑名单源
        blacklist_urls = []
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist_urls.append((line, False))
        
        # 读取白名单源
        whitelist_urls = []
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if line.startswith('http'):
                            whitelist_urls.append((line, True))
                        elif line.startswith('@@'):
                            # 直接处理本地白名单规则
                            domain, is_whitelist = self.extract_domain_simple(line)
                            if domain and is_whitelist:
                                self.true_white_domains.add(domain)
        
        all_urls = blacklist_urls + whitelist_urls
        
        if not all_urls:
            print("  ⚠️ 未找到规则源")
            return
        
        print(f"  找到 {len(all_urls)} 个规则源")
        
        # 并行处理
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url, is_whitelist in all_urls:
                future = executor.submit(self.process_url, url, is_whitelist)
                futures.append(future)
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=30)
                    completed += 1
                    print(f"  ✅ [{completed}/{len(all_urls)}] 完成")
                except Exception as e:
                    print(f"  ❌ 处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.black_domains):,} 个")
        print(f"   白名单域名: {len(self.true_white_domains):,} 个")
    
    def apply_critical_domains(self):
        """确保关键广告域名被包含"""
        print("🛡️  添加关键广告域名...")
        
        added = 0
        for domain in CONFIG['CRITICAL_AD_DOMAINS']:
            if domain not in self.true_white_domains:
                self.black_domains.add(domain)
                added += 1
        
        self.stats['critical_domains_added'] = added
        print(f"  添加 {added} 个关键广告域名")
    
    def create_final_blacklist(self):
        """创建最终黑名单"""
        print("🔄 创建最终黑名单...")
        
        # 最终黑名单 = 所有黑名单域名 - 白名单域名
        self.final_blacklist = self.black_domains.copy()
        
        # 移除白名单域名（只移除完全匹配的，不移除子域名）
        domains_to_remove = set()
        for black_domain in self.final_blacklist:
            for white_domain in self.true_white_domains:
                # 完全匹配才移除
                if black_domain == white_domain:
                    domains_to_remove.add(black_domain)
                    break
        
        self.final_blacklist -= domains_to_remove
        
        print(f"  移除 {len(domains_to_remove)} 个白名单域名")
        print(f"  最终黑名单: {len(self.final_blacklist):,} 个域名")
    
    def generate_files(self):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        # 获取时间
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d')
        
        # 排序域名
        sorted_blacklist = sorted(self.final_blacklist)
        
        # 1. AdBlock规则 (ad.txt)
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 v{version}\n")
            f.write(f"! 更新时间: {timestamp}\n")
            f.write(f"! 黑名单域名: {len(self.final_blacklist):,} 个\n")
            f.write(f"! 白名单域名: {len(self.true_white_domains):,} 个\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.true_white_domains:
                f.write("! ====== 白名单 ======\n")
                for domain in sorted(self.true_white_domains):
                    f.write(f"@@||{domain}^\n")
                f.write("\n")
            
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
            
            # 关键域名在前
            critical_domains = []
            other_domains = []
            
            for domain in sorted_blacklist:
                if domain in CONFIG['CRITICAL_AD_DOMAINS']:
                    critical_domains.append(domain)
                else:
                    other_domains.append(domain)
            
            if critical_domains:
                f.write("# 关键广告域名\n")
                for domain in sorted(critical_domains):
                    f.write(f"{domain}\n")
                f.write("\n")
            
            f.write("# 其他广告域名\n")
            for domain in sorted(other_domains):
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
            
            # 分批写入
            batch_size = 1000
            for i in range(0, len(sorted_blacklist), batch_size):
                batch = sorted_blacklist[i:i+batch_size]
                f.write(f"# 第 {i//batch_size + 1} 组\n")
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
            f.write(f"# 域名数量: {len(self.true_white_domains):,} 个\n")
            f.write("#\n\n")
            
            for domain in sorted(self.true_white_domains):
                f.write(f"@@||{domain}^\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'statistics': {
                'lines_processed': self.stats['lines_processed'],
                'final_blacklist_domains': len(self.final_blacklist),
                'whitelist_domains': len(self.true_white_domains),
                'critical_domains_added': self.stats['critical_domains_added'],
                'whitelist_ignored': self.stats['whitelist_lines_ignored']
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print(f"📄 规则文件生成完成:")
        print(f"   ad.txt - {len(self.final_blacklist):,}个域名")
        print(f"   dns.txt - {len(self.final_blacklist):,}个域名")
        print(f"   hosts.txt - {len(self.final_blacklist):,}个域名")
        print(f"   black.txt - 黑名单")
        print(f"   white.txt - {len(self.true_white_domains):,}个白名单")
    
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
- 白名单域名：{info['statistics']['whitelist_domains']:,} 个

---

## 最新更新时间

**{info['updated_at']}**

*规则每天自动更新*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
    
    def run_test(self):
        """运行快速测试"""
        print("🔬 运行快速测试...")
        
        # 检查关键域名是否包含
        missing = []
        for domain in CONFIG['CRITICAL_AD_DOMAINS']:
            if domain not in self.final_blacklist:
                missing.append(domain)
        
        if missing:
            print(f"⚠️  警告: 缺失 {len(missing)} 个关键域名")
            for domain in missing[:5]:
                print(f"   - {domain}")
        else:
            print("✅ 所有关键域名已包含")
        
        # 检查白名单数量
        if len(self.true_white_domains) > 100:
            print(f"⚠️  警告: 白名单过多 ({len(self.true_white_domains)} 个)")
        
        print(f"📊 最终统计:")
        print(f"   黑名单域名: {len(self.final_blacklist):,} 个")
        print(f"   白名单域名: {len(self.true_white_domains):,} 个")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器 (优化版)")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载和处理规则源
            self.load_and_process()
            
            # 2. 添加关键广告域名
            self.apply_critical_domains()
            
            # 3. 创建最终黑名单
            self.create_final_blacklist()
            
            # 4. 运行测试
            self.run_test()
            
            # 5. 生成文件
            self.generate_files()
            
            # 6. 生成README
            self.generate_readme()
            
            elapsed = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 黑名单域名: {len(self.final_blacklist):,}个")
            print(f"📊 白名单域名: {len(self.true_white_domains):,}个")
            print("📁 规则文件: rules/outputs/")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    generator = OptimizedAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
