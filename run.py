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
from typing import Set, List, Optional, Dict
import requests

# 配置信息
CONFIG = {
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    'MAX_WORKERS': 5,
    'TIMEOUT': 30,
    'RETRY': 3,
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
    },
    
    # 额外放行的域名（避免误杀）
    'EXTRA_SAFE_DOMAINS': {
        'windowsupdate.com',
        'apple-dns.net',
        'msftncsi.com',
        'mzstatic.com',
        'icloud.com'
    }
}

class AdBlockGenerator:
    def __init__(self):
        self.black_domains = set()      # 黑名单域名
        self.final_blacklist = set()    # 最终黑名单
        self.whitelist_domains = set()  # 白名单域名
        
        # 统计
        self.stats = {
            'lines_processed': 0,
            'domains_found': 0,
            'whitelist_ignored': 0,
            'urls_processed': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源 - 使用更多可靠的源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源 - 修复版\n")
                f.write("# 使用可靠的广告规则源\n\n")
                
                f.write("# 1. AdGuard Base Filter\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                
                f.write("# 2. EasyList\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                
                f.write("# 3. AdGuard Tracking Protection\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking_servers.txt\n\n")
                
                f.write("# 4. AdGuard Mobile Ads\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt\n\n")
                
                f.write("# 5. Peter Lowe's Ad and tracking server list\n")
                f.write("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext\n\n")
        
        # 白名单源 - 只放行真正需要的
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只放行真正需要的域名\n\n")
                f.write("# 重要网站主域名\n")
                for domain in CONFIG['TRUE_WHITELIST_DOMAINS']:
                    f.write(f"{domain}\n")
                f.write("\n# 额外安全域名\n")
                for domain in CONFIG['EXTRA_SAFE_DOMAINS']:
                    f.write(f"{domain}\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/plain, */*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Cache-Control': 'no-cache'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                self.stats['urls_processed'] += 1
                return response.text
            except requests.exceptions.Timeout:
                print(f"    ⏱️  超时 ({i+1}/{CONFIG['RETRY']})")
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(3)
            except Exception as e:
                print(f"    ❌ 下载失败: {e}")
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(2)
        return None
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        if not domain or len(domain) > 253:
            return False
        
        # 排除本地域名
        local_domains = {'localhost', 'local', 'broadcasthost', '0.0.0.0', '127.0.0.1', '::1'}
        if domain in local_domains:
            return False
        
        # 排除IP地址
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        if re.match(ip_pattern, domain):
            return False
        
        # 排除太短的域名
        if len(domain) < 3:
            return False
        
        # 基本域名格式检查
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 检查每部分
        for part in parts:
            if not part or len(part) > 63:
                return False
            # 允许字母、数字、连字符
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', part):
                return False
        
        return True
    
    def extract_domain_from_line(self, line: str) -> Optional[str]:
        """从行中提取域名"""
        line = line.strip()
        if not line:
            return None
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#') or line.startswith('['):
            return None
        
        # 如果是白名单规则（以@@开头），跳过但统计
        if line.startswith('@@'):
            self.stats['whitelist_ignored'] += 1
            return None
        
        # 处理不同的规则格式
        domain = None
        
        # 1. AdBlock格式: ||domain.com^
        if line.startswith('||') and '^' in line:
            match = re.match(r'^\|\|([a-zA-Z0-9.-]+)\^', line)
            if match:
                domain = match.group(1).lower()
        
        # 2. 简单域名格式: domain.com
        elif re.match(r'^[a-zA-Z0-9.-]+$', line):
            domain = line.lower()
        
        # 3. Hosts格式: 0.0.0.0 domain.com
        elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
        
        # 4. 通配符格式: *.domain.com
        elif line.startswith('*.'):
            domain = line[2:].lower()
        
        # 5. 其他常见格式
        else:
            # 尝试提取domain.com^格式
            match = re.match(r'^([a-zA-Z0-9.-]+)\^', line)
            if match:
                domain = match.group(1).lower()
        
        if not domain:
            return None
        
        # 清理域名
        domain = domain.strip()
        
        # 移除www前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # 移除末尾的特殊字符
        domain = re.sub(r'[\^\$]$', '', domain)
        
        # 验证域名
        if self.is_valid_domain(domain):
            self.stats['domains_found'] += 1
            return domain
        
        return None
    
    def process_blacklist_url(self, url: str):
        """处理黑名单URL"""
        print(f"  📥 下载: {url}")
        content = self.download_content(url)
        if not content:
            print(f"    ⚠️  跳过 (下载失败)")
            return
        
        domains_found = 0
        lines = content.split('\n')
        
        for line in lines:
            self.stats['lines_processed'] += 1
            
            domain = self.extract_domain_from_line(line)
            if domain:
                # 只在添加前检查白名单
                if not self.is_whitelisted_domain(domain):
                    self.black_domains.add(domain)
                    domains_found += 1
        
        print(f"    ✓ 找到 {domains_found} 个广告域名")
    
    def is_whitelisted_domain(self, domain: str) -> bool:
        """检查域名是否在白名单中"""
        # 直接匹配
        if domain in self.whitelist_domains:
            return True
        
        # 检查是否是白名单域名的子域名
        for white_domain in self.whitelist_domains:
            # 注意：这里只放行确切的域名，不过度放行子域名
            # 例如：white_domain = "google.com"，只放行"google.com"，不放行"ads.google.com"
            if domain == white_domain:
                return True
        
        return False
    
    def load_whitelist(self) -> Set[str]:
        """加载白名单"""
        print("✅ 加载白名单...")
        
        # 从配置中获取基础白名单
        whitelist_domains = set(CONFIG['TRUE_WHITELIST_DOMAINS'])
        whitelist_domains.update(CONFIG['EXTRA_SAFE_DOMAINS'])
        
        # 从文件读取附加的白名单
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理纯域名
                    domain = self.extract_domain_from_line(line)
                    if domain:
                        whitelist_domains.add(domain)
                    elif self.is_valid_domain(line):
                        whitelist_domains.add(line.lower())
        
        self.whitelist_domains = whitelist_domains
        
        print(f"  白名单域名: {len(whitelist_domains)} 个")
        print("  白名单示例:", list(sorted(whitelist_domains))[:15])
        
        return whitelist_domains
    
    def generate_files(self):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d')
        
        # 排序域名
        sorted_blacklist = sorted(self.final_blacklist)
        sorted_whitelist = sorted(self.whitelist_domains)
        
        # 1. AdBlock规则 (ad.txt)
        print("  生成 ad.txt...")
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 v{version}\n")
            f.write(f"! 更新时间: {timestamp}\n")
            f.write(f"! 黑名单域名: {len(self.final_blacklist):,} 个\n")
            f.write(f"! 白名单域名: {len(self.whitelist_domains)} 个\n")
            f.write("!\n\n")
            
            # 白名单规则（放在前面）
            f.write("! ====== 白名单 ======\n")
            for domain in sorted_whitelist:
                f.write(f"@@||{domain}^$important\n")
            
            f.write("\n! ====== 黑名单 ======\n")
            # 分批写入，避免内存问题
            for i, domain in enumerate(sorted_blacklist):
                f.write(f"||{domain}^\n")
                if (i + 1) % 10000 == 0:
                    print(f"    已写入 {i+1} 条规则")
        
        # 2. DNS规则 (dns.txt)
        print("  生成 dns.txt...")
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.final_blacklist):,} 个\n")
            f.write("#\n\n")
            
            for i, domain in enumerate(sorted_blacklist):
                f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        print("  生成 hosts.txt...")
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
        print("  生成 black.txt...")
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            for domain in sorted_blacklist:
                f.write(f"{domain}\n")
        
        # 5. 纯白名单 (white.txt)
        print("  生成 white.txt...")
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.whitelist_domains)} 个\n")
            f.write("#\n\n")
            
            for domain in sorted_whitelist:
                f.write(f"{domain}\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'statistics': {
                'urls_processed': self.stats['urls_processed'],
                'lines_processed': self.stats['lines_processed'],
                'domains_found': self.stats['domains_found'],
                'final_blacklist_domains': len(self.final_blacklist),
                'whitelist_domains': len(self.whitelist_domains),
                'whitelist_ignored': self.stats['whitelist_ignored']
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 文件生成完成:")
        print(f"   原始域名: {self.stats['domains_found']:,} 个")
        print(f"   最终黑名单: {len(self.final_blacklist):,} 个")
        print(f"   白名单域名: {len(self.whitelist_domains)} 个")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 广告过滤规则生成器 - 修复版")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载白名单
            self.load_whitelist()
            
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
            
            # 顺序处理，避免并发问题
            for i, url in enumerate(blacklist_urls):
                print(f"\n[{i+1}/{len(blacklist_urls)}] ", end='')
                self.process_blacklist_url(url)
            
            print(f"\n📊 原始域名收集完成:")
            print(f"   总行数: {self.stats['lines_processed']:,}")
            print(f"   找到域名: {self.stats['domains_found']:,}")
            print(f"   唯一域名: {len(self.black_domains):,}")
            
            # 3. 应用白名单（更保守的方式）
            print("\n🔄 应用白名单过滤...")
            original_count = len(self.black_domains)
            
            # 只移除完全匹配的白名单域名，不过度过滤子域名
            self.final_blacklist = set()
            for domain in self.black_domains:
                if not self.is_whitelisted_domain(domain):
                    self.final_blacklist.add(domain)
            
            removed = original_count - len(self.final_blacklist)
            print(f"  移除 {removed} 个白名单域名")
            print(f"  最终黑名单: {len(self.final_blacklist):,} 个域名")
            
            # 4. 检查黑名单状态
            self.check_blacklist_status()
            
            # 5. 生成文件
            self.generate_files()
            
            # 6. 生成README
            self.generate_readme()
            
            # 7. 运行验证
            self.run_validation()
            
            elapsed = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 处理URL: {self.stats['urls_processed']}个")
            print(f"📊 原始域名: {self.stats['domains_found']:,}个")
            print(f"📊 最终黑名单: {len(self.final_blacklist):,}个")
            print(f"📊 白名单域名: {len(self.whitelist_domains)}个")
            print("📁 规则文件: rules/outputs/")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def check_blacklist_status(self):
        """检查黑名单状态"""
        print("\n🔍 检查黑名单状态...")
        
        if not self.final_blacklist:
            print("⚠️ 警告: 黑名单为空!")
            print("可能的原因:")
            print("  1. 网络问题，规则源无法下载")
            print("  2. 白名单过滤过严")
            print("  3. 域名提取逻辑有问题")
            return
        
        print(f"  黑名单域名数量: {len(self.final_blacklist):,}")
        
        # 检查典型广告域名
        test_domains = [
            'doubleclick.net',
            'google-analytics.com',
            'googlesyndication.com',
            'googleadservices.com',
            'adsystem.com',
            'adnxs.com',
            'scorecardresearch.com',
            'amazon-adsystem.com',
            'facebook.com/tr',  # Facebook追踪
            'ads.youtube.com'
        ]
        
        found = 0
        for domain in test_domains:
            # 检查主域名
            main_domain = domain.split('/')[0]
            if main_domain in self.final_blacklist:
                found += 1
                print(f"  ✅ {domain} 在黑名单中")
            else:
                print(f"  ❌ {domain} 不在黑名单中")
        
        print(f"  测试域名覆盖率: {found}/{len(test_domains)}")
        
        # 显示部分黑名单域名
        print("\n  部分黑名单域名示例:")
        sample = list(self.final_blacklist)[:20]
        for i, domain in enumerate(sample):
            print(f"    {i+1:2d}. {domain}")
    
    def generate_readme(self):
        """生成README.md"""
        print("\n📖 生成README.md...")
        
        try:
            with open('rules/outputs/info.json', 'r', encoding='utf-8') as f:
                info = json.load(f)
        except:
            info = {'version': 'unknown', 'statistics': {}}
        
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        readme = f"""# 广告过滤规则

简洁高效的广告过滤规则，专注于拦截广告域名。

---

## 订阅地址

| 规则类型 | 规则说明 | 订阅链接 |
|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `{base_url}/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `{base_url}/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `{base_url}/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `{base_url}/black.txt` |
| **白名单规则** | 排除误拦域名 | `{base_url}/white.txt` |

**版本 {info.get('version', 'unknown')} 统计：**
- 处理规则源：{info['statistics'].get('urls_processed', 0)} 个
- 原始域名：{info['statistics'].get('domains_found', 0):,} 个
- 最终黑名单：{info['statistics'].get('final_blacklist_domains', 0):,} 个
- 白名单域名：{info['statistics'].get('whitelist_domains', 0)} 个

---

## 使用说明

### 1. 浏览器插件（如uBlock Origin）
1. 打开uBlock Origin设置
2. 点击"规则列表"
3. 点击"导入..."
4. 粘贴订阅地址：`{base_url}/ad.txt`
5. 点击"应用更改"

### 2. DNS过滤（如AdGuard Home）
1. 打开AdGuard Home控制台
2. 进入"过滤器" → "DNS封锁列表"
3. 点击"添加封锁列表"
4. 名称：广告过滤规则
5. URL：`{base_url}/dns.txt`
6. 点击"保存"

### 3. 系统Hosts文件
1. 下载：`{base_url}/hosts.txt`
2. 备份原有hosts文件
3. 将下载的内容追加到hosts文件末尾
4. 刷新DNS缓存

---

## 最新更新时间

**{info.get('updated_at', '未知')}**

*规则每天自动更新*

## 注意事项

1. 本规则包含约 {info['statistics'].get('final_blacklist_domains', 0):,} 个广告域名
2. 白名单只包含 {info['statistics'].get('whitelist_domains', 0)} 个关键域名
3. 如果发现误拦，请添加到白名单
4. 规则每日自动更新，无需手动操作

---
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
    
    def run_validation(self):
        """运行验证"""
        print("\n🔍 运行验证...")
        
        if not self.final_blacklist:
            print("⚠️ 警告: 黑名单为空，验证失败")
            return
        
        # 检查文件是否存在
        required_files = [
            'rules/outputs/ad.txt',
            'rules/outputs/dns.txt',
            'rules/outputs/hosts.txt',
            'rules/outputs/black.txt',
            'rules/outputs/white.txt',
            'rules/outputs/info.json'
        ]
        
        all_exist = True
        for file in required_files:
            if os.path.exists(file):
                print(f"  ✅ {os.path.basename(file)} 存在")
            else:
                print(f"  ❌ {os.path.basename(file)} 缺失")
                all_exist = False
        
        if all_exist:
            print("✅ 所有文件生成成功")
        else:
            print("⚠️  部分文件缺失")

def main():
    """主函数"""
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    print("检查网络连接...")
    try:
        response = requests.get('https://raw.githubusercontent.com/', timeout=10)
        if response.status_code == 200:
            print("✅ 网络连接正常")
        else:
            print(f"⚠️  网络连接异常: HTTP {response.status_code}")
    except Exception as e:
        print(f"⚠️  网络连接异常: {e}")
    
    generator = AdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔗 查看README.md获取订阅链接")
        
        # 显示文件大小
        print("\n📦 生成的文件大小:")
        for file in os.listdir('rules/outputs'):
            filepath = os.path.join('rules/outputs', file)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                if size > 1024*1024:
                    size_str = f"{size/(1024*1024):.1f} MB"
                elif size > 1024:
                    size_str = f"{size/1024:.1f} KB"
                else:
                    size_str = f"{size} B"
                print(f"  {file}: {size_str}")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
