#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 完整解决方案
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
    'MAX_WORKERS': 8,
    'TIMEOUT': 20,
    'RETRY': 3,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    'PROTECTED_DOMAINS': {
        'google.com', 'github.com', 'microsoft.com', 'apple.com',
        'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'weibo.com'
    }
}

class AdBlockGenerator:
    def __init__(self):
        # 主规则集合
        self.black_domains = set()           # 最终黑名单域名
        self.all_black_domains = set()       # 所有收集到的黑名单域名（包含可能被移除的）
        self.all_white_domains = set()       # 所有收集到的白名单域名
        self.black_rules = set()             # 复杂黑名单规则
        self.white_rules = set()             # 复杂白名单规则
        
        # 来源追踪
        self.blacklist_sources = []          # 黑名单源URL
        self.whitelist_sources = []          # 白名单源URL
        self.processed_urls = []             # 已处理的URL
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def get_beijing_time(self) -> datetime:
        """获取北京时间"""
        try:
            from datetime import timezone
            utc_now = datetime.now(timezone.utc)
            beijing_time = utc_now + timedelta(hours=8)
            return beijing_time
        except:
            return datetime.now()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 1. AdGuard基础广告规则（包含白名单）\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# 2. EasyList规则（包含白名单）\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 3. 中文规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n")
        
        # 白名单源
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含以@@开头的规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 手动添加重要白名单\n")
                f.write("# @@||google.com^\n")
                f.write("# @@||github.com^\n")
    
    def download_content(self, url: str) -> Optional[str]:
        """下载规则内容"""
        for i in range(CONFIG['RETRY']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain, */*',
                    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                    'Connection': 'keep-alive'
                }
                response = requests.get(url, headers=headers, timeout=CONFIG['TIMEOUT'])
                response.raise_for_status()
                return response.text
            except Exception as e:
                if i < CONFIG['RETRY'] - 1:
                    time.sleep(1)
                else:
                    print(f"  ❌ 下载失败 {url}: {str(e)[:100]}")
        return None
    
    def normalize_domain(self, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""
        
        domain = domain.lower().strip()
        
        # 移除常见前缀
        if domain.startswith('www.'):
            domain = domain[4:]
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # 移除常见后缀
        if domain.endswith('.'):
            domain = domain[:-1]
        
        return domain
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名是否有效"""
        domain = self.normalize_domain(domain)
        
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
        """从规则中提取域名和判断是否是白名单"""
        rule = rule.strip()
        if not rule:
            return None, False
        
        # 判断是否是白名单
        is_whitelist = rule.startswith('@@')
        original_rule = rule
        
        # 如果是白名单规则，移除@@前缀
        if is_whitelist:
            rule = rule[2:]
        
        # 尝试匹配常见格式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',          # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)\/',          # ||domain.com/
            r'^([a-zA-Z0-9.-]+)\^',              # domain.com^
            r'^([a-zA-Z0-9.-]+)$',               # domain.com
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',  # 0.0.0.0 domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',            # *.domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = self.normalize_domain(match.group(1))
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, is_whitelist
    
    def classify_rule(self, line: str) -> Tuple[Optional[str], Optional[str], str]:
        """分类规则类型"""
        line = line.strip()
        if not line:
            return None, None, ""
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#'):
            return None, None, ""
        
        # 提取域名并判断类型
        domain, is_whitelist = self.extract_domain_from_rule(line)
        
        if domain:
            if is_whitelist:
                return 'white_domain', domain, f"@@||{domain}^"
            else:
                return 'black_domain', domain, f"||{domain}^"
        else:
            # 复杂规则
            if is_whitelist:
                return 'white_rule', None, line
            else:
                if len(line) > 3 and re.search(r'[a-zA-Z0-9]', line):
                    return 'black_rule', None, line
        
        return None, None, ""
    
    def process_url(self, url: str, source_type: str) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """处理单个规则源URL"""
        print(f"  📥 下载: {url}")
        content = self.download_content(url)
        if not content:
            return set(), set(), set(), set()
        
        black_domains = set()
        white_domains = set()
        black_rules = set()
        white_rules = set()
        
        lines_processed = 0
        for line in content.split('\n'):
            lines_processed += 1
            rule_type, domain, rule = self.classify_rule(line)
            
            if rule_type == 'black_domain':
                black_domains.add(domain)
            elif rule_type == 'white_domain':
                white_domains.add(domain)
                if rule:
                    white_rules.add(rule)
            elif rule_type == 'black_rule':
                black_rules.add(rule)
            elif rule_type == 'white_rule':
                white_rules.add(rule)
        
        print(f"  ✓ 处理完成: {lines_processed} 行")
        print(f"    黑名单域名: {len(black_domains)}, 白名单域名: {len(white_domains)}")
        
        return black_domains, white_domains, black_rules, white_rules
    
    def load_sources(self):
        """加载规则源URL"""
        print("🔍 加载规则源...")
        
        # 读取黑名单源
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blacklist_sources.append(line)
        
        # 读取白名单源
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.whitelist_sources.append(line)
        
        print(f"  黑名单源: {len(self.blacklist_sources)} 个")
        print(f"  白名单源: {len(self.whitelist_sources)} 个")
        
        if not self.blacklist_sources and not self.whitelist_sources:
            print("  ⚠️ 未找到规则源URL")
            return False
        
        return True
    
    def process_all_sources(self):
        """处理所有规则源"""
        all_urls = []
        
        # 黑名单源
        for url in self.blacklist_sources:
            all_urls.append(('black', url))
        
        # 白名单源
        for url in self.whitelist_sources:
            all_urls.append(('white', url))
        
        if not all_urls:
            return
        
        print(f"🔄 开始处理 {len(all_urls)} 个规则源...")
        
        # 并行处理所有规则源
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            # 提交所有任务
            future_to_url = {}
            for source_type, url in all_urls:
                future = executor.submit(self.process_url, url, source_type)
                future_to_url[future] = (source_type, url)
                self.processed_urls.append(url)
            
            # 收集结果
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                source_type, url = future_to_url[future]
                try:
                    bd, wd, br, wr = future.result(timeout=30)
                    results.append((bd, wd, br, wr))
                    completed += 1
                    print(f"  ✓ [{completed}/{len(all_urls)}] 完成: {url}")
                except Exception as e:
                    print(f"  ❌ 处理失败 {url}: {e}")
        
        # 合并所有结果
        total_black = 0
        total_white = 0
        for bd, wd, br, wr in results:
            self.all_black_domains.update(bd)
            self.all_white_domains.update(wd)
            self.black_rules.update(br)
            self.white_rules.update(wr)
            total_black += len(bd)
            total_white += len(wd)
        
        print(f"✅ 解析完成:")
        print(f"   收集到的黑名单域名: {len(self.all_black_domains):,} 个")
        print(f"   收集到的白名单域名: {len(self.all_white_domains):,} 个")
        print(f"   复杂规则: 黑名单 {len(self.black_rules):,} 条, 白名单 {len(self.white_rules):,} 条")
    
    def apply_whitelist_logic(self):
        """
        应用白名单逻辑 - 核心算法
        处理黑名单源中的白名单规则
        """
        print("🤔 应用白名单逻辑...")
        
        # 备份原始数据
        self.black_domains = self.all_black_domains.copy()
        original_count = len(self.black_domains)
        
        # 策略1: 保护重要域名（绝对不删除）
        protected_domains = set()
        for domain in self.black_domains:
            for protected in CONFIG['PROTECTED_DOMAINS']:
                if domain == protected or domain.endswith(f".{protected}"):
                    protected_domains.add(domain)
                    break
        
        print(f"  🛡️  保护 {len(protected_domains)} 个重要域名")
        
        # 策略2: 应用白名单规则（分优先级）
        
        # 2.1 首先应用白名单源中的白名单（最高优先级）
        whitelist_source_removals = set()
        for white_domain in self.all_white_domains:
            if white_domain in self.black_domains and white_domain not in protected_domains:
                whitelist_source_removals.add(white_domain)
        
        # 2.2 然后应用黑名单源中的白名单（较低优先级）
        # 注意：黑名单源中的白名单通常是为了修复特定问题
        # 我们应用这些规则，但可以记录日志
        
        # 我们已经在 process_url 中收集了白名单域名
        # 直接应用
        blacklist_source_removals = set()
        # （注意：self.all_white_domains 已经包含了所有来源的白名单）
        
        # 移除操作（只移除完全匹配，不移除子域名）
        domains_to_remove = whitelist_source_removals  # 现在只移除白名单源中的
        
        # 不移除子域名，只移除完全匹配的（防止误删）
        self.black_domains -= domains_to_remove
        
        removed = original_count - len(self.black_domains)
        
        print(f"  🔄 白名单处理统计:")
        print(f"    从黑名单中移除: {removed} 个域名")
        print(f"    受保护的域名: {len(protected_domains)} 个")
        print(f"    剩余黑名单域名: {len(self.black_domains):,} 个")
        
        # 详细日志
        if removed > 0:
            print(f"  📋 移除的域名示例（最多显示5个）:")
            sample = list(domains_to_remove)[:5]
            for domain in sample:
                print(f"    - {domain}")
        
        return removed
    
    def generate_files(self):
        """生成各种格式的规则文件"""
        print("📁 生成规则文件...")
        
        # 使用北京时间
        beijing_time = self.get_beijing_time()
        version = beijing_time.strftime('%Y%m%d')
        timestamp = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # 对域名排序
        sorted_black_domains = sorted(self.black_domains)
        
        # 1. AdBlock格式规则 (ad.txt)
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 版本 {version}\n")
            f.write(f"! 更新时间 (北京时间): {timestamp}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.all_white_domains):,} 个\n")
            f.write(f"! 规则源: {len(self.processed_urls)} 个\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.white_rules:
                f.write("! ====== 白名单规则 ======\n")
                for rule in sorted(self.white_rules):
                    if rule.startswith('@@'):
                        f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单域名规则
            f.write("! ====== 域名黑名单 ======\n")
            for domain in sorted_black_domains:
                f.write(f"||{domain}^\n")
        
        # 2. DNS过滤规则 (dns.txt)
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间 (北京时间): {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write(f"# 适用于: AdGuard Home, Pi-hole, SmartDNS\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            
            for domain in sorted_black_domains:
                f.write(f"{domain}\n")
        
        # 3. Hosts格式规则 (hosts.txt)
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 - 版本 {version}\n")
            f.write(f"# 更新时间 (北京时间): {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write(f"# 适用于: 系统hosts文件\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n")
            f.write("#\n\n")
            f.write("# 本地域名\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n")
            
            # 分批写入
            batch_size = 1000
            for i in range(0, len(sorted_black_domains), batch_size):
                batch = sorted_black_domains[i:i+batch_size]
                f.write(f"\n# 域名 {i+1}-{i+len(batch)}\n")
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 纯黑名单规则 (black.txt)
        with open('rules/outputs/black.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 黑名单规则 - 版本 {version}\n")
            f.write(f"# 更新时间 (北京时间): {timestamp}\n")
            f.write("#\n\n")
            for domain in sorted_black_domains:
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open('rules/outputs/white.txt', 'w', encoding='utf-8') as f:
            f.write(f"# 白名单规则 - 版本 {version}\n")
            f.write(f"# 更新时间 (北京时间): {timestamp}\n")
            f.write(f"# 规则数量: {len([r for r in self.white_rules if r.startswith('@@')]):,} 条\n")
            f.write("#\n\n")
            
            white_list = sorted([r for r in self.white_rules if r.startswith('@@')])
            for rule in white_list:
                f.write(f"{rule}\n")
        
        # 6. 规则信息文件 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'timezone': 'Asia/Shanghai (UTC+8)',
            'statistics': {
                'final_blacklist_domains': len(self.black_domains),
                'original_blacklist_domains': len(self.all_black_domains),
                'whitelist_domains': len(self.all_white_domains),
                'whitelist_rules': len([r for r in self.white_rules if r.startswith('@@')]),
                'sources_processed': len(self.processed_urls),
                'domains_removed_by_whitelist': len(self.all_black_domains) - len(self.black_domains)
            },
            'sources': {
                'blacklist': len(self.blacklist_sources),
                'whitelist': len(self.whitelist_sources)
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("📄 规则文件生成完成:")
        print(f"   ad.txt - AdBlock格式 ({len(self.black_domains):,}个域名)")
        print(f"   dns.txt - DNS格式 ({len(self.black_domains):,}个域名)")
        print(f"   hosts.txt - Hosts格式 ({len(self.black_domains):,}个域名)")
        print(f"   black.txt - 黑名单规则 ({len(self.black_domains):,}个域名)")
        print(f"   white.txt - 白名单规则 ({len([r for r in self.white_rules if r.startswith('@@')]):,}条规则)")
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
- 黑名单域名：{info['statistics']['final_blacklist_domains']:,} 个
- 白名单域名：{info['statistics']['whitelist_domains']:,} 个
- 白名单移除：{info['statistics']['domains_removed_by_whitelist']:,} 个域名

---

## 最新更新时间

**{info['updated_at']}** (北京时间)

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
            # 1. 加载规则源
            if not self.load_sources():
                print("❌ 没有找到规则源")
                return False
            
            # 2. 处理所有规则源
            self.process_all_sources()
            
            # 3. 应用智能白名单逻辑
            self.apply_whitelist_logic()
            
            # 4. 生成规则文件
            self.generate_files()
            
            # 5. 生成README
            self.generate_readme()
            
            # 统计信息
            end_time = time.time()
            elapsed = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 最终黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 收集到白名单域名: {len(self.all_white_domains):,}个")
            print(f"📁 规则文件: rules/outputs/")
            print(f"📖 使用说明: README.md")
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
        print("🔄 将在 GitHub Actions 自动更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
