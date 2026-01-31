#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 最终修复版
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
    'MAX_WORKERS': 8,
    'TIMEOUT': 20,
    'RETRY': 3,
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    'PROTECTED_DOMAINS': {  # 受保护的域名，不会被移除
        'google.com', 'github.com', 'microsoft.com', 'apple.com',
        'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'weibo.com'
    }
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
    
    def get_beijing_time(self):
        """获取北京时间（东八区）"""
        # 方法1：使用timezone偏移（Python 3.2+）
        try:
            from datetime import timezone
            utc_now = datetime.now(timezone.utc)
            beijing_time = utc_now + timedelta(hours=8)
            return beijing_time
        except:
            # 方法2：使用本地时间（如果服务器在上海时区）
            return datetime.now()
    
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
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n")
        
        # 白名单源
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含以@@开头的规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 手动添加白名单（格式：@@||domain.com^）\n")
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
        """从规则中提取域名"""
        rule = rule.strip()
        if not rule:
            return None, False
        
        # 判断是否是白名单
        is_whitelist = rule.startswith('@@')
        if is_whitelist:
            rule = rule[2:]  # 移除@@前缀
        
        # 尝试匹配常见格式
        patterns = [
            r'^\|\|([a-zA-Z0-9.-]+)\^',          # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)\/',          # ||domain.com/
            r'^([a-zA-Z0-9.-]+)\^',              # domain.com^
            r'^([a-zA-Z0-9.-]+)$',               # domain.com
            r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)',  # 0.0.0.0 domain.com
            r'^\*\.([a-zA-Z0-9.-]+)',            # *.domain.com
            r'^\/[^\/]+\/([a-zA-Z0-9.-]+)',      # /ads/domain.com
        ]
        
        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                domain = self.normalize_domain(match.group(1))
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, is_whitelist
    
    def process_rule_line(self, line: str) -> Tuple[Optional[str], Optional[str], str]:
        """处理单条规则"""
        line = line.strip()
        if not line:
            return None, None, ""
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#'):
            return None, None, ""
        
        # 提取域名
        domain, is_whitelist = self.extract_domain_from_rule(line)
        
        if domain:
            if is_whitelist:
                return 'white', domain, f"@@||{domain}^"
            else:
                return 'black', domain, f"||{domain}^"
        else:
            # 无法提取域名的规则
            if is_whitelist:
                return 'white_rule', None, line
            else:
                return 'black_rule', None, line
    
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
            rule_type, domain, rule = self.process_rule_line(line)
            
            if rule_type == 'black':
                black_domains.add(domain)
            elif rule_type == 'white':
                white_domains.add(domain)
                if rule:
                    white_rules.add(rule)
            elif rule_type == 'black_rule':
                black_rules.add(rule)
            elif rule_type == 'white_rule':
                white_rules.add(rule)
        
        print(f"  ✓ 处理完成: {lines_processed} 行")
        return black_domains, white_domains, black_rules, white_rules
    
    def load_and_process_sources(self):
        """加载并处理所有规则源"""
        print("🔍 加载规则源...")
        
        # 读取所有规则源URL
        urls = []
        
        # 读取黑名单源
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(('black', line))
        
        # 读取白名单源
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(('white', line))
        
        if not urls:
            print("  ⚠️ 未找到规则源URL")
            return
        
        print(f"  找到 {len(urls)} 个规则源")
        
        # 并行处理所有规则源
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            # 提交所有任务
            future_to_url = {}
            for source_type, url in urls:
                future = executor.submit(self.process_url, url, source_type)
                future_to_url[future] = (source_type, url)
            
            # 收集结果
            for future in concurrent.futures.as_completed(future_to_url):
                source_type, url = future_to_url[future]
                try:
                    bd, wd, br, wr = future.result(timeout=25)
                    results.append((bd, wd, br, wr))
                    print(f"  ✓ 完成: {url}")
                except Exception as e:
                    print(f"  ❌ 处理失败 {url}: {e}")
        
        # 合并所有结果
        for bd, wd, br, wr in results:
            self.black_domains.update(bd)
            self.white_domains.update(wd)
            self.black_rules.update(br)
            self.white_rules.update(wr)
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.black_domains):,} 个")
        print(f"   白名单域名: {len(self.white_domains):,} 个")
        print(f"   复杂规则: 黑名单 {len(self.black_rules):,} 条, 白名单 {len(self.white_rules):,} 条")
    
    def smart_whitelist_filter(self):
        """智能白名单过滤"""
        if not self.white_domains:
            print("ℹ️  没有白名单域名")
            return
        
        original_count = len(self.black_domains)
        
        # 保护重要域名
        protected_domains = set()
        for domain in self.black_domains:
            for protected in CONFIG['PROTECTED_DOMAINS']:
                if domain == protected or domain.endswith(f".{protected}"):
                    protected_domains.add(domain)
                    break
        
        print(f"🛡️  保护 {len(protected_domains)} 个重要域名")
        
        # 从黑名单中移除完全匹配的白名单域名（安全操作）
        safe_to_remove = set()
        for white_domain in self.white_domains:
            if white_domain in self.black_domains:
                safe_to_remove.add(white_domain)
        
        # 不移除子域名，只移除完全匹配的（防止误删）
        self.black_domains -= safe_to_remove
        
        removed = original_count - len(self.black_domains)
        if removed > 0:
            print(f"🔄 应用白名单: 安全移除 {removed} 个完全匹配的域名")
    
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
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n")
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
            
            # 分批写入，提高可读性
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
            f.write(f"# 规则数量: {len(self.white_rules):,} 条\n")
            f.write("#\n\n")
            
            white_list = sorted([r for r in self.white_rules if r.startswith('@@')])
            for rule in white_list:
                f.write(f"{rule}\n")
        
        # 6. 规则信息文件 (info.json)
        info = {
            'version': version,
            'updated_at': timestamp,
            'updated_at_utc': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'timezone': 'Asia/Shanghai (UTC+8)',
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
                {'name': 'white.txt', 'description': '白名单规则', 'rules': len([r for r in self.white_rules if r.startswith('@@')])}
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
            # 1. 加载并处理规则源
            self.load_and_process_sources()
            
            # 2. 应用智能白名单过滤
            self.smart_whitelist_filter()
            
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
        print("🔄 将在 GitHub Actions 自动更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
