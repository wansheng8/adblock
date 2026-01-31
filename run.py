#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告过滤规则生成器 - 增强拦截效果版
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
    'STRONG_AD_DOMAINS': {  # 强化拦截的广告域名
        'doubleclick.net', 'google-analytics.com', 'googlesyndication.com',
        'googleadservices.com', 'adservice.google.com', 'ads.google.com',
        'adzerk.net', 'amazon-adsystem.com', 'scorecardresearch.com',
        'outbrain.com', 'taboola.com', 'criteo.com', 'adsrvr.org',
        'adnxs.com', 'casalemedia.com', 'rlcdn.com'
    }
}

class EnhancedAdBlockGenerator:
    def __init__(self):
        self.black_domains = set()      # 最终黑名单域名
        self.white_domains = set()      # 白名单域名
        self.black_rules = set()        # 复杂黑名单规则
        self.white_rules = set()        # 复杂白名单规则
        
        # 统计信息
        self.stats = {
            'total_rules_processed': 0,
            'domains_extracted': 0,
            'complex_rules_saved': 0
        }
        
        # 创建目录
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建默认规则源
        self.create_default_sources()
    
    def create_default_sources(self):
        """创建默认规则源文件"""
        # 黑名单源 - 使用更多有效的规则源
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 广告过滤规则源 - 增强版\n")
                f.write("# 每行一个URL\n\n")
                f.write("# 1. AdGuard基础广告规则（核心）\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n\n")
                f.write("# 2. EasyList规则（主要规则）\n")
                f.write("https://easylist.to/easylist/easylist.txt\n\n")
                f.write("# 3. EasyPrivacy规则（隐私保护）\n")
                f.write("https://easylist.to/easylist/easyprivacy.txt\n\n")
                f.write("# 4. 中文广告规则\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/ChineseFilter/master/ADGUARD_FILTER.txt\n\n")
                f.write("# 5. Fanboy's Annoyance List（烦人内容）\n")
                f.write("https://secure.fanboy.co.nz/fanboy-annoyance.txt\n\n")
                f.write("# 6. NoCoin List（挖矿脚本）\n")
                f.write("https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt\n\n")
                f.write("# 7. 恶意软件过滤\n")
                f.write("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt\n\n")
                f.write("# 8. AdGuard Tracking Protection\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt\n")
        
        # 白名单源 - 保持简洁
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 只包含以@@开头的规则\n\n")
                f.write("# AdGuard白名单\n")
                f.write("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n\n")
                f.write("# 重要网站白名单\n")
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
    
    def extract_domains_from_line(self, line: str) -> Tuple[List[str], bool, Optional[str]]:
        """从规则行中提取域名（支持多种格式）"""
        line = line.strip()
        if not line:
            return [], False, None
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#'):
            return [], False, None
        
        # 判断是否是白名单
        is_whitelist = line.startswith('@@')
        original_line = line
        
        # 如果是白名单规则，移除@@前缀
        if is_whitelist:
            line = line[2:]
        
        # 尝试匹配常见格式
        patterns = [
            # AdBlock格式
            (r'^\|\|([a-zA-Z0-9.-]+)\^', 1),          # ||domain.com^
            (r'^\|\|([a-zA-Z0-9.-]+)\/', 1),          # ||domain.com/
            (r'^([a-zA-Z0-9.-]+)\^$', 1),             # domain.com^
            (r'^\|\|([a-zA-Z0-9.-]+)\$', 1),          # ||domain.com$
            
            # 域名格式
            (r'^([a-zA-Z0-9.-]+)$', 1),               # domain.com
            
            # Hosts格式
            (r'^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.-]+)', 1),  # 0.0.0.0 domain.com
            
            # 通配符格式
            (r'^\*\.([a-zA-Z0-9.-]+)', 1),            # *.domain.com
            
            # URL格式
            (r'^https?://([^/\$\^]+)', 1),            # http://domain.com
            (r'^//([^/\$\^]+)', 1),                   # //domain.com
            
            # 复杂规则中的域名
            (r'domain=([a-zA-Z0-9.-]+)', 1),          # $domain=domain.com
            (r'([a-zA-Z0-9.-]+)\^?\$', 1),            # domain.com^$...
        ]
        
        domains = []
        for pattern, group in patterns:
            matches = re.findall(pattern, line)
            for match in matches:
                if isinstance(match, tuple):
                    domain = match[group-1]
                else:
                    domain = match
                
                domain = self.normalize_domain(domain)
                if self.is_valid_domain(domain):
                    domains.append(domain)
        
        # 去重
        domains = list(set(domains))
        
        return domains, is_whitelist, original_line if not domains else None
    
    def normalize_domain(self, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""
        
        domain = domain.lower().strip()
        
        # 移除常见前缀
        prefixes = ['www.', '*.', 'm.']
        for prefix in prefixes:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # 移除常见后缀
        suffixes = ['.', '^', '$', '|', '~']
        for suffix in suffixes:
            if domain.endswith(suffix):
                domain = domain[:-len(suffix)]
        
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
    
    def process_rule_content(self, content: str, url: str):
        """处理规则内容"""
        lines_processed = 0
        domains_found = 0
        
        for line in content.split('\n'):
            lines_processed += 1
            self.stats['total_rules_processed'] += 1
            
            domains, is_whitelist, original_line = self.extract_domains_from_line(line)
            
            if domains:
                domains_found += len(domains)
                self.stats['domains_extracted'] += len(domains)
                
                if is_whitelist:
                    self.white_domains.update(domains)
                    # 保存白名单规则
                    for domain in domains:
                        self.white_rules.add(f"@@||{domain}^")
                else:
                    self.black_domains.update(domains)
            
            # 保存无法提取域名的复杂规则
            elif original_line and len(original_line.strip()) > 3:
                self.stats['complex_rules_saved'] += 1
                if is_whitelist:
                    self.white_rules.add(original_line)
                else:
                    # 保存有效的复杂规则
                    if re.search(r'[a-zA-Z0-9\/\$\^\|\*]', original_line):
                        self.black_rules.add(original_line)
        
        print(f"  ✓ 处理完成: {lines_processed} 行, 提取 {domains_found} 个域名")
    
    def process_url(self, url: str):
        """处理单个规则源URL"""
        print(f"  📥 处理: {url}")
        content = self.download_content(url)
        if not content:
            return
        
        self.process_rule_content(content, url)
    
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
                        urls.append(line)
        
        # 读取白名单源
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
        
        if not urls:
            print("  ⚠️ 未找到规则源URL")
            return
        
        print(f"  找到 {len(urls)} 个规则源")
        
        # 并行处理所有规则源
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url in urls:
                future = executor.submit(self.process_url, url)
                futures.append(future)
            
            # 等待所有任务完成
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result(timeout=30)
                    completed += 1
                    print(f"  ✅ [{completed}/{len(urls)}] 完成")
                except Exception as e:
                    print(f"  ❌ 处理失败: {e}")
        
        print(f"✅ 解析完成:")
        print(f"   黑名单域名: {len(self.black_domains):,} 个")
        print(f"   白名单域名: {len(self.white_domains):,} 个")
        print(f"   复杂规则: 黑名单 {len(self.black_rules):,} 条, 白名单 {len(self.white_rules):,} 条")
    
    def enhance_ad_domains(self):
        """强化广告域名拦截"""
        print("🛡️  强化广告域名拦截...")
        
        original_count = len(self.black_domains)
        
        # 添加强化的广告域名
        for domain in CONFIG['STRONG_AD_DOMAINS']:
            if domain not in self.white_domains:
                self.black_domains.add(domain)
        
        added = len(self.black_domains) - original_count
        if added > 0:
            print(f"  添加 {added} 个强化广告域名")
    
    def apply_intelligent_whitelist(self):
        """智能白名单处理"""
        print("🤔 应用智能白名单...")
        
        original_count = len(self.black_domains)
        
        # 只移除完全匹配的白名单域名（安全操作）
        domains_to_remove = set()
        for white_domain in self.white_domains:
            if white_domain in self.black_domains:
                domains_to_remove.add(white_domain)
        
        self.black_domains -= domains_to_remove
        
        removed = original_count - len(self.black_domains)
        if removed > 0:
            print(f"  安全移除 {removed} 个白名单域名")
    
    def generate_optimized_files(self):
        """生成优化的规则文件"""
        print("📁 生成规则文件...")
        
        # 获取时间
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d')
        
        # 对域名排序
        sorted_black_domains = sorted(self.black_domains)
        
        # 1. 生成优化的ad.txt
        with open('rules/outputs/ad.txt', 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则 - 增强版 v{version}\n")
            f.write(f"! 更新时间: {timestamp}\n")
            f.write(f"! 域名数量: {len(self.black_domains):,} 个\n")
            f.write(f"! 规则数量: {len(self.black_rules):,} 条\n")
            f.write(f"! 强化广告域名: {len(CONFIG['STRONG_AD_DOMAINS'])} 个\n")
            f.write("!\n\n")
            
            # 白名单规则
            if self.white_rules:
                f.write("! ====== 白名单规则 ======\n")
                for rule in sorted(self.white_rules):
                    if rule.startswith('@@'):
                        f.write(f"{rule}\n")
                f.write("\n")
            
            # 核心广告域名（强化拦截的）
            f.write("! ====== 核心广告域名 ======\n")
            for domain in sorted(CONFIG['STRONG_AD_DOMAINS']):
                if domain in self.black_domains:
                    f.write(f"||{domain}^\n")
            
            # 其他广告域名
            f.write("\n! ====== 其他广告域名 ======\n")
            for domain in sorted_black_domains:
                if domain not in CONFIG['STRONG_AD_DOMAINS']:
                    f.write(f"||{domain}^\n")
            
            # 复杂规则
            if self.black_rules:
                f.write("\n! ====== 复杂拦截规则 ======\n")
                for rule in sorted(self.black_rules):
                    if not rule.startswith('@@'):
                        f.write(f"{rule}\n")
        
        # 2. 生成dns.txt（只包含域名）
        with open('rules/outputs/dns.txt', 'w', encoding='utf-8') as f:
            f.write(f"# DNS广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write("#\n\n")
            
            # 分组写入，提高可读性
            batch_size = 1000
            for i in range(0, len(sorted_black_domains), batch_size):
                batch = sorted_black_domains[i:i+batch_size]
                if i > 0:
                    f.write("\n")
                for domain in batch:
                    f.write(f"{domain}\n")
        
        # 3. 生成hosts.txt
        with open('rules/outputs/hosts.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Hosts广告过滤规则 v{version}\n")
            f.write(f"# 更新时间: {timestamp}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,} 个\n")
            f.write("#\n\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n")
            f.write("#\n")
            f.write("# 广告域名\n\n")
            
            # 分批写入
            batch_size = 500
            for i in range(0, len(sorted_black_domains), batch_size):
                batch = sorted_black_domains[i:i+batch_size]
                f.write(f"# 域名 {i+1}-{i+len(batch)}\n")
                for domain in batch:
                    f.write(f"0.0.0.0 {domain}\n")
                f.write("\n")
        
        # 4. 生成规则信息
        info = {
            'version': version,
            'updated_at': timestamp,
            'statistics': {
                'total_processed_rules': self.stats['total_rules_processed'],
                'domains_extracted': self.stats['domains_extracted'],
                'complex_rules_saved': self.stats['complex_rules_saved'],
                'final_blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains),
                'strong_ad_domains': len(CONFIG['STRONG_AD_DOMAINS'])
            }
        }
        
        with open('rules/outputs/info.json', 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("📄 规则文件生成完成:")
        print(f"   ad.txt - AdBlock规则 ({len(self.black_domains):,}个域名)")
        print(f"   dns.txt - DNS规则 ({len(self.black_domains):,}个域名)")
        print(f"   hosts.txt - Hosts规则 ({len(self.black_domains):,}个域名)")
        print(f"   info.json - 统计信息")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("🚀 增强版广告过滤规则生成器")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载并处理规则源
            self.load_and_process_sources()
            
            # 2. 强化广告域名拦截
            self.enhance_ad_domains()
            
            # 3. 应用智能白名单
            self.apply_intelligent_whitelist()
            
            # 4. 生成优化的规则文件
            self.generate_optimized_files()
            
            # 5. 运行测试
            self.run_tests()
            
            # 统计信息
            end_time = time.time()
            elapsed = end_time - start_time
            
            print("\n" + "=" * 60)
            print("🎉 规则生成完成！")
            print(f"⏱️  耗时: {elapsed:.1f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print("📁 规则文件: rules/outputs/")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_tests(self):
        """运行快速测试"""
        print("🔬 运行快速测试...")
        
        # 检查常见广告域名是否被包含
        test_domains = CONFIG['STRONG_AD_DOMAINS']
        missing = []
        
        for domain in test_domains:
            if domain not in self.black_domains:
                missing.append(domain)
        
        if missing:
            print(f"⚠️  警告: 以下强化广告域名缺失:")
            for domain in missing[:5]:  # 只显示前5个
                print(f"   - {domain}")
            print(f"  总计缺失: {len(missing)} 个")
        else:
            print("✅ 所有强化广告域名均已包含")

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
    generator = EnhancedAdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n✨ 规则生成成功！")
        print("🔬 建议运行测试脚本: python test_rules.py")
        print("🔄 将在 GitHub Actions 自动更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
