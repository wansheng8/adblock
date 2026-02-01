#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能优化版广告过滤规则生成器
针对处理慢的问题进行了深度优化
"""

import os
import re
import json
import time
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, List, Optional, Tuple
import requests
from urllib.parse import urlparse
import hashlib

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # ⚡ 性能优化设置
    'MAX_WORKERS': 20,           # 增加线程数
    'TIMEOUT': 15,              # 减少超时时间
    'RETRY_TIMES': 2,           # 减少重试次数
    'BATCH_SIZE': 10000,        # 批量处理大小
    'CACHE_ENABLED': True,      # 启用简单缓存
    'SKIP_URL_VALIDATION': True, # 跳过URL验证（加速）
    
    # 文件路径（固定文件名）
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 输出文件（固定文件名）
    'AD_FILE': 'rules/outputs/ad.txt',
    'DNS_FILE': 'rules/outputs/dns.txt',
    'HOSTS_FILE': 'rules/outputs/hosts.txt',
    'BLACK_FILE': 'rules/outputs/black.txt',
    'WHITE_FILE': 'rules/outputs/white.txt',
    'INFO_FILE': 'rules/outputs/info.json',
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.WARNING,  # 减少日志输出
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FastAdBlockGenerator:
    """快速广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        
        # 性能统计
        self.stats = {
            'load_time': 0,
            'download_time': 0,
            'parse_time': 0,
            'process_time': 0,
            'write_time': 0,
            'total_time': 0,
            'urls_processed': 0,
            'domains_found': 0
        }
        
        # 简单缓存
        self.url_cache = {}
        
        # 创建目录
        self.setup_directories()
    
    def setup_directories(self):
        """创建目录"""
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建示例源文件（仅当不存在时）
        self.create_example_sources()
    
    def create_example_sources(self):
        """创建示例源文件"""
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 黑名单规则源
# 每行一个URL

# AdGuard 基础过滤器（推荐）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt
""")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 白名单规则源
# 每行一个URL

# AdGuard 白名单（推荐）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt
""")
    
    def load_sources_fast(self) -> bool:
        """快速加载规则源"""
        print("📋 加载规则源...")
        start_time = time.time()
        
        # 加载黑名单源（跳过验证以加速）
        if os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                self.black_urls = [line.strip() for line in f 
                                 if line.strip() and not line.startswith('#')]
        else:
            print(f"❌ 黑名单源文件不存在: {CONFIG['BLACK_SOURCE']}")
            return False
        
        # 加载白名单源
        if os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                self.white_urls = [line.strip() for line in f 
                                 if line.strip() and not line.startswith('#')]
        else:
            print(f"⚠️  白名单源文件不存在，继续处理")
        
        # 简单的URL格式检查（快速）
        valid_black_urls = []
        for url in self.black_urls:
            if url.startswith('http://') or url.startswith('https://'):
                valid_black_urls.append(url)
            else:
                print(f"⚠️  跳过无效URL（非HTTP/HTTPS）: {url}")
        
        valid_white_urls = []
        for url in self.white_urls:
            if url.startswith('http://') or url.startswith('https://'):
                valid_white_urls.append(url)
            else:
                print(f"⚠️  跳过无效URL（非HTTP/HTTPS）: {url}")
        
        self.black_urls = valid_black_urls
        self.white_urls = valid_white_urls
        
        if not self.black_urls:
            print("❌ 没有有效的黑名单源URL")
            return False
        
        self.stats['load_time'] = time.time() - start_time
        print(f"✅ 加载完成: {len(self.black_urls)} 黑名单源, {len(self.white_urls)} 白名单源")
        return True
    
    def download_url_fast(self, url: str) -> Optional[str]:
        """快速下载URL内容（带简单缓存）"""
        # 检查缓存
        if CONFIG['CACHE_ENABLED']:
            cache_key = hashlib.md5(url.encode()).hexdigest()
            if cache_key in self.url_cache:
                return self.url_cache[cache_key]
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain,text/html',
                'Accept-Encoding': 'gzip, deflate'
            }
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=CONFIG['TIMEOUT'],
                verify=True,
                stream=False
            )
            
            if response.status_code == 200:
                content = response.text
                
                # 缓存结果
                if CONFIG['CACHE_ENABLED']:
                    cache_key = hashlib.md5(url.encode()).hexdigest()
                    self.url_cache[cache_key] = content
                
                return content
            else:
                logger.warning(f"下载失败 {url}: 状态码 {response.status_code}")
                return None
                
        except Exception as e:
            logger.warning(f"下载失败 {url}: {e}")
            return None
    
    def download_all_fast(self) -> List[Tuple[str, str, str]]:
        """快速下载所有URL"""
        print(f"📥 下载规则源 ({len(self.black_urls) + len(self.white_urls)}个)...")
        start_time = time.time()
        
        all_urls = []
        for url in self.black_urls:
            all_urls.append((url, 'black'))
        for url in self.white_urls:
            all_urls.append((url, 'white'))
        
        results = []
        successful = 0
        failed = 0
        
        # 使用线程池并行下载
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            future_to_url = {executor.submit(self.download_url_fast, url): (url, url_type) 
                           for url, url_type in all_urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, url_type = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        results.append((url, url_type, content))
                        successful += 1
                        if successful % 5 == 0:  # 每5个成功显示一次
                            print(f"  ✅ 已下载 {successful}/{len(all_urls)}")
                    else:
                        failed += 1
                        print(f"  ❌ 下载失败: {url}")
                except Exception as e:
                    failed += 1
                    logger.error(f"下载异常 {url}: {e}")
        
        self.stats['download_time'] = time.time() - start_time
        self.stats['urls_processed'] = len(all_urls)
        
        print(f"✅ 下载完成: {successful}成功, {failed}失败")
        
        if successful == 0:
            print("❌ 所有规则源下载都失败了！")
            return []
        
        return results
    
    def extract_domain_fast(self, line: str) -> Tuple[Optional[str], bool]:
        """快速提取域名"""
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            return None, False
        
        # 快速判断是否为白名单
        is_whitelist = line.startswith('@@')
        if is_whitelist:
            line = line[2:]  # 移除@@
        
        # 常见格式的快速提取
        if line.startswith('||'):
            # 提取 ||domain.com^ 格式
            if '^' in line:
                domain = line[2:line.find('^')]
            else:
                domain = line[2:]
        elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
            # 提取 Hosts 格式: 0.0.0.0 domain.com
            parts = line.split()
            domain = parts[1] if len(parts) > 1 else None
        elif line.startswith('*.'):
            # 提取通配符格式: *.domain.com
            domain = line[2:]
        elif '.' in line and not any(c in line for c in ' /$#%&?'):
            # 简单域名格式
            domain = line.split('^')[0] if '^' in line else line
        else:
            return None, False
        
        # 清理和验证域名
        if domain:
            domain = domain.lower()
            domain = re.sub(r'^www\d*\.', '', domain)
            domain = re.sub(r'^\.+|\.+$', '', domain)
            
            # 快速验证
            if (3 <= len(domain) <= 253 and 
                '.' in domain and
                not any(exclude in domain for exclude in ['localhost', '127.0.0.1', '0.0.0.0', '::1']) and
                re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain)):
                return domain, is_whitelist
        
        return None, False
    
    def parse_content_fast(self, content: str, source_type: str) -> Tuple[Set[str], Set[str]]:
        """快速解析规则内容"""
        black_domains = set()
        white_domains = set()
        
        lines = content.split('\n')
        batch_size = CONFIG['BATCH_SIZE']
        
        # 分批处理以提高性能
        for i in range(0, len(lines), batch_size):
            batch = lines[i:i + batch_size]
            for line in batch:
                domain, is_whitelist = self.extract_domain_fast(line)
                if domain:
                    if is_whitelist:
                        white_domains.add(domain)
                    else:
                        black_domains.add(domain)
        
        return black_domains, white_domains
    
    def process_results_fast(self, results: List[Tuple[str, str, str]]):
        """快速处理下载结果"""
        print("🔍 解析和处理规则...")
        start_time = time.time()
        
        all_black_domains = set()
        all_white_domains = set()
        
        # 第一阶段：并行解析所有内容
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            futures = []
            for url, url_type, content in results:
                future = executor.submit(self.parse_content_fast, content, url_type)
                futures.append((future, url_type))
            
            for future, url_type in futures:
                black_domains, white_domains = future.result()
                
                if url_type == 'black':
                    all_black_domains.update(black_domains)
                    all_white_domains.update(white_domains)  # 黑名单源中的白名单
                else:
                    # 白名单源：优先使用
                    all_white_domains.update(white_domains)
        
        # 第二阶段：应用白名单过滤
        print(f"🔄 应用白名单过滤...")
        print(f"  原始黑名单: {len(all_black_domains):,} 个")
        print(f"  白名单: {len(all_white_domains):,} 个")
        
        # 构建白名单前缀树以加速匹配
        white_tree = {}
        for domain in all_white_domains:
            parts = domain.split('.')
            parts.reverse()
            node = white_tree
            for part in parts:
                if part not in node:
                    node[part] = {}
                node = node[part]
            node['*'] = True
        
        # 使用前缀树快速过滤
        filtered_black_domains = set()
        for domain in all_black_domains:
            parts = domain.split('.')
            parts.reverse()
            node = white_tree
            
            # 检查是否在白名单中
            is_whitelisted = False
            for part in parts:
                if '*' in node:
                    is_whitelisted = True
                    break
                if part in node:
                    node = node[part]
                else:
                    break
            else:
                if '*' in node:
                    is_whitelisted = True
            
            if not is_whitelisted:
                filtered_black_domains.add(domain)
        
        removed = len(all_black_domains) - len(filtered_black_domains)
        print(f"✅ 过滤完成: 移除 {removed} 个域名")
        print(f"  剩余黑名单: {len(filtered_black_domains):,} 个")
        
        self.black_domains = filtered_black_domains
        self.white_domains = all_white_domains
        self.stats['domains_found'] = len(self.black_domains)
        self.stats['parse_time'] = time.time() - start_time
    
    def generate_files_fast(self):
        """快速生成规则文件"""
        print("📁 生成规则文件...")
        start_time = time.time()
        
        # 准备排序的域名列表
        black_domains_sorted = sorted(self.black_domains)
        white_domains_sorted = sorted(self.white_domains)
        
        # 生成所有文件的内容
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d_%H%M')
        base_info = f"! 生成时间: {timestamp}\n! 版本: {version}\n"
        
        # 1. Adblock规则 (ad.txt)
        ad_content = f"""! 广告过滤规则
{base_info}! 黑名单域名: {len(self.black_domains):,} 个
! 白名单域名: {len(self.white_domains):,} 个
! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}

! ========== 白名单规则 ==========
"""
        ad_content += '\n'.join(f'@@||{domain}^' for domain in white_domains_sorted)
        ad_content += '\n\n! ========== 黑名单规则 ==========\n'
        ad_content += '\n'.join(f'||{domain}^' for domain in black_domains_sorted)
        
        # 2. DNS规则 (dns.txt)
        dns_content = f"""# DNS过滤规则
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}

"""
        dns_content += '\n'.join(black_domains_sorted)
        
        # 3. Hosts规则 (hosts.txt)
        hosts_content = f"""# Hosts格式广告过滤规则
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}

127.0.0.1 localhost
::1 localhost

# 广告域名屏蔽
"""
        hosts_content += '\n'.join(f'0.0.0.0 {domain}' for domain in black_domains_sorted)
        
        # 4. 黑名单规则 (black.txt)
        black_content = f"""! 黑名单规则
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.black_domains):,}

"""
        black_content += '\n'.join(f'||{domain}^' for domain in black_domains_sorted)
        
        # 5. 白名单规则 (white.txt)
        white_content = f"""! 白名单规则
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.white_domains):,}

"""
        white_content += '\n'.join(f'@@||{domain}^' for domain in white_domains_sorted)
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains)
            },
            'performance': self.stats
        }
        
        # 批量写入文件
        print("  写入文件...")
        with open(CONFIG['AD_FILE'], 'w', encoding='utf-8') as f:
            f.write(ad_content)
        
        with open(CONFIG['DNS_FILE'], 'w', encoding='utf-8') as f:
            f.write(dns_content)
        
        with open(CONFIG['HOSTS_FILE'], 'w', encoding='utf-8') as f:
            f.write(hosts_content)
        
        with open(CONFIG['BLACK_FILE'], 'w', encoding='utf-8') as f:
            f.write(black_content)
        
        with open(CONFIG['WHITE_FILE'], 'w', encoding='utf-8') as f:
            f.write(white_content)
        
        with open(CONFIG['INFO_FILE'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        self.stats['write_time'] = time.time() - start_time
        print("✅ 规则文件生成完成")
    
    def generate_readme_fast(self):
        """快速生成README.md"""
        print("📖 生成README.md...")
        
        # 读取规则信息
        try:
            with open(CONFIG['INFO_FILE'], 'r', encoding='utf-8') as f:
                info = json.load(f)
        except:
            info = {
                'version': datetime.now().strftime('%Y%m%d'),
                'updated_at': datetime.now().isoformat(),
                'rules': {'blacklist_domains': 0, 'whitelist_domains': 0}
            }
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        # 生成README内容
        readme = f"""# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 更新内容：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("✅ README.md生成完成")
    
    def run_fast(self):
        """快速运行主流程"""
        print("=" * 60)
        print("⚡ 性能优化版广告过滤规则生成器")
        print("=" * 60)
        
        total_start_time = time.time()
        
        try:
            # 1. 快速加载规则源
            print("\n🚀 步骤 1/5: 加载规则源")
            if not self.load_sources_fast():
                return False
            
            # 2. 快速下载所有规则源
            print(f"\n🚀 步骤 2/5: 下载规则源")
            results = self.download_all_fast()
            if not results:
                print("❌ 没有成功下载任何规则源")
                return False
            
            # 3. 快速处理结果
            print(f"\n🚀 步骤 3/5: 解析和处理规则")
            self.process_results_fast(results)
            
            # 4. 快速生成规则文件
            print(f"\n🚀 步骤 4/5: 生成规则文件")
            self.generate_files_fast()
            
            # 5. 快速生成README
            print(f"\n🚀 步骤 5/5: 生成README.md")
            self.generate_readme_fast()
            
            # 计算总时间
            self.stats['total_time'] = time.time() - total_start_time
            self.stats['process_time'] = self.stats['total_time'] - (
                self.stats['load_time'] + self.stats['download_time'] + 
                self.stats['parse_time'] + self.stats['write_time']
            )
            
            # 显示性能统计
            print("\n" + "=" * 60)
            print("🎉 处理完成！")
            print("=" * 60)
            print(f"⏱️  总耗时: {self.stats['total_time']:.2f}秒")
            print(f"📊 性能分析:")
            print(f"  • 加载源文件: {self.stats['load_time']:.2f}秒")
            print(f"  • 下载规则源: {self.stats['download_time']:.2f}秒")
            print(f"  • 解析和处理: {self.stats['parse_time']:.2f}秒")
            print(f"  • 写入文件: {self.stats['write_time']:.2f}秒")
            print(f"  • 其他处理: {self.stats['process_time']:.2f}秒")
            print("=" * 60)
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print(f"📈 处理效率: {self.stats['domains_found'] / max(0.1, self.stats['total_time']):.0f} 域名/秒")
            print("=" * 60)
            print(f"📁 规则文件: rules/outputs/")
            print("📖 文档更新: README.md")
            print("🔗 订阅地址已在README.md中更新")
            print("=" * 60)
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  用户中断程序")
            return False
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """主函数"""
    import sys
    
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("❌ 缺少依赖：requests")
        print("请运行：pip install requests")
        return
    
    # 命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print("⚡ 性能优化版广告过滤规则生成器")
            print("\n使用方法:")
            print("  python run.py              # 正常运行")
            print("  python run.py --test       # 性能测试")
            print("  python run.py --simple     # 极简模式")
            print("  python run.py --benchmark  # 基准测试")
            return
        
        elif sys.argv[1] == '--test':
            print("🔧 性能测试模式")
            CONFIG['MAX_WORKERS'] = 5
            CONFIG['TIMEOUT'] = 10
            CONFIG['RETRY_TIMES'] = 1
            CONFIG['CACHE_ENABLED'] = False
        
        elif sys.argv[1] == '--simple':
            print("🔧 极简模式")
            CONFIG['MAX_WORKERS'] = 5
            CONFIG['TIMEOUT'] = 10
            CONFIG['BATCH_SIZE'] = 1000
        
        elif sys.argv[1] == '--benchmark':
            print("📊 基准测试模式")
            import timeit
            
            # 测试域名提取速度
            test_lines = [
                "||example.com^",
                "||ad.example.com^",
                "0.0.0.0 tracking.com",
                "@@||whitelist.com^",
                "||sub.domain.com^$third-party",
                "# 注释行",
                "! 注释行",
                "",
                "||another-example.com^"
            ]
            
            generator = FastAdBlockGenerator()
            
            # 测试域名提取
            print("测试域名提取速度...")
            start = time.time()
            for line in test_lines * 1000:
                generator.extract_domain_fast(line)
            elapsed = time.time() - start
            print(f"  提取速度: {len(test_lines) * 1000 / elapsed:.0f} 行/秒")
            
            # 测试解析速度
            print("\n测试解析速度...")
            test_content = "\n".join(test_lines * 100)
            start = time.time()
            black, white = generator.parse_content_fast(test_content, 'test')
            elapsed = time.time() - start
            print(f"  解析速度: {len(test_lines) * 100 / elapsed:.0f} 行/秒")
            print(f"  找到域名: {len(black)} 黑名单, {len(white)} 白名单")
            
            return
    
    # 正常运行
    print("⚡ 正在启动性能优化版...")
    print(f"配置: {CONFIG['MAX_WORKERS']}线程, {CONFIG['TIMEOUT']}秒超时")
    
    generator = FastAdBlockGenerator()
    success = generator.run_fast()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("🚀 GitHub Actions会自动提交更新")
    else:
        print("\n💥 规则生成失败！")

if __name__ == "__main__":
    main()
