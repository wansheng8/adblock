#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
精简版广告过滤规则生成器
只使用用户配置的源，提供详细的错误诊断
"""

import os
import re
import json
import time
import socket
import ssl
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, List, Optional, Tuple
import requests
from urllib.parse import urlparse

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 10,
    'TIMEOUT': 60,  # 增加超时时间
    'RETRY_TIMES': 5,
    
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
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AdBlockGenerator:
    """广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 下载统计
        self.download_stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'failed_urls': []
        }
        
        # 创建目录
        self.setup_directories()
    
    def setup_directories(self):
        """创建目录"""
        os.makedirs('rules/sources', exist_ok=True)
        os.makedirs('rules/outputs', exist_ok=True)
        
        # 创建示例源文件
        self.create_example_sources()
    
    def create_example_sources(self):
        """创建示例源文件（只创建文件结构，不预设内容）"""
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 黑名单规则源\n")
                f.write("# 每行一个URL，必须是可公开访问的规则列表\n")
                f.write("# 示例：\n")
                f.write("# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt\n")
                f.write("# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt\n\n")
                f.write("# 请在此处添加您的规则源URL：\n")
            
            logger.info(f"创建空白黑名单源文件: {CONFIG['BLACK_SOURCE']}")
            print(f"⚠️  请编辑 {CONFIG['BLACK_SOURCE']} 添加您的规则源URL")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("# 白名单规则源\n")
                f.write("# 每行一个URL，必须是可公开访问的白名单规则列表\n")
                f.write("# 示例：\n")
                f.write("# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt\n")
                f.write("# https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist_domains.txt\n\n")
                f.write("# 请在此处添加您的白名单源URL：\n")
            
            logger.info(f"创建空白白名单源文件: {CONFIG['WHITE_SOURCE']}")
            print(f"⚠️  请编辑 {CONFIG['WHITE_SOURCE']} 添加您的白名单源URL")
    
    def check_network(self):
        """检查网络连接"""
        print("🔍 检查网络连接...")
        
        test_urls = [
            "https://raw.githubusercontent.com",
            "https://github.com",
            "https://www.google.com"
        ]
        
        for url in test_urls:
            try:
                response = requests.head(url, timeout=10)
                if response.status_code < 400:
                    print(f"  ✅ 可以访问 {url}")
                    return True
            except:
                print(f"  ❌ 无法访问 {url}")
        
        print("❌ 网络连接检查失败，请检查您的网络")
        return False
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """验证URL格式和可达性"""
        try:
            # 检查URL格式
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False, "URL格式不正确"
            
            # 必须是HTTP或HTTPS
            if result.scheme not in ['http', 'https']:
                return False, "只支持HTTP/HTTPS协议"
            
            # 检查是否可访问（快速HEAD请求）
            try:
                response = requests.head(url, timeout=10, allow_redirects=True)
                if response.status_code >= 400:
                    return False, f"服务器返回错误: {response.status_code}"
                
                # 检查内容类型
                content_type = response.headers.get('content-type', '').lower()
                if 'text/plain' not in content_type and 'text/html' not in content_type:
                    logger.warning(f"URL {url} 内容类型不是文本: {content_type}")
                
                return True, "URL验证通过"
                
            except requests.exceptions.RequestException as e:
                return False, f"无法访问URL: {str(e)}"
                
        except Exception as e:
            return False, f"URL解析错误: {str(e)}"
    
    def load_sources(self) -> bool:
        """加载规则源，验证URL"""
        print("📋 加载规则源...")
        
        # 检查网络
        if not self.check_network():
            return False
        
        # 检查源文件是否存在
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            print(f"❌ 黑名单源文件不存在: {CONFIG['BLACK_SOURCE']}")
            return False
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            print(f"❌ 白名单源文件不存在: {CONFIG['WHITE_SOURCE']}")
            return False
        
        # 加载黑名单源
        with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
            
        # 提取和验证URL
        valid_urls = []
        for line_num, line in enumerate(raw_lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                print(f"  验证黑名单源第{line_num}行: {line}")
                valid, message = self.validate_url(line)
                if valid:
                    valid_urls.append(line)
                    print(f"    ✅ {message}")
                else:
                    print(f"    ❌ {message}")
        
        self.black_urls = valid_urls
        
        # 加载白名单源
        with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
            
        valid_urls = []
        for line_num, line in enumerate(raw_lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                print(f"  验证白名单源第{line_num}行: {line}")
                valid, message = self.validate_url(line)
                if valid:
                    valid_urls.append(line)
                    print(f"    ✅ {message}")
                else:
                    print(f"    ❌ {message}")
        
        self.white_urls = valid_urls
        
        # 检查是否有有效的URL
        if not self.black_urls:
            print("❌ 没有有效的黑名单源URL")
            print("💡 请编辑 rules/sources/black.txt 添加规则源")
            return False
        
        if not self.white_urls:
            print("⚠️  没有有效的白名单源URL（可以跳过，但推荐添加）")
            print("💡 您可以编辑 rules/sources/white.txt 添加白名单源")
            # 白名单源可以为空，不返回False
        
        logger.info(f"加载 {len(self.black_urls)} 个黑名单源")
        logger.info(f"加载 {len(self.white_urls)} 个白名单源")
        
        return True
    
    def download_url_with_diagnosis(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """下载URL内容，提供详细的错误诊断"""
        for attempt in range(CONFIG['RETRY_TIMES']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/plain,text/html,application/xhtml+xml',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'max-age=0'
                }
                
                logger.debug(f"尝试下载 {url} (尝试 {attempt + 1}/{CONFIG['RETRY_TIMES']})")
                
                # 设置更详细的超时
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=(15, 45),  # 连接超时15秒，读取超时45秒
                    verify=True,
                    allow_redirects=True,
                    stream=False
                )
                
                response.raise_for_status()
                
                # 检查内容
                if not response.text:
                    raise ValueError("响应内容为空")
                
                logger.info(f"✅ 下载成功: {url} (大小: {len(response.text):,} 字节)")
                return response.text, None
                
            except socket.timeout:
                error_msg = f"连接超时 (尝试 {attempt + 1}/{CONFIG['RETRY_TIMES']})"
                logger.warning(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(3)
                else:
                    return None, f"连接超时，请检查网络或URL是否正确"
                    
            except requests.exceptions.SSLError as e:
                error_msg = f"SSL证书错误: {str(e)}"
                logger.warning(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    return None, error_msg
                    
            except requests.exceptions.ConnectionError as e:
                error_msg = f"连接错误: {str(e)}"
                logger.warning(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    return None, f"无法连接到服务器，请检查URL或网络"
                    
            except requests.exceptions.HTTPError as e:
                error_msg = f"HTTP错误 {e.response.status_code if e.response else '未知'}: {str(e)}"
                logger.warning(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    return None, error_msg
                    
            except requests.exceptions.RequestException as e:
                error_msg = f"请求错误: {str(e)}"
                logger.warning(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    return None, error_msg
                    
            except Exception as e:
                error_msg = f"未知错误: {str(e)}"
                logger.error(f"{error_msg}: {url}")
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    return None, error_msg
        
        return None, "下载失败，超过最大重试次数"
    
    def download_all_urls(self) -> Tuple[bool, List[Tuple[str, str, str]]]:
        """下载所有URL，返回(是否成功, [(url, content, error)])"""
        print("📥 下载规则源...")
        
        all_urls = [(url, 'black') for url in self.black_urls] + \
                   [(url, 'white') for url in self.white_urls]
        
        self.download_stats['total'] = len(all_urls)
        results = []
        failed_urls = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            # 创建下载任务
            future_to_url = {}
            for url, url_type in all_urls:
                future = executor.submit(self.download_url_with_diagnosis, url)
                future_to_url[future] = (url, url_type)
            
            # 处理结果
            for future in concurrent.futures.as_completed(future_to_url):
                url, url_type = future_to_url[future]
                try:
                    content, error = future.result()
                    if content:
                        results.append((url, url_type, content, None))
                        self.download_stats['success'] += 1
                        print(f"  ✅ 下载成功: {url}")
                    else:
                        results.append((url, url_type, None, error))
                        self.download_stats['failed'] += 1
                        self.download_stats['failed_urls'].append(url)
                        failed_urls.append((url, error))
                        print(f"  ❌ 下载失败: {url}")
                        print(f"     错误: {error}")
                except Exception as e:
                    error_msg = f"任务执行错误: {str(e)}"
                    results.append((url, url_type, None, error_msg))
                    self.download_stats['failed'] += 1
                    self.download_stats['failed_urls'].append(url)
                    failed_urls.append((url, error_msg))
                    print(f"  ❌ 下载失败: {url}")
                    print(f"     错误: {error_msg}")
        
        # 检查是否所有必要的源都失败了
        if self.download_stats['success'] == 0:
            print("\n❌ 所有规则源下载都失败了！")
            print("💡 可能的原因：")
            print("   1. 网络连接问题")
            print("   2. URL地址不正确")
            print("   3. 源网站暂时不可用")
            print("   4. 需要科学上网（某些源可能需要）")
            print("\n🔧 解决方案：")
            print("   1. 检查网络连接")
            print("   2. 验证URL是否正确（复制到浏览器中测试）")
            print("   3. 编辑 rules/sources/ 中的文件，更换其他源")
            return False, results
        
        # 检查黑名单源是否全部失败
        black_success = any(1 for url, url_type, content, error in results 
                          if url_type == 'black' and content)
        
        if not black_success:
            print("\n❌ 所有黑名单源都下载失败了！")
            print("💡 请检查 rules/sources/black.txt 中的URL")
            return False, results
        
        # 如果有失败的URL，但不是全部失败，继续处理
        if failed_urls:
            print(f"\n⚠️  部分源下载失败 ({len(failed_urls)}/{len(all_urls)})")
            print("将使用成功下载的源继续处理")
        
        return True, results
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain:
            return False
        
        domain = domain.strip().lower()
        
        # 排除列表
        exclude = ['localhost', 'local', '127.0.0.1', '0.0.0.0', '::1', 
                  'broadcasthost', 'ip6-localhost', 'ip6-loopback']
        if domain in exclude:
            return False
        
        # 长度检查
        if len(domain) < 3 or len(domain) > 253:
            return False
        
        # 必须有点
        if '.' not in domain:
            return False
        
        # 检查格式
        if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
            return False
        
        # 不能有两个连续的点或破折号
        if '..' in domain or '--' in domain:
            return False
        
        # 检查每个部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            # 每部分长度
            if len(part) < 1 or len(part) > 63:
                return False
            
            # 开始和结束字符
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def extract_domain_and_type(self, line: str) -> Tuple[Optional[str], bool]:
        """提取域名和规则类型（是否白名单）"""
        if not line:
            return None, False
        
        line = line.strip()
        
        # 跳过注释
        if line.startswith('!') or line.startswith('#'):
            return None, False
        
        is_whitelist = line.startswith('@@')
        
        # 清理规则
        if is_whitelist:
            line = line[2:]  # 移除@@
        
        # 常见格式匹配
        patterns = [
            # ||domain.com^ 格式
            (r'^\|\|([^\^\$\*\/:]+)', 1),
            (r'^\|\|([^\^]+)\^', 1),
            
            # domain.com^ 格式
            (r'^([a-zA-Z0-9.-]+)\^', 1),
            
            # 纯域名
            (r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', 0),
            
            # Hosts格式: 0.0.0.0 domain.com
            (r'^\d+\.\d+\.\d+\.\d+\s+([^\s#]+)', 1),
            
            # 通配符: *.domain.com
            (r'^\*\.([a-zA-Z0-9.-]+)', 1),
        ]
        
        for pattern, group in patterns:
            match = re.match(pattern, line)
            if match:
                domain = match.group(group if group > 0 else 0).lower()
                
                # 清理域名
                domain = re.sub(r'^www\d*\.', '', domain)  # 移除www前缀
                domain = re.sub(r'^\.+|\.+$', '', domain)  # 移除开头结尾的点
                domain = re.sub(r'\s+', '', domain)        # 移除空格
                
                if self.is_valid_domain(domain):
                    return domain, is_whitelist
        
        return None, False
    
    def parse_content(self, content: str, source_url: str, source_type: str):
        """解析规则内容"""
        lines = content.split('\n')
        black_domains_from_source = set()
        white_domains_from_source = set()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # 跳过空行和注释
            if not line:
                continue
            
            domain, is_whitelist = self.extract_domain_and_type(line)
            
            if domain:
                if is_whitelist:
                    white_domains_from_source.add(domain)
                    
                    # 如果是黑名单源中的白名单，记录下来
                    if source_type == 'black':
                        logger.debug(f"黑名单源 {source_url} 第{line_num}行发现白名单: {domain}")
                else:
                    black_domains_from_source.add(domain)
        
        logger.info(f"解析 {source_url}: 发现 {len(black_domains_from_source)} 黑名单域名, {len(white_domains_from_source)} 白名单域名")
        
        return black_domains_from_source, white_domains_from_source
    
    def process_downloaded_content(self, results: List[Tuple[str, str, str, str]]):
        """处理下载的内容"""
        print("🔍 解析规则内容...")
        
        all_black_domains = set()
        all_white_domains = set()
        
        # 第一阶段：收集所有黑名单源中的域名（包括其中的白名单）
        for url, url_type, content, error in results:
            if content and url_type == 'black':
                black_domains, white_domains = self.parse_content(content, url, 'black')
                all_black_domains.update(black_domains)
                
                # 记录从黑名单源中找到的白名单
                if white_domains:
                    logger.info(f"从黑名单源 {url} 中发现 {len(white_domains)} 个白名单域名")
                    # 暂时保存，后续处理
                    all_white_domains.update(white_domains)
        
        # 第二阶段：处理白名单源（优先级最高）
        for url, url_type, content, error in results:
            if content and url_type == 'white':
                black_domains, white_domains = self.parse_content(content, url, 'white')
                # 白名单源中的白名单优先级最高
                all_white_domains.update(white_domains)
                
                # 白名单源中的黑名单通常应该忽略，但先记录下来
                if black_domains:
                    logger.warning(f"白名单源 {url} 中包含 {len(black_domains)} 个黑名单域名，将忽略")
        
        logger.info(f"收集完成: 总共发现 {len(all_black_domains)} 个黑名单域名，{len(all_white_domains)} 个白名单域名")
        
        # 第三阶段：应用白名单（移除黑名单中的白名单域名）
        print("🔄 应用白名单过滤...")
        
        original_count = len(all_black_domains)
        
        # 1. 直接移除完全匹配的白名单
        domains_to_remove = all_black_domains.intersection(all_white_domains)
        all_black_domains -= domains_to_remove
        
        removed_direct = len(domains_to_remove)
        logger.info(f"直接匹配移除 {removed_direct} 个域名")
        
        # 2. 移除子域名匹配的
        # 优化：按域名长度排序，长的优先匹配
        white_domains_sorted = sorted(all_white_domains, key=len, reverse=True)
        more_to_remove = set()
        
        for black_domain in all_black_domains:
            for white_domain in white_domains_sorted:
                if black_domain.endswith(f".{white_domain}"):
                    more_to_remove.add(black_domain)
                    break
        
        all_black_domains -= more_to_remove
        
        removed_total = original_count - len(all_black_domains)
        logger.info(f"子域名匹配移除 {len(more_to_remove)} 个域名")
        logger.info(f"总共移除 {removed_total} 个域名，剩余 {len(all_black_domains)} 个黑名单域名")
        
        self.black_domains = all_black_domains
        self.white_domains = all_white_domains
        
        # 生成规则集
        for domain in self.black_domains:
            self.black_rules.add(f"||{domain}^")
        
        for domain in self.white_domains:
            self.white_rules.add(f"@@||{domain}^")
    
    def generate_files(self):
        """生成规则文件（固定文件名）"""
        print("📁 生成规则文件...")
        
        # 检查是否有足够的域名
        if len(self.black_domains) == 0:
            print("⚠️  警告：没有找到任何有效的黑名单域名")
            print("💡 可能的原因：")
            print("   1. 规则源内容为空")
            print("   2. 所有域名都被白名单过滤了")
            print("   3. 规则源格式不正确")
        
        # 1. Adblock规则 (ad.txt)
        with open(CONFIG['AD_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"! 广告过滤规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 版本: {datetime.now().strftime('%Y%m%d_%H%M')}\n")
            f.write(f"! 黑名单域名: {len(self.black_domains):,} 个\n")
            f.write(f"! 白名单域名: {len(self.white_domains):,} 个\n")
            f.write(f"! 下载统计: {self.download_stats['success']}/{self.download_stats['total']} 成功\n")
            f.write(f"! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n\n")
            
            # 白名单规则
            if self.white_rules:
                f.write("! ========== 白名单规则 ==========\n")
                for rule in sorted(self.white_rules):
                    f.write(f"{rule}\n")
                f.write("\n")
            
            # 黑名单规则
            f.write("! ========== 黑名单规则 ==========\n")
            if self.black_domains:
                for domain in sorted(self.black_domains):
                    f.write(f"||{domain}^\n")
            else:
                f.write("! 暂无黑名单域名\n")
        
        # 2. DNS规则 (dns.txt)
        with open(CONFIG['DNS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"# DNS过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n\n")
            
            if self.black_domains:
                for domain in sorted(self.black_domains):
                    f.write(f"{domain}\n")
            else:
                f.write("# 暂无域名\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open(CONFIG['HOSTS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"# Hosts格式广告过滤规则\n")
            f.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"# 域名数量: {len(self.black_domains):,}\n")
            f.write(f"# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}\n\n")
            f.write("# 本地主机\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            f.write("# 广告域名屏蔽\n")
            
            if self.black_domains:
                for domain in sorted(self.black_domains):
                    f.write(f"0.0.0.0 {domain}\n")
            else:
                f.write("# 暂无域名\n")
        
        # 4. 黑名单规则 (black.txt)
        with open(CONFIG['BLACK_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"! 黑名单规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"! 域名数量: {len(self.black_domains):,}\n\n")
            
            if self.black_domains:
                for domain in sorted(self.black_domains):
                    f.write(f"||{domain}^\n")
            else:
                f.write("! 暂无域名\n")
        
        # 5. 白名单规则 (white.txt)
        with open(CONFIG['WHITE_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"! 白名单规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 版本: {datetime.now().strftime('%Y%m%d')}\n")
            f.write(f"! 域名数量: {len(self.white_domains):,}\n\n")
            
            if self.white_domains:
                for domain in sorted(self.white_domains):
                    f.write(f"@@||{domain}^\n")
            else:
                f.write("! 暂无域名\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': datetime.now().strftime('%Y%m%d_%H%M'),
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains)
            },
            'download_stats': self.download_stats,
            'sources': {
                'blacklist': len(self.black_urls),
                'whitelist': len(self.white_urls)
            }
        }
        
        with open(CONFIG['INFO_FILE'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("✅ 规则文件生成完成")
    
    def generate_readme(self):
        """生成README.md（只包含3个部分）"""
        print("📖 生成README.md...")
        
        # 读取规则信息
        try:
            with open(CONFIG['INFO_FILE'], 'r', encoding='utf-8') as f:
                info = json.load(f)
        except Exception as e:
            logger.error(f"读取规则信息失败: {e}")
            info = {
                'version': datetime.now().strftime('%Y%m%d'),
                'updated_at': datetime.now().isoformat(),
                'rules': {'blacklist_domains': 0, 'whitelist_domains': 0}
            }
        
        # 生成链接
        base_url = f"https://raw.githubusercontent.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}/{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        cdn_url = f"https://cdn.jsdelivr.net/gh/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}@{CONFIG['GITHUB_BRANCH']}/rules/outputs"
        
        # 只包含3个部分的README
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
- 下载成功率：{info.get('download_stats', {}).get('success', 0)}/{info.get('download_stats', {}).get('total', 0)}

## 最新更新时间

**{info['updated_at'].replace('T', ' ').replace('Z', '')}**

*规则每天自动更新，更新时间：北京时间 02:00*
"""
        
        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(readme)
        
        print("✅ README.md生成完成")
    
    def run(self):
        """运行主流程"""
        print("=" * 60)
        print("广告过滤规则生成器")
        print("只使用用户自定义的规则源")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # 1. 加载并验证规则源
            print("\n步骤 1/5: 加载和验证规则源")
            if not self.load_sources():
                print("\n❌ 规则源加载失败")
                print("💡 请按照以下步骤操作：")
                print("   1. 检查 rules/sources/black.txt 和 white.txt 文件")
                print("   2. 确保URL格式正确（以 http:// 或 https:// 开头）")
                print("   3. 验证URL是否可公开访问")
                print("   4. 重新运行程序")
                return False
            
            # 2. 下载所有规则源
            print(f"\n步骤 2/5: 下载规则源 ({self.download_stats['total']}个)")
            success, results = self.download_all_urls()
            if not success:
                print("\n❌ 规则源下载失败")
                if self.download_stats['failed_urls']:
                    print("失败的URL：")
                    for url in self.download_stats['failed_urls']:
                        print(f"  - {url}")
                print("\n💡 解决方案：")
                print("   1. 检查网络连接")
                print("   2. 将失败的URL复制到浏览器中测试")
                print("   3. 如果URL需要科学上网，请配置代理或更换其他源")
                print("   4. 编辑 rules/sources/ 中的文件，更换可用的源")
                return False
            
            # 3. 解析和处理规则
            print("\n步骤 3/5: 解析和处理规则")
            self.process_downloaded_content(results)
            
            # 4. 生成规则文件
            print("\n步骤 4/5: 生成规则文件")
            self.generate_files()
            
            # 5. 生成README
            print("\n步骤 5/5: 生成README.md")
            self.generate_readme()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("✅ 处理完成！")
            print("=" * 60)
            print(f"⏱️  总耗时: {elapsed_time:.2f}秒")
            print(f"📊 黑名单域名: {len(self.black_domains):,}个")
            print(f"📊 白名单域名: {len(self.white_domains):,}个")
            print(f"📈 下载成功率: {self.download_stats['success']}/{self.download_stats['total']}")
            print("=" * 60)
            print(f"📁 规则文件: rules/outputs/")
            print("📖 文档更新: README.md")
            print("🔗 订阅地址已在README.md中更新")
            print("=" * 60)
            
            # 显示下载失败的URL（如果有）
            if self.download_stats['failed'] > 0:
                print("\n⚠️  以下URL下载失败：")
                for url in self.download_stats['failed_urls']:
                    print(f"  - {url}")
                print("💡 请检查这些URL是否正确或可访问")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  用户中断程序")
            return False
            
        except Exception as e:
            print(f"\n❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()
            
            print("\n💡 可能的原因和解决方案：")
            print("   1. 网络连接问题 - 检查网络")
            print("   2. 规则源格式问题 - 检查 rules/sources/ 中的URL")
            print("   3. 磁盘空间不足 - 检查磁盘空间")
            print("   4. 内存不足 - 减少并发数（修改run.py中的MAX_WORKERS）")
            
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
            print("使用方法:")
            print("  python run.py              # 正常运行")
            print("  python run.py --test <URL> # 测试URL")
            print("  python run.py --config     # 显示当前配置")
            print("  python run.py --list       # 列出当前配置的源")
            return
        
        elif sys.argv[1] == '--test' and len(sys.argv) > 2:
            url = sys.argv[2]
            print(f"🔍 测试URL: {url}")
            generator = AdBlockGenerator()
            content, error = generator.download_url_with_diagnosis(url)
            if content:
                print(f"✅ 测试成功")
                print(f"   内容长度: {len(content):,} 字节")
                print(f"   前200字符: {content[:200]}...")
                
                # 尝试解析内容
                black, white = generator.parse_content(content, url, 'test')
                print(f"   解析结果: {len(black)} 黑名单域名, {len(white)} 白名单域名")
                if black:
                    print(f"   示例域名: {list(black)[:5]}")
            else:
                print(f"❌ 测试失败: {error}")
            return
        
        elif sys.argv[1] == '--config':
            print("当前配置:")
            print(f"  GitHub用户: {CONFIG['GITHUB_USER']}")
            print(f"  仓库: {CONFIG['GITHUB_REPO']}")
            print(f"  分支: {CONFIG['GITHUB_BRANCH']}")
            print(f"  超时时间: {CONFIG['TIMEOUT']}秒")
            print(f"  最大重试: {CONFIG['RETRY_TIMES']}次")
            print(f"  并发数: {CONFIG['MAX_WORKERS']}")
            return
        
        elif sys.argv[1] == '--list':
            generator = AdBlockGenerator()
            
            # 检查文件是否存在
            if os.path.exists(CONFIG['BLACK_SOURCE']):
                print("黑名单源:")
                with open(CONFIG['BLACK_SOURCE'], 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            print(f"  [{i}] {line}")
            else:
                print(f"黑名单源文件不存在: {CONFIG['BLACK_SOURCE']}")
            
            print()
            
            if os.path.exists(CONFIG['WHITE_SOURCE']):
                print("白名单源:")
                with open(CONFIG['WHITE_SOURCE'], 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            print(f"  [{i}] {line}")
            else:
                print(f"白名单源文件不存在: {CONFIG['WHITE_SOURCE']}")
            
            return
    
    # 正常运行
    generator = AdBlockGenerator()
    success = generator.run()
    
    if success:
        print("\n🎉 规则生成成功！")
        print("📄 查看README.md获取订阅链接")
        print("🚀 GitHub Actions会自动提交更新")
    else:
        print("\n💥 规则生成失败！")
        print("💡 请按照上面的提示检查和修复问题")

if __name__ == "__main__":
    main()
