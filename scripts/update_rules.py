#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则自动更新脚本
项目地址: https://github.com/wansheng8/adblock
"""

import os
import sys
import json
import time
import hashlib
import requests
import datetime
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class RuleUpdater:
    def __init__(self, config_path: str = "sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        self.load_config()
        
    def load_config(self):
        """加载配置文件"""
        with open(self.base_dir / self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.update_freq = self.config.get('update_frequency', 8)
        self.timezone = self.config.get('timezone', 'Asia/Shanghai')
        self.language = self.config.get('language', 'zh-CN')
        self.sources = self.config.get('sources', [])
        
    def fetch_source(self, source: Dict) -> Tuple[bool, str, Dict]:
        """获取单个规则源"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/plain, */*',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            }
            
            print(f"正在下载: {source['name']}")
            response = requests.get(source['url'], headers=headers, timeout=45)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件
            source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # 返回元数据
            meta = {
                'name': source['name'],
                'type': source.get('type', 'blacklist'),
                'url': source['url'],
                'file': str(raw_file),
                'size': len(content),
                'lines': len(content.split('\n'))
            }
            
            return True, content, meta
            
        except Exception as e:
            print(f"下载失败 {source['name']}: {str(e)}")
            return False, "", {'name': source['name'], 'error': str(e)}
    
    def parse_rules(self, content: str, source_type: str) -> List[str]:
        """解析规则内容"""
        rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 特殊处理不同类型的规则
            if source_type == 'whitelist':
                if not line.startswith('@@'):
                    # 确保白名单规则有正确的语法
                    if line.startswith('||'):
                        line = '@@' + line
                    elif '^' in line:
                        line = '@@' + line
                    else:
                        line = '@@||' + line + '^'
            
            rules.append(line)
            
        return rules
    
    def generate_header(self, rule_count: int, source_count: int, whitelist_count: int = 0) -> str:
        """生成规则文件头部信息"""
        now_beijing = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now_beijing.strftime('%Y-%m-%d %H:%M:%S')
        
        header = f"""! 标题: 去广告合并规则 - 中文版
! 描述: 自动合并的多源广告拦截规则
! 版本: {now_beijing.strftime('%Y%m%d.%H%M')}
! 生成时间: {update_time} (北京时间)
! 总规则数量: {rule_count}
! 黑名单规则: {rule_count - whitelist_count}
! 白名单规则: {whitelist_count}
! 规则源数量: {source_count}
! 建议更新周期: {self.update_freq} 小时
! 项目地址: https://github.com/wansheng8/adblock.git
! 作者: wansheng8
! 许可证: MIT
! 
! 注意: 本文件由自动化脚本生成，请勿手动修改
! 最后更新时间: {update_time}
!
"""
        return header
    
    def generate_faq_section(self) -> str:
        """生成FAQ部分"""
        faq = """
! 常见问题解答:
! 1. 规则添加后不生效？
!    - 请确保规则语法正确，浏览器已重新加载规则
!    - 检查规则是否被其他白名单规则覆盖
!    - 清除浏览器缓存后重试
!
! 2. 遇到误拦截（正常网站无法访问）？
!    - 请访问 https://github.com/wansheng8/adblock.git 提交问题
!    - 临时解决方案：添加网站到白名单 @@||example.com^
!    - 检查是否有冲突的规则
!
! 3. Hosts规则生效慢？
!    - Hosts规则需要刷新DNS缓存：Windows(ipconfig /flushdns)，macOS(sudo dscacheutil -flushcache)
!    - 重启网络服务或设备
!    - 考虑使用DNS级别的广告拦截
!
! 4. 如何自定义规则？
!    - 在规则前加感叹号 ! 注释掉不需要的规则
!    - 添加自定义规则在文件末尾
!    - 使用 @@ 前缀创建白名单例外
!
"""
        return faq
    
    def remove_duplicates(self, rules: List[str]) -> List[str]:
        """移除重复规则并排序"""
        unique_rules = []
        seen = set()
        
        for rule in rules:
            # 规范化规则进行比较
            normalized = rule.strip().lower()
            if normalized not in seen and normalized:
                seen.add(normalized)
                unique_rules.append(rule)
        
        # 排序规则
        def rule_sort_key(r):
            if r.startswith('@@'):
                return (0, r)
            elif r.startswith('||'):
                return (1, r)
            elif r.startswith('|'):
                return (2, r)
            elif r.startswith('##'):
                return (3, r)
            elif r.startswith('/'):
                return (4, r)
            else:
                return (5, r)
        
        return sorted(unique_rules, key=rule_sort_key)
    
    def validate_rule(self, rule: str) -> bool:
        """检查规则是否有效"""
        if not rule or rule.strip() == '':
            return False
        
        if rule.startswith('!'):
            return False
        
        # 常见规则模式
        patterns = [
            r'^@@?\|',
            r'^\/.*\/$',
            r'^\|\|',
            r'^\|',
            r'^\$',
            r'^@@',
            r'^##',
            r'^#@?#',
            r'^0\.0\.0\.0\s+',
            r'^127\.0\.0\.1\s+',
        ]
        
        for pattern in patterns:
            if re.match(pattern, rule):
                return True
        
        return False
    
    def extract_whitelist_rules(self, content: str) -> List[str]:
        """从内容中提取白名单规则"""
        whitelist_rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('@@'):
                whitelist_rules.append(line)
        
        return whitelist_rules
    
    def run(self):
        """执行更新流程"""
        print("=" * 60)
        print("开始更新广告拦截规则")
        print("=" * 60)
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(parents=True, exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(parents=True, exist_ok=True)
        
        all_black_rules = []
        all_white_rules = []
        successful_sources = 0
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        print(f"总共 {len(sorted_sources)} 个规则源")
        print("-" * 60)
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                continue
            
            success, content, meta = self.fetch_source(source)
            
            if success and content:
                source_type = source.get('type', 'blacklist')
                rules = self.parse_rules(content, source_type)
                
                if source_type == 'whitelist':
                    all_white_rules.extend(rules)
                else:
                    # 从黑名单源中提取白名单规则
                    all_white_rules.extend(self.extract_whitelist_rules(content))
                    all_black_rules.extend(rules)
                
                successful_sources += 1
                print(f"  ✓ {source['name']}: {len(rules)} 条规则")
            else:
                print(f"  ✗ {source['name']}: 失败")
        
        print("-" * 60)
        print(f"规则下载完成: {successful_sources}/{len(sorted_sources)} 成功")
        
        # 去重和排序
        print("\n处理规则...")
        black_rules = self.remove_duplicates(all_black_rules)
        white_rules = self.remove_duplicates(all_white_rules)
        
        # 验证规则
        valid_black_rules = [r for r in black_rules if self.validate_rule(r)]
        valid_white_rules = [r for r in white_rules if self.validate_rule(r)]
        
        print(f"黑名单规则: {len(valid_black_rules)} 条")
        print(f"白名单规则: {len(valid_white_rules)} 条")
        
        # 生成文件头部
        total_rules = len(valid_black_rules) + len(valid_white_rules)
        header = self.generate_header(total_rules, successful_sources, len(valid_white_rules))
        faq_section = self.generate_faq_section()
        
        # 生成黑名单文件
        print("\n生成黑名单文件...")
        blacklist_content = header + faq_section + '\n'.join(valid_black_rules)
        
        # 生成白名单文件
        print("生成白名单文件...")
        whitelist_content = header + faq_section + '\n'.join(valid_white_rules)
        
        # 保存文件
        blacklist_file = self.base_dir / 'dist/blacklist.txt'
        whitelist_file = self.base_dir / 'dist/whitelist.txt'
        
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write(blacklist_content)
        
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            f.write(whitelist_content)
        
        # 生成元数据
        metadata = {
            "last_updated": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "total_rules": total_rules,
            "blacklist_rules": len(valid_black_rules),
            "whitelist_rules": len(valid_white_rules),
            "sources_used": successful_sources,
            "next_update": (datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))) + 
                          datetime.timedelta(hours=self.update_freq)).isoformat(),
            "version": datetime.datetime.now().strftime('%Y%m%d.%H%M')
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # 格式化规则文件
        self.format_rules()
        
        print("=" * 60)
        print("更新完成!")
        print(f"黑名单: {blacklist_file}")
        print(f"白名单: {whitelist_file}")
        print(f"总规则数: {total_rules}")
        print(f"下次更新: {metadata['next_update']}")
        print("=" * 60)
        
        return True
    
    def format_rules(self):
        """格式化规则文件"""
        try:
            print("\n格式化规则文件...")
            from scripts.format_rules import RuleFormatter
            formatter = RuleFormatter()
            formatter.format_all()
            print("✓ 规则文件格式化完成")
        except ImportError:
            print("⚠️  格式化模块未找到，跳过格式化")
        except Exception as e:
            print(f"⚠️  格式化失败: {str(e)}")


def main():
    """主函数"""
    updater = RuleUpdater()
    try:
        updater.run()
        sys.exit(0)
    except Exception as e:
        print(f"更新过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
