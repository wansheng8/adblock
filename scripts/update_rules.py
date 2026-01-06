#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
去广告规则自动更新脚本
作者: wansheng8
创建时间: 2024
"""

import os
import sys
import json
import time
import hashlib
import requests
import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import re

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
        
    def fetch_source(self, source: Dict) -> Tuple[bool, str]:
        """获取单个规则源"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件
            source_name = source['name'].replace(' ', '_').lower()
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True, content
            
        except Exception as e:
            print(f"获取规则源 {source['name']} 失败: {str(e)}")
            return False, ""
    
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
                # 确保白名单规则有正确的语法
                if not line.startswith('@@'):
                    line = '@@' + line
                    
            rules.append(line)
            
        return rules
    
    def generate_header(self, rule_count: int, source_count: int) -> str:
        """生成规则文件头部信息"""
        now_beijing = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now_beijing.strftime('%Y-%m-%d %H:%M:%S')
        
        header = f"""! 标题: 去广告合并规则 - 中文版
! 描述: 自动合并的多源广告拦截规则，包含开屏广告、弹窗广告、内嵌广告等过滤
! 版本: {now_beijing.strftime('%Y%m%d.%H%M')}
! 生成时间: {update_time} (北京时间)
! 有效规则数量: {rule_count}
! 规则源数量: {source_count}
! 建议更新周期: {self.update_freq} 小时
! 项目地址: https://github.com/wansheng8/adblock.git
! 作者: wansheng8
! 许可证: MIT
! 支持类型: 
!   - URL过滤规则
!   - 域名过滤规则
!   - 元素隐藏规则(CSS)
!   - 脚本过滤规则
!   - 隐私保护规则
!   - 重定向拦截规则
!   - 反跟踪规则
!   - 恶意网站拦截
!   - 挖矿脚本拦截
!   - 社交媒体插件过滤
!   - 弹窗过滤规则
!   - 视音频广告过滤
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
        
        # 排序：白名单优先，然后是域名规则，最后是复杂规则
        def rule_sort_key(r):
            if r.startswith('@@'):
                return (0, r)
            elif '^' in r and '$' in r:
                return (2, r)
            elif '^' in r:
                return (1, r)
            else:
                return (3, r)
        
        return sorted(unique_rules, key=rule_sort_key)
    
    def validate_rules(self, rules: List[str]) -> List[str]:
        """验证规则语法"""
        valid_rules = []
        invalid_rules = []
        
        for rule in rules:
            # 基本语法检查
            if self.is_valid_rule(rule):
                valid_rules.append(rule)
            else:
                invalid_rules.append(rule)
        
        if invalid_rules:
            print(f"发现 {len(invalid_rules)} 条无效规则")
            with open(self.base_dir / 'rules/invalid_rules.log', 'a', encoding='utf-8') as f:
                f.write(f"检查时间: {datetime.datetime.now()}\n")
                for rule in invalid_rules[:10]:  # 只记录前10条
                    f.write(f"  {rule}\n")
        
        return valid_rules
    
    def is_valid_rule(self, rule: str) -> bool:
        """检查规则是否有效"""
        # 空规则
        if not rule or rule.strip() == '':
            return False
        
        # 注释
        if rule.startswith('!'):
            return False
        
        # 检查基本语法
        patterns = [
            r'^@@?\|',  # 域名规则
            r'^\/.*\/$',  # 正则表达式
            r'^\|\|',  # 域名开始
            r'^\|',  # URL开始
            r'^\$',  # 规则选项
            r'^@@',  # 白名单
            r'^[a-zA-Z0-9*.-]+$',  # 简单主机名
            r'^#@?#',  # 元素隐藏规则
        ]
        
        for pattern in patterns:
            if re.match(pattern, rule):
                return True
        
        return False
    
    def run(self):
        """执行更新流程"""
        print(f"开始更新规则 (北京时间: {datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))})")
        print(f"规则源数量: {len(self.sources)}")
        
        all_black_rules = []
        all_white_rules = []
        successful_sources = 0
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                print(f"跳过禁用源: {source['name']}")
                continue
            
            print(f"正在获取: {source['name']}")
            success, content = self.fetch_source(source)
            
            if success and content:
                rules = self.parse_rules(content, source.get('type', 'blacklist'))
                
                if source.get('type') == 'whitelist':
                    all_white_rules.extend(rules)
                else:
                    all_black_rules.extend(rules)
                
                successful_sources += 1
                print(f"  获取成功: {len(rules)} 条规则")
            else:
                print(f"  获取失败")
        
        print(f"\n规则获取完成: {successful_sources}/{len([s for s in self.sources if s.get('enabled', True)])}")
        
        # 合并和去重
        print("正在处理规则...")
        black_rules = self.remove_duplicates(all_black_rules)
        white_rules = self.remove_duplicates(all_white_rules)
        
        # 验证规则
        black_rules = self.validate_rules(black_rules)
        white_rules = self.validate_rules(white_rules)
        
        # 生成文件头部
        total_rules = len(black_rules) + len(white_rules)
        header = self.generate_header(total_rules, successful_sources)
        faq_section = self.generate_faq_section()
        
        # 生成黑名单文件
        print(f"生成黑名单文件: {len(black_rules)} 条规则")
        blacklist_content = header + faq_section + '\n'.join(black_rules)
        
        # 生成白名单文件
        print(f"生成白名单文件: {len(white_rules)} 条规则")
        whitelist_content = header + faq_section + '\n'.join(white_rules)
        
        # 确保dist目录存在
        dist_dir = self.base_dir / 'dist'
        dist_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存文件
        blacklist_file = dist_dir / 'blacklist.txt'
        whitelist_file = dist_dir / 'whitelist.txt'
        
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            f.write(blacklist_content)
        
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            f.write(whitelist_content)
        
        # 生成元数据
        metadata = {
            "last_updated": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "total_rules": total_rules,
            "blacklist_rules": len(black_rules),
            "whitelist_rules": len(white_rules),
            "sources_used": successful_sources,
            "next_update": (datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))) + 
                          datetime.timedelta(hours=self.update_freq)).isoformat(),
            "version": datetime.datetime.now().strftime('%Y%m%d.%H%M')
        }
        
        with open(dist_dir / 'metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print(f"\n更新完成!")
        print(f"黑名单: {blacklist_file}")
        print(f"白名单: {whitelist_file}")
        print(f"下次更新: {metadata['next_update']}")
        
        return True

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