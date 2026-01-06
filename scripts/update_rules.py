#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则自动更新脚本
"""

import json
import requests
import datetime
import re
import os
import sys
from pathlib import Path


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        self.load_config()
    
    def load_config(self):
        with open(self.base_dir / self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        self.sources = self.config.get('sources', [])
    
    def fetch_source(self, source):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"正在获取: {source['name']}")
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            return True, response.text
            
        except Exception as e:
            print(f"获取失败 {source['name']}: {e}")
            return False, ""
    
    def parse_rules(self, content, source_type):
        rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue
            
            if source_type == 'whitelist' and not line.startswith('@@'):
                if line.startswith('||'):
                    line = '@@' + line
                elif '^' in line:
                    line = '@@' + line
            
            rules.append(line)
        
        return rules
    
    def remove_duplicates(self, rules):
        unique = []
        seen = set()
        
        for rule in rules:
            norm = rule.strip().lower()
            if norm not in seen and norm:
                seen.add(norm)
                unique.append(rule)
        
        return sorted(unique)
    
    def generate_header(self, black_count, white_count, source_count):
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now.strftime('%Y-%m-%d %H:%M:%S')
        
        return f"""! 标题: 去广告合并规则
! 描述: 自动合并的多源广告拦截规则
! 版本: {now.strftime('%Y%m%d.%H%M')}
! 生成时间: {update_time} (北京时间)
! 黑名单规则: {black_count}
! 白名单规则: {white_count}
! 规则源数量: {source_count}
! 建议更新周期: 8小时
! 项目地址: https://github.com/wansheng8/adblock.git
! 许可证: MIT
! 
! 注意: 本文件由自动化脚本生成
! 最后更新时间: {update_time}
!
"""
    
    def run(self):
        print("开始更新广告拦截规则...")
        print("=" * 60)
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(exist_ok=True)
        
        all_black = []
        all_white = []
        successful = 0
        
        for source in self.sources:
            if not source.get('enabled', True):
                continue
            
            success, content = self.fetch_source(source)
            if success and content:
                rules = self.parse_rules(content, source.get('type', 'blacklist'))
                
                if source.get('type') == 'whitelist':
                    all_white.extend(rules)
                else:
                    all_black.extend(rules)
                
                # 保存原始文件
                source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
                raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(raw_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                successful += 1
                print(f"  ✓ {source['name']}: {len(rules)} 条规则")
            else:
                print(f"  ✗ {source['name']}: 失败")
        
        print(f"\n规则获取完成: {successful}/{len([s for s in self.sources if s.get('enabled', True)])}")
        
        # 处理规则
        black_rules = self.remove_duplicates(all_black)
        white_rules = self.remove_duplicates(all_white)
        
        # 生成文件
        header = self.generate_header(len(black_rules), len(white_rules), successful)
        
        # 黑名单文件
        with open(self.base_dir / 'dist/blacklist.txt', 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(black_rules))
        
        # 白名单文件
        with open(self.base_dir / 'dist/whitelist.txt', 'w', encoding='utf-8') as f:
            f.write(header)
            f.write('\n'.join(white_rules))
        
        # 元数据
        metadata = {
            "last_updated": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "blacklist_rules": len(black_rules),
            "whitelist_rules": len(white_rules),
            "total_rules": len(black_rules) + len(white_rules),
            "sources_used": successful,
            "next_update": (datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))) + datetime.timedelta(hours=8)).isoformat()
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print(f"更新完成!")
        print(f"黑名单规则: {len(black_rules)} 条")
        print(f"白名单规则: {len(white_rules)} 条")
        print(f"总规则数: {len(black_rules) + len(white_rules)} 条")
        print("=" * 60)
        
        return True


def main():
    updater = RuleUpdater()
    try:
        updater.run()
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
