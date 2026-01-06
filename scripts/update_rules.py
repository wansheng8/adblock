#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本
"""

import json
import requests
import datetime
import re
import sys
from pathlib import Path


class RuleUpdater:
    def __init__(self, config_path="sources/sources.json"):
        self.config_path = config_path
        self.base_dir = Path(__file__).parent.parent
        
    def load_config(self):
        """加载配置文件"""
        with open(self.base_dir / self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.sources = self.config.get('sources', [])
        print(f"已加载 {len(self.sources)} 个规则源")
        
    def fetch_source(self, source):
        """获取单个规则源"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"正在获取: {source['name']}")
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件（仅供调试，不提交）
            source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True, content
            
        except Exception as e:
            print(f"获取失败 {source['name']}: {str(e)}")
            return False, ""
    
    def extract_rules(self, content, source_type):
        """从内容中提取规则"""
        black_rules = []
        white_rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 提取白名单规则（以@@开头的）
            if line.startswith('@@'):
                white_rules.append(line)
            else:
                # 黑名单规则
                black_rules.append(line)
        
        # 如果是白名单源，确保所有规则都被标记为白名单
        if source_type == 'whitelist':
            for rule in black_rules.copy():
                # 将黑名单规则转换为白名单规则
                if not rule.startswith('@@'):
                    white_rules.append('@@' + rule if rule.startswith('||') else '@@||' + rule + '^')
            black_rules = []  # 清空白名单源中的黑名单规则
        
        return black_rules, white_rules
    
    def remove_duplicates(self, rules):
        """移除重复规则"""
        unique_rules = []
        seen = set()
        
        for rule in rules:
            norm = rule.strip()
            if norm and norm not in seen:
                seen.add(norm)
                unique_rules.append(rule)
        
        return sorted(unique_rules)
    
    def generate_header(self, black_count, white_count, source_count):
        """生成规则文件头部"""
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now.strftime('%Y-%m-%d %H:%M:%S')
        
        return f"""! 标题: 广告拦截规则
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
! 最后更新时间: {update_time}
!
"""
    
    def run(self):
        """执行更新流程"""
        print("=" * 60)
        print("开始更新广告拦截规则")
        print("=" * 60)
        
        self.load_config()
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(exist_ok=True)
        
        all_black_rules = []
        all_white_rules = []
        successful_sources = 0
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                print(f"跳过禁用源: {source['name']}")
                continue
            
            success, content = self.fetch_source(source)
            
            if success and content:
                black_rules, white_rules = self.extract_rules(content, source.get('type', 'blacklist'))
                
                # 如果是白名单源，只添加白名单规则
                if source.get('type') == 'whitelist':
                    all_white_rules.extend(white_rules)
                    print(f"  ✓ {source['name']} (白名单): {len(white_rules)} 条规则")
                else:
                    # 普通源，黑白名单都添加
                    all_black_rules.extend(black_rules)
                    all_white_rules.extend(white_rules)
                    print(f"  ✓ {source['name']}: {len(black_rules)} 条黑名单, {len(white_rules)} 条白名单")
                
                successful_sources += 1
            else:
                print(f"  ✗ {source['name']}: 失败")
        
        print(f"\n规则获取完成: {successful_sources}/{len(sorted_sources)} 成功")
        
        # 去重
        print("\n处理规则...")
        black_rules = self.remove_duplicates(all_black_rules)
        white_rules = self.remove_duplicates(all_white_rules)
        
        print(f"黑名单规则: {len(black_rules)} 条")
        print(f"白名单规则: {len(white_rules)} 条")
        
        # 生成文件头部
        header = self.generate_header(len(black_rules), len(white_rules), successful_sources)
        
        # 生成黑名单文件
        print("\n生成黑名单文件...")
        blacklist_content = header + '\n'.join(black_rules)
        
        with open(self.base_dir / 'dist/blacklist.txt', 'w', encoding='utf-8') as f:
            f.write(blacklist_content)
        
        # 生成白名单文件
        print("生成白名单文件...")
        whitelist_content = header + '\n'.join(white_rules)
        
        with open(self.base_dir / 'dist/whitelist.txt', 'w', encoding='utf-8') as f:
            f.write(whitelist_content)
        
        # 生成元数据
        metadata = {
            "last_updated": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
            "blacklist_rules": len(black_rules),
            "whitelist_rules": len(white_rules),
            "total_rules": len(black_rules) + len(white_rules),
            "sources_used": successful_sources,
            "next_update": (datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))) + datetime.timedelta(hours=8)).isoformat()
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("更新完成!")
        print(f"黑名单: {len(black_rules)} 条规则")
        print(f"白名单: {len(white_rules)} 条规则")
        print(f"总计: {len(black_rules) + len(white_rules)} 条规则")
        print("=" * 60)
        
        return True


def main():
    updater = RuleUpdater()
    try:
        success = updater.run()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"更新过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
