#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告拦截规则更新脚本 - 完整版（支持混合规则）
生成 blacklist.txt 和 whitelist.txt
"""

import json
import requests
import datetime
import re
import sys
import os
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
        print(f"📋 已加载 {len(self.sources)} 个规则源")
        
    def fetch_mixed_source(self, source):
        """获取混合规则源（包含多个URL）"""
        try:
            print(f"🌐 正在获取混合规则: {source['name']}")
            
            # 首先获取混合规则索引文件
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            # 解析混合规则URL列表
            mixed_urls = response.text.strip().split('\n')
            mixed_urls = [url.strip() for url in mixed_urls if url.strip()]
            
            print(f"  找到 {len(mixed_urls)} 个子规则源")
            
            all_content = []
            successful_sub_sources = 0
            
            # 逐个获取子规则源
            for i, sub_url in enumerate(mixed_urls, 1):
                try:
                    print(f"  正在获取子源 {i}/{len(mixed_urls)}: {sub_url[:60]}...")
                    sub_response = requests.get(sub_url, headers=headers, timeout=20)
                    sub_response.raise_for_status()
                    
                    sub_content = sub_response.text
                    all_content.append(sub_content)
                    successful_sub_sources += 1
                    
                    # 保存原始文件（仅供调试）
                    source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
                    sub_name = re.sub(r'[^\w\-_]', '_', sub_url.split('/')[-1])
                    raw_file = self.base_dir / f"rules/raw/{source_name}_{sub_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    raw_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(raw_file, 'w', encoding='utf-8') as f:
                        f.write(sub_content)
                        
                except Exception as e:
                    print(f"    ❌ 子源获取失败: {str(e)[:50]}")
                    continue
            
            if successful_sub_sources > 0:
                print(f"  ✅ 混合规则获取完成: {successful_sub_sources}/{len(mixed_urls)} 成功")
                return True, '\n'.join(all_content)
            else:
                print(f"  ❌ 所有子源获取失败")
                return False, ""
            
        except Exception as e:
            print(f"❌ 获取混合规则失败 {source['name']}: {str(e)}")
            return False, ""
    
    def fetch_standard_source(self, source):
        """获取标准规则源（单个URL）"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"🌐 正在获取: {source['name']}")
            response = requests.get(source['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # 保存原始文件（仅供调试）
            source_name = re.sub(r'[^\w\-_]', '_', source['name'].lower())
            raw_file = self.base_dir / f"rules/raw/{source_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            raw_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True, content
            
        except Exception as e:
            print(f"❌ 获取失败 {source['name']}: {str(e)}")
            return False, ""
    
    def fetch_source(self, source):
        """获取规则源（根据类型调用不同方法）"""
        source_type = source.get('type', 'blacklist')
        
        if source_type == 'mixed':
            return self.fetch_mixed_source(source)
        else:
            return self.fetch_standard_source(source)
    
    def is_advanced_rule(self, rule):
        """检测是否是高级规则"""
        advanced_patterns = [
            r'#@#',  # 元素隐藏例外
            r'#\?#',  # 高级选择器
            r'\$\$',  # 元素移除
            r'\$removeparam=',  # 参数移除
            r'\$(domain|denyallow)=',  # 域名限定
            r'\$redirect=',  # 重定向
            r'\$cname',  # CNAME
            r'\$(generichide|specifichide)',  # 隐藏规则
            r'\$(badfilter|important)',  # 特殊修饰符
        ]
        
        return any(re.search(pattern, rule) for pattern in advanced_patterns)
    
    def extract_rules(self, content, source_type):
        """从内容中提取规则 - 增强版"""
        black_rules = []
        white_rules = []
        advanced_rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!'):
                continue
            
            # 高级规则检测
            if self.is_advanced_rule(line):
                advanced_rules.append(line)
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
                if not rule.startswith('@@'):
                    white_rules.append('@@' + rule if rule.startswith('||') else '@@||' + rule + '^')
            black_rules = []
        
        return black_rules, white_rules, advanced_rules
    
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
    
    def generate_header(self, black_count, white_count, source_count, update_time):
        """生成规则文件头部"""
        return f"""! 标题: 广告拦截规则
! 描述: 自动合并的多源广告拦截规则（包含混合规则）
! 版本: {datetime.datetime.now().strftime('%Y%m%d.%H%M')}
! 生成时间: {update_time} (北京时间)
! 黑名单规则: {black_count} 条
! 白名单规则: {white_count} 条
! 规则源数量: {source_count} 个
! 更新周期: 每8小时
! 项目地址: https://github.com/wansheng8/adblock.git
! 许可证: MIT License

! ============================================================
! 🎯 拦截内容分类:
! • 开屏广告 - 应用启动时的全屏广告
! • 弹窗广告 - 网页弹窗、浮动窗口广告
! • 视频广告 - 视频前贴片、中插广告
! • 横幅广告 - 页面顶部/底部横幅广告
! • 内联广告 - 文章内容中的原生广告
! • 跟踪器 - 用户行为跟踪脚本
! • 恶意软件 - 钓鱼、挖矿、病毒网站
! • 社交媒体 - 社交分享按钮追踪
! ============================================================

"""
    
    def generate_blacklist_content(self, rules):
        """生成黑名单文件内容（带分类）"""
        # 广告类型分类
        categories = {
            "开屏广告": ["popup", "fullscreen", "interstitial", "splash"],
            "弹窗广告": ["popup", "popunder", "modal", "dialog"],
            "视频广告": ["video", "youtube", "pre-roll", "mid-roll"],
            "横幅广告": ["banner", "leaderboard", "rectangle"],
            "内联广告": ["inline", "native", "text-ad", "content-ad"],
            "跟踪器": ["track", "analytics", "pixel", "cookie"],
            "恶意软件": ["malware", "phishing", "scam", "virus"],
            "社交媒体": ["facebook", "twitter", "share", "like"],
            "通用广告": ["ad", "ads", "advert", "advertising"]
        }
        
        # 按分类分组规则
        categorized_rules = {category: [] for category in categories.keys()}
        categorized_rules["其他广告"] = []
        
        for rule in rules:
            matched = False
            for category, keywords in categories.items():
                if any(keyword in rule.lower() for keyword in keywords):
                    categorized_rules[category].append(rule)
                    matched = True
                    break
            if not matched:
                categorized_rules["其他广告"].append(rule)
        
        # 生成分类内容
        content_lines = []
        
        for category, rules_list in categorized_rules.items():
            if rules_list:
                # 去重
                unique_rules = sorted(set(rules_list))
                
                # 添加分类标题
                content_lines.append(f"! ============================================================")
                content_lines.append(f"! 🎯 {category} ({len(unique_rules)}条)")
                content_lines.append(f"! ============================================================")
                content_lines.append("")
                
                # 添加规则
                content_lines.extend(unique_rules)
                content_lines.append("")
        
        return "\n".join(content_lines).strip()
    
    def generate_whitelist_content(self, rules):
        """生成白名单文件内容"""
        if not rules:
            return "! 暂无白名单规则"
        
        # 去重排序
        unique_rules = sorted(set(rules))
        
        content_lines = []
        content_lines.append("! ============================================================")
        content_lines.append(f"! ✅ 白名单规则 ({len(unique_rules)}条)")
        content_lines.append("! 说明: 以下规则不会被拦截，用于解决误拦截问题")
        content_lines.append("! ============================================================")
        content_lines.append("")
        content_lines.extend(unique_rules)
        
        return "\n".join(content_lines)
    
    def run(self):
        """执行更新流程"""
        print("=" * 60)
        print("🚀 开始更新广告拦截规则（包含混合规则）")
        print("=" * 60)
        
        self.load_config()
        
        # 确保目录存在
        (self.base_dir / 'dist').mkdir(exist_ok=True)
        (self.base_dir / 'rules/raw').mkdir(exist_ok=True)
        
        all_black_rules = []
        all_white_rules = []
        all_advanced_rules = []
        successful_sources = 0
        
        # 按优先级排序
        sorted_sources = sorted(self.sources, key=lambda x: x.get('priority', 999))
        
        for source in sorted_sources:
            if not source.get('enabled', True):
                print(f"⏭️  跳过禁用源: {source['name']}")
                continue
            
            success, content = self.fetch_source(source)
            
            if success and content:
                source_type = source.get('type', 'blacklist')
                black_rules, white_rules, advanced_rules = self.extract_rules(content, source_type)
                
                # 合并高级规则到黑名单
                black_rules.extend(advanced_rules)
                
                if source_type == 'whitelist':
                    all_white_rules.extend(white_rules)
                    print(f"  ✅ {source['name']} (白名单): {len(white_rules)} 条规则")
                elif source_type == 'mixed':
                    all_black_rules.extend(black_rules)
                    all_white_rules.extend(white_rules)
                    print(f"  ✅ {source['name']} (混合): {len(black_rules)} 条黑名单, {len(white_rules)} 条白名单, {len(advanced_rules)} 条高级规则")
                else:
                    all_black_rules.extend(black_rules)
                    all_white_rules.extend(white_rules)
                    print(f"  ✅ {source['name']}: {len(black_rules)} 条黑名单, {len(white_rules)} 条白名单, {len(advanced_rules)} 条高级规则")
                
                successful_sources += 1
            else:
                print(f"  ❌ {source['name']}: 失败")
        
        print(f"\n📊 规则获取完成: {successful_sources}/{len(sorted_sources)} 成功")
        
        # 去重
        print("\n🔧 处理规则...")
        black_rules = self.remove_duplicates(all_black_rules)
        white_rules = self.remove_duplicates(all_white_rules)
        
        print(f"📦 黑名单规则: {len(black_rules)} 条")
        print(f"📦 白名单规则: {len(white_rules)} 条")
        
        # 生成时间
        now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
        update_time = now.strftime('%Y-%m-%d %H:%M:%S')
        
        # 生成黑名单文件
        print("\n📄 生成黑名单文件...")
        header = self.generate_header(len(black_rules), len(white_rules), successful_sources, update_time)
        blacklist_content = header + self.generate_blacklist_content(black_rules)
        
        with open(self.base_dir / 'dist/blacklist.txt', 'w', encoding='utf-8') as f:
            f.write(blacklist_content)
        
        # 生成白名单文件
        print("📄 生成白名单文件...")
        whitelist_content = header + self.generate_whitelist_content(white_rules)
        
        with open(self.base_dir / 'dist/whitelist.txt', 'w', encoding='utf-8') as f:
            f.write(whitelist_content)
        
        # 生成元数据
        metadata = {
            "last_updated": now.isoformat(),
            "blacklist_rules": len(black_rules),
            "whitelist_rules": len(white_rules),
            "total_rules": len(black_rules) + len(white_rules),
            "sources_used": successful_sources,
            "sources_total": len(sorted_sources),
            "next_update": (now + datetime.timedelta(hours=8)).isoformat(),
            "categories": {
                "popup_ads": "开屏/弹窗广告",
                "video_ads": "视频广告", 
                "banner_ads": "横幅广告",
                "inline_ads": "内联广告",
                "trackers": "跟踪器",
                "malware": "恶意软件",
                "social_media": "社交媒体"
            },
            "source_types": {
                "mixed_sources": sum(1 for s in sorted_sources if s.get('type') == 'mixed' and s.get('enabled', True)),
                "advanced_rules": sum(1 for rule in black_rules + white_rules if self.is_advanced_rule(rule))
            }
        }
        
        with open(self.base_dir / 'dist/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print("\n" + "=" * 60)
        print("✅ 更新完成!")
        print(f"📊 黑名单: {len(black_rules)} 条规则")
        print(f"📊 白名单: {len(white_rules)} 条规则")
        print(f"📊 总计: {len(black_rules) + len(white_rules)} 条规则")
        print(f"📦 混合规则源: {metadata['source_types']['mixed_sources']} 个")
        print(f"⚡ 高级规则: {metadata['source_types']['advanced_rules']} 条")
        print(f"⏰ 下次更新: {(now + datetime.timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}")
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
        print(f"❌ 更新过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
