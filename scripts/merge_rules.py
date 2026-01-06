#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path

class RuleMerger:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
    def merge_special_rules(self):
        """合并特殊类型的规则"""
        # 这里可以添加自定义规则合并逻辑
        custom_rules = [
            "! 自定义规则开始",
            "! 开屏广告拦截",
            "||*.splashad.*^",
            "||*ad.splash*^$third-party",
            "! 弹窗广告",
            "||popad.*.js^",
            "||*.popup.*^",
            "! 视频广告",
            "||*.video-ad.*^",
            "||*pre-roll*^",
            "! 社交媒体跟踪",
            "||connect.facebook.net^$third-party",
            "||platform.twitter.com^$third-party",
            "! 挖矿脚本拦截",
            "||coin-hive.com^",
            "||miner.*.js^",
            "! 隐私保护",
            "||*.google-analytics.com^",
            "||*.doubleclick.net^"
        ]
        
        return custom_rules

if __name__ == "__main__":
    merger = RuleMerger()
    rules = merger.merge_special_rules()
    print("自定义规则生成完成")