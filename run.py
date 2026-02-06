#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
精准修复版广告过滤规则生成器（增强版）
解决不拦截和误拦截问题，增加精确匹配和智能过滤
针对测试结果增强：分析工具、横幅广告、错误监控
"""

import os
import re
import json
import time
import logging
import concurrent.futures
from datetime import datetime
from typing import Set, List, Optional, Tuple, Dict
import requests
from urllib.parse import urlparse
from collections import defaultdict

# ========== 配置 ==========
CONFIG = {
    # GitHub信息
    'GITHUB_USER': 'wansheng8',
    'GITHUB_REPO': 'adblock',
    'GITHUB_BRANCH': 'main',
    
    # 性能设置
    'MAX_WORKERS': 15,
    'TIMEOUT': 20,
    'RETRY_TIMES': 3,
    
    # 文件路径
    'BLACK_SOURCE': 'rules/sources/black.txt',
    'WHITE_SOURCE': 'rules/sources/white.txt',
    
    # 输出文件（固定文件名）
    'AD_FILE': 'rules/outputs/ad.txt',
    'DNS_FILE': 'rules/outputs/dns.txt',
    'HOSTS_FILE': 'rules/outputs/hosts.txt',
    'BLACK_FILE': 'rules/outputs/black.txt',
    'WHITE_FILE': 'rules/outputs/white.txt',
    'INFO_FILE': 'rules/outputs/info.json',
    
    # 新增：智能过滤配置
    'INTELLIGENT_FILTERING': {
        'enable_essential_domain_whitelist': True,  # 启用必要域名白名单
        'enable_safe_domains_check': True,          # 启用安全域名检查
        'enable_false_positive_filter': True,       # 启用误报过滤
        'remove_suspicious_wildcards': True,        # 移除可疑通配符
        'keep_popular_domains': True,              # 保留常用域名
        'enable_domain_validation': True           # 启用域名验证
    },
    
    # 增强拦截配置（针对测试结果）
    'ENHANCED_BLOCKING': {
        # 分析工具增强拦截
        'enhance_analytics_blocking': True,
        'block_analytics_execution': True,  # 阻止分析脚本执行
        
        # 横幅广告增强拦截
        'enhance_banner_blocking': True,
        'block_flash_banners': True,
        'block_gif_ads': True,
        'block_static_image_ads': True,
        
        # 错误监控增强拦截
        'enhance_error_monitoring_blocking': True,
        
        # 元素隐藏规则增强
        'generate_element_hiding_rules': True,
        'generate_script_blocking_rules': True,
        
        # 上下文广告增强
        'enhance_contextual_ads': True,
    },
    
    # 必要域名白名单（防止误拦截）
    'ESSENTIAL_DOMAINS': [
        # 常用APP和服务域名
        'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
        'github.com', 'gitlab.com', 'docker.com', 'cloudflare.com',
        'baidu.com', 'tencent.com', 'alibaba.com', 'taobao.com',
        'weixin.qq.com', 'qq.com', 'weibo.com', 'zhihu.com',
        'bilibili.com', 'douyin.com', 'kuaishou.com',
        
        # 操作系统和浏览器
        'windowsupdate.com', 'mozilla.org', 'chromium.org',
        'ubuntu.com', 'debian.org', 'redhat.com',
        
        # 安全证书和加密
        'letsencrypt.org', 'digicert.com', 'symantec.com',
        'verisign.com', 'globalsign.com',
        
        # 开发工具
        'npmjs.com', 'yarnpkg.com', 'pypi.org', 'maven.org',
        'docker.io', 'kubernetes.io', 'terraform.io',
        
        # 常见CDN和云服务
        'akamai.net', 'fastly.net', 'aws.amazon.com',
        'azure.com', 'cloud.google.com', 'aliyun.com',
        'huaweicloud.com', 'tencentcloud.com',
        
        # 邮箱服务
        'gmail.com', 'outlook.com', 'yahoo.com', '163.com',
        '126.com', 'foxmail.com', 'qq.com', 'sina.com',
        
        # 社交媒体
        'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'pinterest.com', 'tiktok.com',
        
        # 支付服务
        'paypal.com', 'stripe.com', 'alipay.com', 'wechat.com',
        'unionpay.com', 'visa.com', 'mastercard.com'
    ],
    
    # 安全域名检查（不拦截这些域名）
    'SAFE_DOMAINS': [
        # 系统域名
        'localhost', 'local', '127.0.0.1', '0.0.0.0', '::1',
        
        # 常用工具
        'stackoverflow.com', 'stackexchange.com', 'github.com',
        'gitlab.com', 'bitbucket.org', 'sourceforge.net',
        
        # 文档和帮助
        'wikipedia.org', 'wikimedia.org', 'archive.org',
        'creativecommons.org', 'gnu.org', 'apache.org',
        
        # 政府和非营利组织
        'gov.cn', 'gov.uk', 'gov', 'org', 'edu', 'mil',
        
        # 开源项目
        'linuxfoundation.org', 'opensource.org', 'gnu.org',
        'apache.org', 'eclipse.org', 'mozilla.org'
    ],
    
    # 可疑规则模式（可能误拦截）
    'SUSPICIOUS_PATTERNS': [
        r'^\|\|([a-z]{1,2})\.com\^',          # 短域名.com
        r'^\|\|([a-z]{1,3})\.(com|net|org)\^', # 很短的主域名
        r'^\|\|([a-z0-9]+-[a-z0-9]+)\.[a-z]+\^', # 带横线的域名
        r'^\|\|([a-z]+)\d+[a-z]+\.[a-z]+\^',   # 数字在中间的域名
        r'^\|\|\*\.',                         # 全通配符
        r'^\|\|.*\$\$.*',                     # 复杂元素规则
        r'^\|\|.*\$\$script.*',               # 脚本拦截规则
        r'^\|\|.*\$\$image.*',                # 图片拦截规则
        r'^\|\|.*\$\$stylesheet.*',           # 样式表拦截规则
    ],
    
    # 保留的关键规则（确保拦截）
    'CRITICAL_PATTERNS': [
        r'^.*doubleclick\.net.*',             # Google广告
        r'^.*googlesyndication\.com.*',       # Google联盟
        r'^.*googleadservices\.com.*',        # Google广告服务
        r'^.*adsense\.com.*',                 # AdSense
        r'^.*amazon-adsystem\.com.*',         # 亚马逊广告
        r'^.*facebook\.com\/ads.*',           # Facebook广告
        r'^.*\.ad\.',                         # 广告子域名
        r'^.*\.ads\.',                        # 广告子域名
        r'^.*\.tracking\.',                   # 追踪子域名
        r'^.*\.analytics\.',                  # 分析子域名
        r'^.*adserver.*',                     # 广告服务器
        r'^.*tracking.*',                     # 追踪相关
        r'^.*analytics.*',                    # 分析相关
        r'^.*metrics.*',                      # 指标相关
        r'^.*beacon.*',                       # 信标
        r'^.*pixel.*',                        # 像素
        r'^.*tagmanager.*',                   # 标签管理
    ],
    
    # 新增：需要增强拦截的分析工具域名
    'ANALYTICS_DOMAINS': [
        # 谷歌分析
        'google-analytics.com', 'analytics.google.com', 'googletagmanager.com',
        'googleadservices.com', 'googlesyndication.com', 'googleadservices.com',
        'doubleclick.net', 'stats.g.doubleclick.net', 'google-analytics-urchin.com',
        
        # 热图工具
        'hotjar.com', 'hotjar.io', 'crazyegg.com', 'mouseflow.com',
        'luckyorange.com', 'inspectlet.com', 'sessioncam.com', 'clicktale.com',
        'uservoice.com', 'usabilitytools.com', 'wisepops.com',
        
        # Yandex 分析
        'yandex.ru', 'yandex.net', 'yandex.com', 'yandexadexchange.net',
        'metrika.yandex.ru', 'mc.yandex.ru', 'yastatic.net',
        
        # 其他分析工具
        'matomo.org', 'piwik.org', 'clicky.com', 'clicky.net',
        'statcounter.com', 'histats.com', 'w3counter.com', 'goingup.com',
        'woopra.com', 'reinvigorate.net', 'sitemeter.com',
        
        # 广告分析
        'adroll.com', 'criteo.com', 'outbrain.com', 'taboola.com',
        'revcontent.com', 'zemanta.com', 'mgid.com', 'content.ad',
        'adblade.com', 'adbrite.com', 'adform.com', 'adition.com',
        'adnxs.com', 'rubiconproject.com', 'openx.net', 'pubmatic.com',
        'indexexchange.com', 'sonobi.com', 'districtm.io',
        
        # 社交媒体分析
        'facebook.com/tr', 'facebook.com/connect', 'twitter.com/i/adsct',
        'linkedin.com/analytics', 'pinterest.com/analytics',
        
        # 视频分析
        'vidyard.com', 'wistia.com', 'vimeo.com/analytics',
        
        # A/B测试工具
        'optimizely.com', 'visualwebsiteoptimizer.com', 'convert.com',
        'abtasty.com', 'kameleoon.com', 'dynamic-yield.com',
    ],
    
    # 新增：横幅广告相关域名
    'BANNER_AD_DOMAINS': [
        # Flash 横幅相关
        '*.swf', '*.flv', '*.f4v', '*.swf?*', 'cdn.flash.com',
        'mediafire.com/*.swf', 'uploaded.net/*.swf',
        
        # 广告网络
        'adzerk.net', 'adblade.com', 'adbrn.com', 'adbrite.com',
        'adbutler.com', 'adcentric.com', 'adcolony.com', 'adform.com',
        'adition.com', 'adnxs.com', 'adotmob.com', 'adperium.com',
        'adsrvr.org', 'advertising.com', 'advertstream.com',
        'adview.cn', 'adxpose.com', 'aerserv.com', 'casalemedia.com',
        'contextweb.com', 'conversantmedia.com', 'criteo.com',
        'districtm.io', 'doubleverify.com', 'e-planning.net',
        'eyereturn.com', 'getclicky.com', 'googleadservices.com',
        'imrworldwide.com', 'indexexchange.com', 'infolinks.com',
        'innovid.com', 'ipinyou.com', 'kargo.com', 'kiosked.com',
        'lijit.com', 'linksynergy.com', 'media.net', 'mediamath.com',
        'meetrics.net', 'mgid.com', 'mopub.com', 'openx.net',
        'outbrain.com', 'pubmatic.com', 'pulpix.com', 'quantserve.com',
        'revcontent.com', 'rubiconproject.com', 'sharethrough.com',
        'sonobi.com', 'sovrn.com', 'spotxchange.com', 'taboola.com',
        'teads.tv', 'telaria.com', 'tremorhub.com', 'triplelift.com',
        'truex.com', 'undertone.com', 'unruly.co', 'video.unrulymedia.com',
        'videologygroup.com', 'yahoo.com/apollo', 'yieldmo.com',
        'yieldone.com', 'yldmgrimg.net', 'zemanta.com',
        
        # 图片广告域名模式
        'adimg.*', 'ads.*', 'banner.*', 'promo.*', 'sponsor.*',
        'adserver.*', 'static.ads.*', 'cdn.ads.*', 'img.ads.*',
        'media.ads.*', 'resources.ads.*', 'servedby.*', 'serving.*',
        'static.doubleclick.net', '*.g.doubleclick.net',
        
        # 中国广告网络
        'tanx.com', 'alimama.com', 'miaozhen.com', 'cnzz.com',
        '51.la', 'baidu.com/cpro', 'cpro.baidu.com', 'hm.baidu.com',
        'eiv.baidu.com', 'pos.baidu.com', 'cpro.baidustatic.com',
        'dup.baidustatic.com', 'google-analytics.com.cn',
        'tongji.baidu.com', 'hmma.baidu.com',
    ],
    
    # 新增：错误监控工具域名
    'ERROR_MONITORING_DOMAINS': [
        # Sentry
        'sentry.io', 'getsentry.com', '*.sentry.io',
        
        # Bugsnag
        'bugsnag.com', 'notify.bugsnag.com', '*.bugsnag.com',
        
        # 其他错误监控
        'rollbar.com', 'airbrake.io', 'raygun.io', 'newrelic.com',
        'appdynamics.com', 'dynatrace.com', 'datadoghq.com',
        'splunk.com', 'loggly.com', 'logentries.com', 'papertrailapp.com',
        'sumologic.com', 'graylog.org', 'elastic.co', 'kibana.org',
        'librato.com', 'circonus.com', 'copperegg.com', 'serverdensity.com',
        'scalyr.com', 'logdna.com', 'logz.io', 'humio.com',
        
        # 性能监控
        'speedcurve.com', 'webpagetest.org', 'gtmetrix.com',
        'pingdom.com', 'uptimerobot.com', 'statuscake.com',
        'freshping.io', 'monitor.us', 'site24x7.com',
        
        # 前端错误监控
        'trackjs.com', 'errorception.com', 'exceptionhub.com',
        'muscula.com', 'errorify.com', 'errorlogger.com',
    ],
    
    # 新增：需要增强拦截的上下文广告
    'CONTEXTUAL_AD_NETWORKS': [
        'adsense.google.com', 'pagead2.googlesyndication.com',
        'ad.doubleclick.net', 'securepubads.g.doubleclick.net',
        'ads.yahoo.com', 'ads.microsoft.com', 'adservice.google.com',
        'adservice.google.*', 'ads.google.com', 'googleads.g.doubleclick.net',
        'partner.googleadservices.com', 'tpc.googlesyndication.com',
        'www.googlesyndication.com', 'www.googleadservices.com',
        'ads.pubmatic.com', 'ads.revcontent.com', 'ads.taboola.com',
        'ads.outbrain.com', 'ads.criteo.com', 'ads.adthrive.com',
        'ads.media.net', 'ads.infolinks.com', 'ads.zemanta.com',
        'ads.gumgum.com', 'ads.nativeads.com', 'ads.content.ad',
        'ads.sonobi.com', 'ads.triplelift.com', 'ads.sharethrough.com',
        'ads.yieldmo.com', 'ads.yieldone.com', 'ads.aerserv.com',
        'ads.smaato.com', 'ads.mopub.com', 'ads.inmobi.com',
        'ads.unity3d.com', 'ads.vungle.com', 'ads.applovin.com',
        'ads.ironsrc.com', 'ads.adcolony.com', 'ads.chartboost.com',
        'ads.tapjoy.com', 'ads.supersonic.com', 'ads.heyzap.com',
        'ads.fyber.com', 'ads.digitalturbine.com',
    ],
    
    # 新增：需要阻止执行的脚本模式
    'BLOCKED_SCRIPT_PATTERNS': [
        # 分析脚本
        r'analytics\.js', r'ga\.js', r'gtm\.js', r'gtm\.php',
        r'stat\.js', r'track\.js', r'beacon\.js', r'pixel\.js',
        r'tagmanager\.js', r'stats\.js', r'counter\.js',
        r'metrics\.js', r'measure\.js', r'collect\.js',
        r'logger\.js', r'log\.js', r'report\.js',
        
        # 广告脚本
        r'ads\.js', r'ad\.js', r'banner\.js', r'popunder\.js',
        r'popup\.js', r'interstitial\.js', r'preroll\.js',
        r'midroll\.js', r'postroll\.js', r'video-ad\.js',
        r'ad-unit\.js', r'ad-container\.js', r'ad-wrapper\.js',
        
        # 错误监控脚本
        r'sentry\.js', r'bugsnag\.js', r'rollbar\.js',
        r'airbrake\.js', r'raygun\.js', r'newrelic\.js',
        r'appdynamics\.js', r'dynatrace\.js', r'datadog\.js',
        
        # 追踪脚本
        r'tracking\.js', r'tracker\.js', r'pixel\.js',
        r'fingerprint\.js', r'cookie\.js', r'session\.js',
        r'user\.js', r'visitor\.js', r'identification\.js',
        
        # 热图脚本
        r'hotjar\.js', r'crazyegg\.js', r'mouseflow\.js',
        r'luckyorange\.js', r'inspectlet\.js', r'sessioncam\.js',
        r'clicktale\.js', r'uservoice\.js',
        
        # A/B测试脚本
        r'optimizely\.js', r'vwo\.js', r'convert\.js',
        r'abtasty\.js', r'kameleoon\.js', r'dynamic-yield\.js',
    ],
    
    # 新增：元素隐藏规则（针对可见广告）
    'ELEMENT_HIDING_RULES': [
        # 通用广告容器
        r'##div[class*="ad-"]',
        r'##div[id*="ad-"]',
        r'##div[class*="banner"]',
        r'##div[id*="banner"]',
        r'##div[class*="advert"]',
        r'##div[id*="advert"]',
        r'##div[class*="sponsor"]',
        r'##div[id*="sponsor"]',
        r'##div[class*="promo"]',
        r'##div[id*="promo"]',
        
        # 内嵌广告
        r'##iframe[src*="ad"]',
        r'##iframe[id*="ad"]',
        r'##iframe[class*="ad"]',
        r'##iframe[src*="banner"]',
        r'##iframe[src*="doubleclick"]',
        r'##iframe[src*="googleadservices"]',
        r'##iframe[src*="googlesyndication"]',
        
        # 图片广告
        r'##img[src*="ad"]',
        r'##img[alt*="广告"]',
        r'##img[alt*="推广"]',
        r'##img[alt*="赞助"]',
        r'##img[title*="广告"]',
        r'##img[src*="banner"]',
        r'##img[src*="sponsor"]',
        r'##img[src*="promo"]',
        
        # 悬浮广告
        r'##div[class*="popup"]',
        r'##div[id*="popup"]',
        r'##div[class*="float"]',
        r'##div[id*="float"]',
        r'##div[class*="overlay"]',
        r'##div[id*="overlay"]',
        r'##div[class*="modal"]',
        r'##div[id*="modal"]',
        r'##div[class*="lightbox"]',
        r'##div[id*="lightbox"]',
        
        # 视频广告
        r'##video[src*="ad"]',
        r'##embed[src*="ad"]',
        r'##object[data*="ad"]',
        r'##video[id*="ad"]',
        r'##video[class*="ad"]',
        
        # 文本广告
        r'##span[class*="ad-text"]',
        r'##span[id*="ad-text"]',
        r'##p[class*="ad-text"]',
        r'##p[id*="ad-text"]',
        r'##a[class*="ad-link"]',
        r'##a[id*="ad-link"]',
        
        # 社交媒体广告
        r'##div[class*="fb-ad"]',
        r'##div[id*="fb-ad"]',
        r'##div[class*="twitter-ad"]',
        r'##div[id*="twitter-ad"]',
        r'##div[class*="instagram-ad"]',
        r'##div[id*="instagram-ad"]',
        
        # 内容推荐广告
        r'##div[class*="outbrain"]',
        r'##div[id*="outbrain"]',
        r'##div[class*="taboola"]',
        r'##div[id*="taboola"]',
        r'##div[class*="revcontent"]',
        r'##div[id*="revcontent"]',
        r'##div[class*="zemanta"]',
        r'##div[id*="zemanta"]',
        r'##div[class*="content-recommendation"]',
        r'##div[id*="content-recommendation"]',
        
        # 原生广告
        r'##div[class*="native-ad"]',
        r'##div[id*="native-ad"]',
        r'##div[class*="sponsored-content"]',
        r'##div[id*="sponsored-content"]',
        r'##article[class*="sponsored"]',
        r'##article[id*="sponsored"]',
        
        # 横幅广告特定类名
        r'##.ad-banner',
        r'##.adsbygoogle',
        r'##.ad-unit',
        r'##.ad-container',
        r'##.ad-wrapper',
        r'##.ad-placement',
        r'##.ad-space',
        r'##.ad-zone',
        r'##.ad-slot',
        r'##.ad-position',
        r'##.ad-holder',
        r'##.ad-box',
        r'##.ad-frame',
        r'##.ad-panel',
        r'##.ad-wall',
        r'##.ad-wallpaper',
        r'##.ad-overlay',
        r'##.ad-interstitial',
        r'##.ad-popup',
        r'##.ad-modal',
        r'##.ad-lightbox',
        r'##.ad-video',
        r'##.ad-audio',
        r'##.ad-flash',
        r'##.ad-gif',
        r'##.ad-image',
        r'##.ad-img',
        r'##.ad-picture',
        r'##.ad-photo',
        r'##.ad-graphic',
        r'##.ad-illustration',
        r'##.ad-icon',
        r'##.ad-logo',
        r'##.ad-brand',
        r'##.ad-caption',
        r'##.ad-text',
        r'##.ad-headline',
        r'##.ad-title',
        r'##.ad-description',
        r'##.ad-body',
        r'##.ad-content',
        r'##.ad-message',
        r'##.ad-callout',
        r'##.ad-teaser',
        r'##.ad-preview',
        r'##.ad-excerpt',
        r'##.ad-summary',
        r'##.ad-abstract',
        r'##.ad-intro',
        r'##.ad-lead',
        r'##.ad-hook',
        r'##.ad-pitch',
        r'##.ad-proposition',
        r'##.ad-offer',
        r'##.ad-deal',
        r'##.ad-promo',
        r'##.ad-coupon',
        r'##.ad-discount',
        r'##.ad-sale',
        r'##.ad-clearance',
        r'##.ad-bargain',
        r'##.ad-special',
        r'##.ad-feature',
        r'##.ad-highlight',
        r'##.ad-spotlight',
        r'##.ad-showcase',
        r'##.ad-exhibit',
        r'##.ad-display',
        r'##.ad-presentation',
        r'##.ad-demonstration',
        r'##.ad-illustration',
        r'##.ad-example',
        r'##.ad-sample',
        r'##.ad-specimen',
        r'##.ad-model',
        r'##.ad-prototype',
        r'##.ad-mockup',
        r'##.ad-dummy',
        r'##.ad-placeholder',
        r'##.ad-stub',
        r'##.ad-skeleton',
    ],
}

# ========== 日志设置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AccurateAdBlockGenerator:
    """精准广告过滤规则生成器"""
    
    def __init__(self):
        self.black_urls = []
        self.white_urls = []
        self.black_domains = set()
        self.white_domains = set()
        self.black_rules = set()
        self.white_rules = set()
        
        # 新增：增强拦截相关属性
        self.analytics_domains = set()
        self.banner_ad_domains = set()
        self.error_monitoring_domains = set()
        self.contextual_ad_domains = set()
        self.element_hiding_rules = set()
        self.blocked_script_rules = set()
        
        # 统计信息
        self.stats = {
            'domains_removed_by_whitelist': 0,
            'domains_removed_by_safe_check': 0,
            'domains_removed_by_suspicious': 0,
            'critical_domains_kept': 0,
            'essential_domains_whitelisted': 0,
            'total_domains_processed': 0,
            
            # 新增统计
            'analytics_domains_blocked': 0,
            'banner_ad_domains_blocked': 0,
            'error_monitoring_domains_blocked': 0,
            'contextual_ad_domains_blocked': 0,
            'element_hiding_rules_added': 0,
            'script_blocking_rules_added': 0,
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
        """创建示例源文件"""
        if not os.path.exists(CONFIG['BLACK_SOURCE']):
            with open(CONFIG['BLACK_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 黑名单规则源（增强版）
# 针对测试结果添加更多针对性规则源

# 基础广告规则
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/tracking.txt

# 分析工具规则（针对分析工具测试失败）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/analytics.txt
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/other.txt

# 横幅广告规则（针对横幅广告测试失败）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/banners.txt

# 错误监控规则（针对错误监控测试失败）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/other.txt

# 元素隐藏规则（针对区块可见性测试失败）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/filters.txt

# 社交媒体跟踪规则
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/social.txt

# 增强拦截规则源（自定义）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/i18n.txt
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/mobile.txt
""")
        
        if not os.path.exists(CONFIG['WHITE_SOURCE']):
            with open(CONFIG['WHITE_SOURCE'], 'w', encoding='utf-8') as f:
                f.write("""# 白名单规则源
# 添加必要的白名单以防止误拦截

# 基本白名单
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist.txt

# 针对常见误拦截的补充白名单
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/whitelist_domains.txt

# 必要功能白名单（防止过度拦截）
https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/other.txt
""")
    
    def load_sources(self) -> bool:
        """加载规则源"""
        print("📋 加载规则源...")
        
        # 加载黑名单源
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
        
        if not self.black_urls:
            print("❌ 没有有效的黑名单源URL")
            return False
        
        print(f"✅ 加载完成: {len(self.black_urls)} 黑名单源, {len(self.white_urls)} 白名单源")
        return True
    
    def download_url(self, url: str) -> Optional[str]:
        """下载URL内容"""
        for attempt in range(CONFIG['RETRY_TIMES']):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'text/plain,text/html'
                }
                
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=CONFIG['TIMEOUT']
                )
                
                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"下载失败 {url}: 状态码 {response.status_code}")
                    
            except Exception as e:
                if attempt < CONFIG['RETRY_TIMES'] - 1:
                    time.sleep(2)
                else:
                    logger.warning(f"下载失败 {url}: {e}")
        
        return None
    
    def download_all_urls(self) -> List[Tuple[str, str, str]]:
        """下载所有URL"""
        print(f"📥 下载规则源...")
        
        all_urls = []
        for url in self.black_urls:
            all_urls.append((url, 'black'))
        for url in self.white_urls:
            all_urls.append((url, 'white'))
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['MAX_WORKERS']) as executor:
            future_to_url = {}
            for url, url_type in all_urls:
                future = executor.submit(self.download_url, url)
                future_to_url[future] = (url, url_type)
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, url_type = future_to_url[future]
                content = future.result()
                if content:
                    results.append((url, url_type, content))
                    print(f"  ✅ 下载成功: {url}")
                else:
                    print(f"  ❌ 下载失败: {url}")
        
        if not results:
            print("❌ 所有规则源下载都失败了！")
            return []
        
        return results
    
    def is_valid_domain(self, domain: str) -> bool:
        """检查域名有效性"""
        if not domain:
            return False
        
        domain = domain.strip().lower()
        
        # 基本检查
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        if '.' not in domain:
            return False
        
        # 排除系统域名
        if domain in ['localhost', 'local', '127.0.0.1', '0.0.0.0', '::1']:
            return False
        
        # 检查格式
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain):
            return False
        
        # 不能有两个连续的点或破折号
        if '..' in domain or '--' in domain:
            return False
        
        # 检查每个部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # 顶级域名至少2个字符
        if len(parts[-1]) < 2:
            return False
        
        for part in parts:
            if len(part) < 1 or len(part) > 63:
                return False
            
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def extract_domains_from_content(self, content: str) -> Tuple[Set[str], Set[str]]:
        """从内容中提取域名（黑白名单）"""
        black_domains = set()
        white_domains = set()
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            
            is_whitelist = line.startswith('@@')
            
            # 提取域名
            domain = None
            
            # 常见格式
            if line.startswith('||'):
                # ||domain.com^ 格式
                if '^' in line:
                    domain = line[2:line.find('^')]
                else:
                    domain = line[2:]
            elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
                # Hosts格式: 0.0.0.0 domain.com
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
            elif line.startswith('@@||'):
                # @@||domain.com^ 白名单格式
                if '^' in line:
                    domain = line[4:line.find('^')]
            elif '.' in line and ' ' not in line and '/' not in line:
                # 简单域名格式
                domain = line.split('^')[0] if '^' in line else line
            
            # 清理和验证域名
            if domain:
                domain = domain.lower()
                domain = re.sub(r'^www\d*\.', '', domain)
                domain = re.sub(r'^\.+|\.+$', '', domain)
                
                if self.is_valid_domain(domain):
                    if is_whitelist:
                        white_domains.add(domain)
                    else:
                        black_domains.add(domain)
        
        return black_domains, white_domains
    
    def apply_essential_whitelist(self, domains: Set[str]) -> Set[str]:
        """应用必要域名白名单"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_essential_domain_whitelist']:
            return domains
        
        print("🔧 应用必要域名白名单...")
        
        essential_set = set(CONFIG['ESSENTIAL_DOMAINS'])
        filtered_domains = set()
        whitelisted_count = 0
        
        for domain in domains:
            is_essential = False
            
            # 检查是否在必要域名列表中
            for essential_domain in essential_set:
                if domain == essential_domain or domain.endswith(f".{essential_domain}"):
                    is_essential = True
                    break
            
            if is_essential:
                whitelisted_count += 1
                self.white_domains.add(domain)  # 添加到白名单
            else:
                filtered_domains.add(domain)
        
        self.stats['essential_domains_whitelisted'] = whitelisted_count
        print(f"  ✅ 白名单保护了 {whitelisted_count} 个必要域名")
        
        return filtered_domains
    
    def check_safe_domains(self, domains: Set[str]) -> Set[str]:
        """检查安全域名"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_safe_domains_check']:
            return domains
        
        print("🔍 检查安全域名...")
        
        safe_set = set(CONFIG['SAFE_DOMAINS'])
        filtered_domains = set()
        removed_count = 0
        
        for domain in domains:
            is_safe = False
            
            # 检查是否是安全域名
            for safe_domain in safe_set:
                if domain == safe_domain or domain.endswith(f".{safe_domain}"):
                    is_safe = True
                    break
            
            if is_safe:
                removed_count += 1
                # 安全域名不添加到黑名单
            else:
                filtered_domains.add(domain)
        
        self.stats['domains_removed_by_safe_check'] = removed_count
        print(f"  ✅ 移除了 {removed_count} 个安全域名")
        
        return filtered_domains
    
    def filter_suspicious_domains(self, domains: Set[str]) -> Set[str]:
        """过滤可疑域名"""
        if not CONFIG['INTELLIGENT_FILTERING']['enable_false_positive_filter']:
            return domains
        
        print("🔍 过滤可疑域名...")
        
        filtered_domains = set()
        removed_count = 0
        
        for domain in domains:
            is_suspicious = False
            
            # 检查是否匹配可疑模式
            for pattern in CONFIG['SUSPICIOUS_PATTERNS']:
                if re.match(pattern, f"||{domain}^"):
                    is_suspicious = True
                    break
            
            # 检查是否为短域名（可能误拦截）
            parts = domain.split('.')
            if len(parts) >= 2 and len(parts[-2]) <= 3 and len(domain) < 10:
                is_suspicious = True
            
            if is_suspicious:
                removed_count += 1
                # 可疑域名不添加到黑名单
            else:
                filtered_domains.add(domain)
        
        self.stats['domains_removed_by_suspicious'] = removed_count
        print(f"  ✅ 过滤了 {removed_count} 个可疑域名")
        
        return filtered_domains
    
    def ensure_critical_domains(self, domains: Set[str]) -> Set[str]:
        """确保关键广告域名被包含"""
        print("🎯 确保关键广告域名...")
        
        final_domains = set(domains)
        added_count = 0
        
        # 关键广告域名列表（确保这些被拦截）
        critical_ad_domains = [
            # Google广告系统
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'adservice.google.com', 'adsense.com', 'google-analytics.com',
            
            # Facebook广告
            'facebook.com/ads', 'fbcdn.net',
            
            # 亚马逊广告
            'amazon-adsystem.com',
            
            # 常见广告网络
            'adnxs.com', 'rubiconproject.com', 'openx.net',
            'criteo.com', 'taboola.com', 'outbrain.com',
            
            # 追踪和统计
            'scorecardresearch.com', 'quantserve.com',
            'chartbeat.com', 'mixpanel.com',
            
            # 中国广告网络
            'tanx.com', 'alimama.com',
            'miaozhen.com', 'cnzz.com', '51.la',
        ]
        
        for critical_domain in critical_ad_domains:
            if critical_domain not in final_domains:
                # 检查是否白名单
                is_whitelisted = False
                for white_domain in self.white_domains:
                    if critical_domain == white_domain or critical_domain.endswith(f".{white_domain}"):
                        is_whitelisted = True
                        break
                
                if not is_whitelisted and self.is_valid_domain(critical_domain):
                    final_domains.add(critical_domain)
                    added_count += 1
        
        self.stats['critical_domains_kept'] = added_count
        print(f"  ✅ 确保了 {added_count} 个关键广告域名")
        
        return final_domains
    
    def apply_precise_whitelist(self, black_domains: Set[str], white_domains: Set[str]) -> Set[str]:
        """应用精确的白名单"""
        print("🎯 应用精确白名单...")
        
        filtered_domains = set(black_domains)
        removed_count = 0
        
        # 构建白名单树以加速匹配
        white_tree = {}
        for domain in white_domains:
            parts = domain.split('.')
            parts.reverse()
            node = white_tree
            for part in parts:
                if part not in node:
                    node[part] = {}
                node = node[part]
            node['*'] = True
        
        # 应用白名单
        for black_domain in black_domains:
            parts = black_domain.split('.')
            parts.reverse()
            node = white_tree
            
            # 检查是否在白名单中
            is_whitelisted = False
            for part in parts:
                if '*' in node:
                    # 完全匹配白名单
                    is_whitelisted = True
                    break
                if part in node:
                    node = node[part]
                else:
                    break
            else:
                if '*' in node:
                    is_whitelisted = True
            
            if is_whitelisted:
                filtered_domains.remove(black_domain)
                removed_count += 1
        
        self.stats['domains_removed_by_whitelist'] = removed_count
        print(f"  ✅ 白名单移除了 {removed_count} 个域名")
        
        return filtered_domains
    
    def enhance_analytics_blocking(self, domains: Set[str]) -> Set[str]:
        """增强分析工具拦截"""
        if not CONFIG['ENHANCED_BLOCKING']['enhance_analytics_blocking']:
            return domains
        
        print("🔧 增强分析工具拦截...")
        
        analytics_set = set(CONFIG['ANALYTICS_DOMAINS'])
        enhanced_domains = set(domains)
        added_count = 0
        
        # 添加分析工具域名
        for analytics_domain in analytics_set:
            # 跳过通配符域名
            if '*' in analytics_domain:
                continue
                
            if analytics_domain not in enhanced_domains:
                # 检查是否在白名单中
                is_whitelisted = False
                for white_domain in self.white_domains:
                    if analytics_domain == white_domain or analytics_domain.endswith(f".{white_domain}"):
                        is_whitelisted = True
                        break
                
                if not is_whitelisted and self.is_valid_domain(analytics_domain):
                    enhanced_domains.add(analytics_domain)
                    self.analytics_domains.add(analytics_domain)
                    added_count += 1
        
        self.stats['analytics_domains_blocked'] = added_count
        print(f"  ✅ 添加了 {added_count} 个分析工具域名到黑名单")
        
        return enhanced_domains
    
    def enhance_banner_ad_blocking(self, domains: Set[str]) -> Set[str]:
        """增强横幅广告拦截"""
        if not CONFIG['ENHANCED_BLOCKING']['enhance_banner_blocking']:
            return domains
        
        print("🔧 增强横幅广告拦截...")
        
        banner_set = set(CONFIG['BANNER_AD_DOMAINS'])
        enhanced_domains = set(domains)
        added_count = 0
        
        # 处理通配符域名
        for banner_pattern in banner_set:
            if '*' in banner_pattern:
                # 通配符域名，不直接添加
                continue
                
            if banner_pattern not in enhanced_domains:
                if self.is_valid_domain(banner_pattern):
                    enhanced_domains.add(banner_pattern)
                    self.banner_ad_domains.add(banner_pattern)
                    added_count += 1
        
        self.stats['banner_ad_domains_blocked'] = added_count
        print(f"  ✅ 添加了 {added_count} 个横幅广告域名到黑名单")
        
        return enhanced_domains
    
    def enhance_error_monitoring_blocking(self, domains: Set[str]) -> Set[str]:
        """增强错误监控拦截"""
        if not CONFIG['ENHANCED_BLOCKING']['enhance_error_monitoring_blocking']:
            return domains
        
        print("🔧 增强错误监控拦截...")
        
        error_set = set(CONFIG['ERROR_MONITORING_DOMAINS'])
        enhanced_domains = set(domains)
        added_count = 0
        
        # 添加错误监控域名
        for error_domain in error_set:
            # 跳过通配符域名
            if '*' in error_domain:
                continue
                
            if error_domain not in enhanced_domains:
                if self.is_valid_domain(error_domain):
                    enhanced_domains.add(error_domain)
                    self.error_monitoring_domains.add(error_domain)
                    added_count += 1
        
        self.stats['error_monitoring_domains_blocked'] = added_count
        print(f"  ✅ 添加了 {added_count} 个错误监控域名到黑名单")
        
        return enhanced_domains
    
    def enhance_contextual_ads_blocking(self, domains: Set[str]) -> Set[str]:
        """增强上下文广告拦截"""
        if not CONFIG['ENHANCED_BLOCKING']['enhance_contextual_ads']:
            return domains
        
        print("🔧 增强上下文广告拦截...")
        
        contextual_set = set(CONFIG['CONTEXTUAL_AD_NETWORKS'])
        enhanced_domains = set(domains)
        added_count = 0
        
        # 添加上下文广告域名
        for contextual_domain in contextual_set:
            # 跳过通配符域名
            if '*' in contextual_domain:
                continue
                
            if contextual_domain not in enhanced_domains:
                if self.is_valid_domain(contextual_domain):
                    enhanced_domains.add(contextual_domain)
                    self.contextual_ad_domains.add(contextual_domain)
                    added_count += 1
        
        self.stats['contextual_ad_domains_blocked'] = added_count
        print(f"  ✅ 添加了 {added_count} 个上下文广告域名到黑名单")
        
        return enhanced_domains
    
    def generate_element_hiding_rules(self):
        """生成元素隐藏规则"""
        if not CONFIG['ENHANCED_BLOCKING']['generate_element_hiding_rules']:
            return
        
        print("🔧 生成元素隐藏规则...")
        
        for rule in CONFIG['ELEMENT_HIDING_RULES']:
            self.element_hiding_rules.add(rule)
        
        self.stats['element_hiding_rules_added'] = len(CONFIG['ELEMENT_HIDING_RULES'])
        print(f"  ✅ 生成了 {len(CONFIG['ELEMENT_HIDING_RULES'])} 个元素隐藏规则")
    
    def generate_script_blocking_rules(self):
        """生成脚本拦截规则"""
        if not CONFIG['ENHANCED_BLOCKING']['generate_script_blocking_rules']:
            return
        
        print("🔧 生成脚本拦截规则...")
        
        # 针对分析脚本的拦截规则
        for pattern in CONFIG['BLOCKED_SCRIPT_PATTERNS']:
            # 移除正则表达式标记
            clean_pattern = pattern.replace(r'\.', '.').replace('\\', '')
            rule = f'||*{clean_pattern}$script,important'
            self.blocked_script_rules.add(rule)
            
            # 同时添加域名级别的拦截
            if '.' in clean_pattern:
                # 提取可能的域名部分
                parts = clean_pattern.split('.')
                if len(parts) >= 2:
                    script_domain = f"{parts[-2]}.{parts[-1]}"
                    if self.is_valid_domain(script_domain):
                        self.black_domains.add(script_domain)
        
        self.stats['script_blocking_rules_added'] = len(CONFIG['BLOCKED_SCRIPT_PATTERNS'])
        print(f"  ✅ 生成了 {len(CONFIG['BLOCKED_SCRIPT_PATTERNS'])} 个脚本拦截规则")
    
    def process_downloaded_content(self, results: List[Tuple[str, str, str]]):
        """处理下载的内容（智能过滤版）"""
        print("🔧 智能处理规则内容...")
        
        all_black_domains = set()
        all_white_domains = set()
        
        # 第一阶段：收集所有域名
        for url, url_type, content in results:
            black_domains, white_domains = self.extract_domains_from_content(content)
            
            if url_type == 'black':
                all_black_domains.update(black_domains)
                # 黑名单源中的白名单也收集
                all_white_domains.update(white_domains)
            else:
                # 白名单源：优先使用
                all_white_domains.update(white_domains)
        
        self.stats['total_domains_processed'] = len(all_black_domains)
        print(f"📊 原始数据: {len(all_black_domains)} 黑名单域名, {len(all_white_domains)} 白名单域名")
        
        # 第二阶段：智能过滤处理
        print("\n🎯 开始智能过滤...")
        
        # 步骤1：应用必要域名白名单
        filtered_domains = self.apply_essential_whitelist(all_black_domains)
        
        # 步骤2：检查安全域名
        filtered_domains = self.check_safe_domains(filtered_domains)
        
        # 步骤3：过滤可疑域名（减少误拦截）
        filtered_domains = self.filter_suspicious_domains(filtered_domains)
        
        # 步骤4：应用精确白名单
        filtered_domains = self.apply_precise_whitelist(filtered_domains, all_white_domains)
        
        # 步骤5：增强分析工具拦截（针对测试失败）
        filtered_domains = self.enhance_analytics_blocking(filtered_domains)
        
        # 步骤6：增强横幅广告拦截（针对测试失败）
        filtered_domains = self.enhance_banner_ad_blocking(filtered_domains)
        
        # 步骤7：增强错误监控拦截（针对测试失败）
        filtered_domains = self.enhance_error_monitoring_blocking(filtered_domains)
        
        # 步骤8：增强上下文广告拦截
        filtered_domains = self.enhance_contextual_ads_blocking(filtered_domains)
        
        # 步骤9：确保关键广告域名（防止不拦截）
        final_domains = self.ensure_critical_domains(filtered_domains)
        
        # 步骤10：生成元素隐藏规则
        self.generate_element_hiding_rules()
        
        # 步骤11：生成脚本拦截规则
        if CONFIG['ENHANCED_BLOCKING']['block_analytics_execution']:
            self.generate_script_blocking_rules()
        
        # 最终结果
        self.black_domains = final_domains
        self.white_domains = all_white_domains
        
        # 生成规则
        for domain in self.black_domains:
            self.black_rules.add(f"||{domain}^")
        
        for domain in self.white_domains:
            self.white_rules.add(f"@@||{domain}^")
        
        print(f"\n✅ 处理完成!")
        print(f"📊 最终结果: {len(self.black_domains)} 黑名单域名, {len(self.white_domains)} 白名单域名")
    
    def generate_files(self):
        """生成规则文件"""
        print("📁 生成规则文件...")
        
        # 检查结果
        if len(self.black_domains) == 0:
            print("⚠️  警告：没有找到任何黑名单域名")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        version = datetime.now().strftime('%Y%m%d_%H%M')
        
        # 1. Adblock规则 (ad.txt) - 增强版
        with open(CONFIG['AD_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 精准广告过滤规则（增强版）
! 生成时间: {timestamp}
! 版本: {version}
! 黑名单域名: {len(self.black_domains):,} 个
! 白名单域名: {len(self.white_domains):,} 个
! 智能过滤统计:
!   - 必要域名保护: {self.stats['essential_domains_whitelisted']} 个
!   - 安全域名排除: {self.stats['domains_removed_by_safe_check']} 个
!   - 可疑域名过滤: {self.stats['domains_removed_by_suspicious']} 个
!   - 白名单移除: {self.stats['domains_removed_by_whitelist']} 个
!   - 关键广告域名: {self.stats['critical_domains_kept']} 个
!   - 分析工具拦截: {self.stats['analytics_domains_blocked']} 个
!   - 横幅广告拦截: {self.stats['banner_ad_domains_blocked']} 个
!   - 错误监控拦截: {self.stats['error_monitoring_domains_blocked']} 个
!   - 上下文广告拦截: {self.stats['contextual_ad_domains_blocked']} 个
!   - 元素隐藏规则: {self.stats['element_hiding_rules_added']} 个
!   - 脚本拦截规则: {self.stats['script_blocking_rules_added']} 个
! 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}
! 针对测试结果增强：
!   - 分析工具脚本执行测试失败 → 增强分析脚本拦截
!   - 横幅广告文件加载测试失败 → 增强横幅广告拦截
!   - 错误监控脚本执行测试失败 → 增强错误监控拦截
!   - 区块可见性测试未通过 → 添加元素隐藏规则

! ========== 白名单规则（防止误拦截） ==========
""")
            for rule in sorted(self.white_rules):
                f.write(f"{rule}\n")
            
            f.write(f"""
! ========== 脚本拦截规则（阻止分析脚本执行） ==========
! 针对测试结果：分析工具脚本执行测试失败，错误监控脚本执行测试失败
""")
            for rule in sorted(self.blocked_script_rules):
                f.write(f"{rule}\n")
            
            f.write("""
! ========== 元素隐藏规则（隐藏可见广告） ==========
! 针对测试结果：区块可见性测试未通过，Flash/GIF/静态图像广告测试失败
""")
            for rule in sorted(self.element_hiding_rules):
                f.write(f"{rule}\n")
            
            f.write("""
! ========== 黑名单规则（精准广告过滤） ==========
! 已应用智能过滤和增强拦截，解决测试中的不拦截问题
""")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 2. DNS规则 (dns.txt)
        with open(CONFIG['DNS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""# DNS过滤规则（增强版）
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}
# 已应用智能过滤和增强拦截，解决测试中的不拦截问题

""")
            for domain in sorted(self.black_domains):
                f.write(f"{domain}\n")
        
        # 3. Hosts规则 (hosts.txt)
        with open(CONFIG['HOSTS_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""# Hosts格式广告过滤规则（增强版）
# 生成时间: {timestamp}
# 版本: {version}
# 域名数量: {len(self.black_domains):,}
# 项目地址: https://github.com/{CONFIG['GITHUB_USER']}/{CONFIG['GITHUB_REPO']}
# 已应用智能过滤和增强拦截，解决测试中的不拦截问题

127.0.0.1 localhost
::1 localhost

# 广告域名屏蔽（智能过滤增强版）
""")
            for domain in sorted(self.black_domains):
                f.write(f"0.0.0.0 {domain}\n")
        
        # 4. 黑名单规则 (black.txt)
        with open(CONFIG['BLACK_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 黑名单规则（增强版）
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.black_domains):,}
! 增强拦截：分析工具、横幅广告、错误监控、上下文广告

""")
            for domain in sorted(self.black_domains):
                f.write(f"||{domain}^\n")
        
        # 5. 白名单规则 (white.txt)
        with open(CONFIG['WHITE_FILE'], 'w', encoding='utf-8') as f:
            f.write(f"""! 白名单规则
! 生成时间: {timestamp}
! 版本: {version}
! 域名数量: {len(self.white_domains):,}

""")
            for domain in sorted(self.white_domains):
                f.write(f"@@||{domain}^\n")
        
        # 6. 规则信息 (info.json)
        info = {
            'version': version,
            'updated_at': datetime.now().isoformat(),
            'rules': {
                'blacklist_domains': len(self.black_domains),
                'whitelist_domains': len(self.white_domains)
            },
            'filtering_stats': self.stats,
            'config': {
                'intelligent_filtering': CONFIG['INTELLIGENT_FILTERING'],
                'enhanced_blocking': CONFIG['ENHANCED_BLOCKING'],
                'essential_domains_count': len(CONFIG['ESSENTIAL_DOMAINS']),
                'safe_domains_count': len(CONFIG['SAFE_DOMAINS']),
                'analytics_domains_count': len(CONFIG['ANALYTICS_DOMAINS']),
                'banner_ad_domains_count': len(CONFIG['BANNER_AD_DOMAINS']),
                'error_monitoring_domains_count': len(CONFIG['ERROR_MONITORING_DOMAINS']),
                'element_hiding_rules_count': len(CONFIG['ELEMENT_HIDING_RULES']),
                'script_blocking_patterns_count': len(CONFIG['BLOCKED_SCRIPT_PATTERNS']),
            },
            'test_improvements': {
                'analytics_tools': '增强脚本执行拦截，解决测试失败',
                'banner_ads': '增强文件加载拦截，解决测试失败',
                'error_monitoring': '增强脚本执行拦截，解决测试失败',
                'visibility_issues': '添加元素隐藏规则，解决可见性测试'
            }
        }
        
        with open(CONFIG['INFO_FILE'], 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2, ensure_ascii=False)
        
        print("✅ 规则文件生成完成")
    
    def generate_readme(self):
        """生成README.md"""
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
        
        readme = f"""# 广告过滤规则（增强版）

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 |
|----------|----------|----------|----------|
| 综合广告过滤规则 | Adblock | `{base_url}/ad.txt` | `{cdn_url}/ad.txt` |
| DNS过滤规则 | DNS | `{base_url}/dns.txt` | `{cdn_url}/dns.txt` |
| Hosts格式规则 | Hosts | `{base_url}/hosts.txt` | `{cdn_url}/hosts.txt` |
| 黑名单规则 | 黑名单 | `{base_url}/black.txt` | `{cdn_url}/black.txt` |
| 白名单规则 | 白名单 | `{base_url}/white.txt` | `{cdn_url}/white.txt` |

**版本 {info['version']} 增强内容：**
- 黑名单域名：{info['rules']['blacklist_domains']:,} 个
- 白名单域名：{info['rules']['whitelist_domains']:,} 个
- 智能过滤：防止误拦截和不拦截问题
- 必要域名保护：{info.get('filtering_stats', {}).get('essential_domains_whitelisted', 0)} 个
- 分析工具拦截：{info.get('filtering_stats', {}).get('analytics_domains_blocked', 0)} 个
- 横幅广告拦截：{info.get('filtering_stats', {}).get('banner_ad_domains_blocked', 0)} 个
- 错误监控拦截：{info.get('filtering_stats', {}).get('error_monitoring_domains_blocked', 0)} 个
- 元素隐藏规则：{info.get('filtering_stats', {}).get('element_hiding_rules_added', 0)} 个
- 脚本拦截规则：{info.get('filtering_stats', {}).get('script_blocking_rules_added', 0)} 个

## 测试优化

针对测试结果的增强拦截：
1. **分析工具**（谷歌分析、热图、Yandex分析）- 脚本执行测试失败 → 已增强拦截
2. **横幅广告**（Flash、GIF、静态图像）- 文件加载测试失败 → 已增强拦截
3. **错误监控**（Sentry、Bugsnag）- 脚本执行测试失败 → 已增强拦截
4. **区块可见性** - 测试未通过 → 已添加元素隐藏规则

## 使用方法

### 命令行运行：
```bash
# 正常运行
python run.py

# 增强拦截模式（推荐）
python run.py --enhanced

# 严格模式（更多过滤）
python run.py --strict

# 宽松模式（减少过滤）
python run.py --loose
