# 广告过滤规则

简洁高效的广告过滤规则，专注于拦截广告域名。

---

## 订阅地址

| 规则类型 | 规则说明 | 原始链接 | 加速链接 |
|:---------|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/ad.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/dns.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/hosts.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/black.txt` |
| **白名单规则** | 排除误拦域名 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/white.txt` |

**版本 20260201 统计：**
- 原始黑名单：341,638 个
- 最终黑名单：340,342 个
- 白名单域名：10 个

---

## 最新更新时间

**2026-02-01 01:28:08**

*规则每天自动更新*

## 白名单说明

本规则集采用极简白名单策略，只放行少数重要网站：

1. Google相关服务
2. GitHub开发者平台
3. 微软、苹果官方服务
4. 百度、QQ等国内主要服务
5. 知乎、B站、微博、淘宝等常用网站

如需添加更多白名单，请编辑 `rules/sources/white.txt` 文件。
