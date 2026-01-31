# 广告过滤规则

一个自动更新的广告过滤规则集合，适用于各种广告拦截器和DNS过滤器。

## 订阅地址

| 规则名称 | 规则类型 | 原始链接 | 加速链接 | 说明 |
|----------|----------|----------|----------|------|
| 广告过滤规则 | Adblock | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/ad.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/ad.txt` | 主规则，推荐使用 |
| DNS过滤规则 | DNS | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/dns.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/dns.txt` | Pi-hole/AdGuard Home |
| Hosts格式规则 | Hosts | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/hosts.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/hosts.txt` | 系统Hosts文件 |
| 黑名单规则 | 黑名单 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/black.txt` | 纯黑名单域名 |
| 白名单规则 | 白名单 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white.txt` | `https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/rules/outputs/white.txt` | 排除误杀 |

**版本 20260201 规则统计：**
- 黑名单域名：200,000 个
- 白名单域名：0 个
- 总域名数：200,000 个
- 规则源：375 个

## 最新更新时间

**2026-02-01 03:09:22.333946**

*规则每天自动更新，更新时间：北京时间 02:00*

## 使用建议

1. **AdGuard/uBlock Origin**：使用 `ad.txt` 文件
2. **Pi-hole/AdGuard Home**：使用 `dns.txt` 文件
3. **系统Hosts**：使用 `hosts.txt` 文件（前10万条）
4. **误报处理**：查看 `white.txt` 或提交Issue

## 特点

- **轻量高效**：经过优化，生成速度快
- **质量优先**：筛选高质量广告域名
- **自动更新**：每日自动更新
- **多格式支持**：支持Adblock、DNS、Hosts格式

---
*生成器代码：https://github.com/wansheng8/adblock*
