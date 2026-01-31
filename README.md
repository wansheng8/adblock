# 广告过滤规则

简洁高效的广告过滤规则，专注于拦截广告域名。

---

## 订阅地址

| 规则类型 | 规则说明 | 订阅链接 |
|:---------|:---------|:---------|
| **AdBlock规则** | 适用于浏览器广告插件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/ad.txt` |
| **DNS过滤规则** | 适用于DNS过滤软件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/dns.txt` |
| **Hosts规则** | 适用于系统hosts文件 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/hosts.txt` |
| **黑名单规则** | 纯黑名单域名 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/black.txt` |
| **白名单规则** | 排除误拦域名 | `https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/white.txt` |

**版本 20260201 统计：**
- 处理规则源：382 个
- 原始域名：5,578,170 个
- 最终黑名单：1,249,915 个
- 白名单域名：15 个

---

## 使用说明

### 1. 浏览器插件（如uBlock Origin）
1. 打开uBlock Origin设置
2. 点击"规则列表"
3. 点击"导入..."
4. 粘贴订阅地址：`https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/ad.txt`
5. 点击"应用更改"

### 2. DNS过滤（如AdGuard Home）
1. 打开AdGuard Home控制台
2. 进入"过滤器" → "DNS封锁列表"
3. 点击"添加封锁列表"
4. 名称：广告过滤规则
5. URL：`https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/dns.txt`
6. 点击"保存"

### 3. 系统Hosts文件
1. 下载：`https://raw.githubusercontent.com/wansheng8/adblock/main/rules/outputs/hosts.txt`
2. 备份原有hosts文件
3. 将下载的内容追加到hosts文件末尾
4. 刷新DNS缓存

---

## 最新更新时间

**2026-02-01 01:57:03**

*规则每天自动更新*

## 注意事项

1. 本规则包含约 1,249,915 个广告域名
2. 白名单只包含 15 个关键域名
3. 如果发现误拦，请添加到白名单
4. 规则每日自动更新，无需手动操作

---
