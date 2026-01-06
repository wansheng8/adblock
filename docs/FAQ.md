\# 常见问题解答 (FAQ)



\## 基本问题



\### Q1: 如何订阅这些规则？

\*\*A:\*\* 在支持AdBlock Plus语法的广告拦截器中添加以下订阅链接：

\- 黑名单: `https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt`

\- 白名单: `https://raw.githubusercontent.com/wansheng8/adblock/main/dist/whitelist.txt`



\### Q2: 支持哪些广告拦截器？

\*\*A:\*\* 本规则支持所有兼容AdBlock Plus语法的拦截器：

\- AdGuard (所有平台)

\- uBlock Origin

\- AdBlock Plus

\- AdBlock

\- 浏览器内置拦截器



\## 技术问题



\### Q3: 规则不生效怎么办？

\*\*解决方案:\*\*

1\. \*\*检查订阅状态\*\*

&nbsp;  - 确认规则已成功订阅

&nbsp;  - 检查规则更新时间



2\. \*\*清除缓存\*\*

&nbsp;  ```bash

&nbsp;  # 浏览器缓存

&nbsp;  Ctrl+Shift+Delete (Windows/Linux)

&nbsp;  Cmd+Shift+Delete (macOS)

&nbsp;  

&nbsp;  # DNS缓存

&nbsp;  Windows: ipconfig /flushdns

&nbsp;  macOS: sudo dscacheutil -flushcache

&nbsp;  Linux: sudo systemd-resolve --flush-caches

&nbsp;  ```



3\. \*\*检查规则语法\*\*

&nbsp;  - 确保没有语法冲突

&nbsp;  - 检查规则是否被覆盖



\### Q4: 遇到误拦截怎么处理？

\*\*解决方案:\*\*

1\. \*\*临时禁用\*\*

&nbsp;  - 在问题网站上临时禁用广告拦截器



2\. \*\*添加白名单\*\*

&nbsp;  ```adblock

&nbsp;  @@||example.com^

&nbsp;  @@||subdomain.example.com^$document

&nbsp;  ```



3\. \*\*报告问题\*\*

&nbsp;  - 访问GitHub Issues页面报告误拦截

&nbsp;  - 提供具体网址和截图



\### Q5: Hosts规则为什么生效慢？

\*\*原因和解决方案:\*\*

1\. \*\*DNS缓存\*\*

&nbsp;  - 系统DNS缓存可能导致延迟

&nbsp;  - 解决方法: 刷新DNS缓存



2\. \*\*浏览器缓存\*\*

&nbsp;  - 浏览器DNS缓存独立于系统

&nbsp;  - 解决方法: 重启浏览器或清除缓存



3\. \*\*使用DNS-over-HTTPS\*\*

&nbsp;  - 现代浏览器可能绕过Hosts文件

&nbsp;  - 在浏览器设置中禁用安全DNS



\## 性能优化



\### Q6: 规则太多会影响速度吗？

\*\*A:\*\* 现代广告拦截器使用高效算法，规则数量对性能影响极小。但如果设备性能较低，可以：

1\. 减少订阅源数量

2\. 禁用不需要的规则类型

3\. 使用简化版规则



\### Q7: 如何自定义规则？

\*\*A:\*\* 创建自定义规则文件 `myrules.txt`:

```adblock

! 我的自定义规则

||ads.mycompany.com^

@@||whitelist.site.com^

\#@?#div\[class\*="ad"]:style(display: none !important;)

```



\## 高级功能



\### Q8: 如何支持特定类型的广告拦截？

\*\*语法示例:\*\*

```adblock

! 开屏广告

||\*.splashad.\*^

||\*ad.splash\*^$third-party



! 弹窗

||popad.\*.js^

||\*.popup.\*^$popup



! 视频广告

||\*.video-ad.\*^

||\*pre-roll\*^$media



! 隐私保护

||\*.google-analytics.com^

||\*.doubleclick.net^$third-party

```



\### Q9: 规则更新频率可以调整吗？

\*\*A:\*\* 是的，修改 `sources/sources.json` 中的 `update\_frequency` 值。



\## 故障排除



\### Q10: GitHub Actions更新失败

\*\*检查步骤:\*\*

1\. 查看Actions日志

2\. 检查网络连接

3\. 验证规则源URL是否可用

4\. 检查API速率限制



\### Q11: 规则文件无法访问

\*\*解决方案:\*\*

1\. 确认GitHub Pages已启用

2\. 检查文件权限

3\. 使用raw.githubusercontent.com直接链接



\## 联系支持



\- GitHub Issues: \[报告问题](https://github.com/wansheng8/adblock/issues)

\- 文档: \[查看完整文档](https://github.com/wansheng8/adblock)

\- 更新日志: \[查看更新历史](https://github.com/wansheng8/adblock/commits/main)



---



\*最后更新: $(date)\*

