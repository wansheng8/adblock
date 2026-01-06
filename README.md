\# 去广告合并规则自动更新系统



\[!\[Auto Update](https://github.com/wansheng8/adblock/actions/workflows/update-rules.yml/badge.svg)](https://github.com/wansheng8/adblock/actions/workflows/update-rules.yml)

\[!\[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

\[!\[Last Updated](https://img.shields.io/badge/最后更新-动态-blue)](https://github.com/wansheng8/adblock)



一个自动更新的多源去广告规则合并系统，每8小时自动从上游规则源获取更新，生成统一的广告拦截规则。



\## ✨ 特性



\- 🔄 \*\*自动更新\*\*: 每8小时自动获取最新规则

\- 🎯 \*\*全面覆盖\*\*: 覆盖开屏广告、弹窗广告、内嵌广告等

\- 🛡️ \*\*多重保护\*\*: 包含隐私保护、恶意网站拦截等功能

\- 📊 \*\*智能合并\*\*: 自动去重、排序、验证规则

\- 🌐 \*\*多源支持\*\*: 整合多个知名规则源

\- ⚡ \*\*高效性能\*\*: 优化规则结构，提升拦截效率



\## 📥 订阅链接



\### 主要订阅

\- \*\*黑名单 (推荐)\*\*: 

https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt



text

\- \*\*白名单\*\*: 

https://raw.githubusercontent.com/wansheng8/adblock/main/dist/whitelist.txt



text



\### 简化版本

\- \*\*基础版\*\* (适合低性能设备):

https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist-lite.txt



text



\## 🚀 快速开始



\### 浏览器扩展用户

1\. 安装广告拦截器 (推荐 uBlock Origin 或 AdGuard)

2\. 打开扩展设置

3\. 在"自定义规则"或"订阅规则"中添加上述链接

4\. 启用订阅并更新规则



\### 路由器用户 (AdGuard Home)

1\. 登录 AdGuard Home 管理界面

2\. 转到"过滤器" -> "DNS 黑名单"

3\. 添加黑名单订阅链接

4\. 设置更新频率为 8 小时



\### 系统级拦截 (Hosts)

1\. 下载 hosts 规则文件

2\. 合并到系统 hosts 文件

3\. 刷新 DNS 缓存



\## 📋 拦截内容



\- ✅ 开屏/启动广告

\- ✅ 弹窗广告

\- ✅ 视频广告

\- ✅ 横幅广告

\- ✅ 跟踪脚本

\- ✅ 挖矿脚本

\- ✅ 恶意网站

\- ✅ 钓鱼网站

\- ✅ 社交媒体插件

\- ✅ 隐私追踪器



\## 🛠️ 自定义配置



\### 修改规则源

编辑 `sources/sources.json`:

```json

{

"update\_frequency": 8,

"sources": \[

&nbsp; {

&nbsp;   "name": "自定义规则源",

&nbsp;   "url": "https://your-rules.com/list.txt",

&nbsp;   "type": "blacklist",

&nbsp;   "enabled": true

&nbsp; }

]

}

添加自定义规则

创建 rules/custom.txt 文件，规则将自动合并。



🔧 本地部署

bash

\# 克隆仓库

git clone https://github.com/wansheng8/adblock.git

cd adblock



\# 安装依赖

pip install -r requirements.txt



\# 手动运行更新

python scripts/update\_rules.py



\# 验证规则

python scripts/validate\_rules.py

📊 规则统计

https://img.shields.io/badge/%E6%80%BB%E8%A7%84%E5%88%99%E6%95%B0-%E5%8A%A8%E6%80%81-blue

https://img.shields.io/badge/%E6%9B%B4%E6%96%B0%E9%A2%91%E7%8E%87-8%E5%B0%8F%E6%97%B6-green



🆘 故障排除

常见问题

规则不生效: 清除浏览器缓存，重启拦截器



误拦截网站: 在GitHub Issues报告，临时使用白名单



更新失败: 检查网络连接，查看Actions日志



调试方法

javascript

// 在浏览器控制台检查

console.log(adBlock);

// 或使用广告拦截器调试模式

🤝 贡献

欢迎贡献代码、报告问题或建议新功能：



Fork 本仓库



创建功能分支 (git checkout -b feature/AmazingFeature)



提交更改 (git commit -m 'Add some AmazingFeature')



推送到分支 (git push origin feature/AmazingFeature)



开启 Pull Request



📄 许可证

本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。



🙏 致谢

感谢以下开源项目的规则源：



AdGuard Filters



EasyList



Peter Lowe's Ad server list



Anti-AD



以及所有贡献者



📞 联系方式

项目主页: https://github.com/wansheng8/adblock



问题反馈: GitHub Issues



更新日志: CHANGELOG.md



注意: 本规则仅供学习和研究使用，请遵守相关法律法规。



最后自动更新: $(date)



text



\## 🔧 部署步骤



\### 步骤1: 初始化仓库

```bash

\# 克隆仓库到本地

git clone https://github.com/wansheng8/adblock.git

cd adblock



\# 创建所有必要文件

\# 将上述代码复制到对应文件中



\# 设置文件权限

chmod +x scripts/\*.py

步骤2: 配置GitHub Secrets (可选)

如果需要访问私有规则源：



进入仓库 Settings → Secrets → Actions



添加必要的访问令牌



步骤3: 首次运行

bash

\# 安装依赖

pip install requests



\# 运行更新脚本

python scripts/update\_rules.py



\# 提交更改

git add .

git commit -m "初始提交: 添加自动更新系统"

git push origin main

步骤4: 验证自动更新

访问GitHub仓库的Actions页面



确认工作流正常运行



检查dist目录是否生成规则文件



📊 监控和维护

查看更新状态

访问: https://github.com/wansheng8/adblock/actions



查看工作流运行历史



查看规则统计

bash

\# 查看最新规则信息

cat dist/metadata.json | python -m json.tool

手动触发更新

在GitHub Actions页面点击"Run workflow"



或使用GitHub API:



bash

curl -X POST \\

&nbsp; -H "Authorization: token YOUR\_TOKEN" \\

&nbsp; https://api.github.com/repos/wansheng8/adblock/actions/workflows/update-rules.yml/dispatches \\

&nbsp; -d '{"ref":"main"}'

🎯 规则优化建议

性能优化

使用域名规则: 优先使用 ||domain.com^ 而非通配符



合并相似规则: 使用正则表达式合并相似模式



避免过度拦截: 定期检查白名单，减少误报



兼容性

测试主流网站: 确保常用网站正常工作



多浏览器测试: Chrome, Firefox, Safari等



移动端适配: 考虑移动端广告特性



🔍 调试工具

规则验证工具

python

\# 验证单个规则

from scripts.validate\_rules import RuleValidator

validator = RuleValidator()

print(validator.validate\_rule("||example.com^"))

性能测试

bash

\# 测试规则加载时间

time curl -s https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt | wc -l

📈 扩展功能

添加CDN支持

在 .github/workflows/update-rules.yml 中添加：



yaml

\- name: Deploy to CDN

&nbsp; if: success()

&nbsp; run: |

&nbsp;   # 上传到GitHub Pages或其他CDN

&nbsp;   echo "部署到CDN..."

添加通知功能

yaml

\- name: Send notification

&nbsp; if: always()

&nbsp; uses: dawidd6/action-send-mail@v3

&nbsp; with:

&nbsp;   server\_address: smtp.gmail.com

&nbsp;   server\_port: 465

&nbsp;   username: ${{secrets.MAIL\_USERNAME}}

&nbsp;   password: ${{secrets.MAIL\_PASSWORD}}

&nbsp;   subject: 规则更新状态

&nbsp;   to: your-email@example.com

&nbsp;   from: GitHub Actions

&nbsp;   body: 规则更新完成!

🚨 故障排除

常见问题解决

问题	解决方案

规则下载失败	检查网络连接，更新sources.json中的URL

规则合并冲突	检查规则语法，使用validate\_rules.py验证

GitHub Actions超时	增加timeout-minutes，优化脚本效率

文件权限错误	确保脚本有执行权限 chmod +x scripts/\*.py

日志分析

bash

\# 查看错误日志

tail -f rules/invalid\_rules.log



\# 监控更新状态

grep -E "(成功|失败)" $(ls -t rules/raw/\*.log | head -1)

🎉 完成部署

您的自动更新去广告规则系统现已部署完成！系统将每8小时自动更新，为您提供最新的广告拦截规则。



订阅地址

黑名单: https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt



白名单: https://raw.githubusercontent.com/wansheng8/adblock/main/dist/whitelist.txt



监控地址

Actions状态: https://github.com/wansheng8/adblock/actions



规则文件: https://github.com/wansheng8/adblock/tree/main/dist



后续维护

定期检查Actions运行状态



每月审查规则源的有效性



根据用户反馈调整规则



优化更新脚本性能



📚 参考资料

AdBlock Plus过滤规则语法



uBlock Origin Wiki



AdGuard过滤规则



GitHub Actions文档





