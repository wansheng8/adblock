# 🛡️ AdBlock 规则自动更新系统

[![GitHub Actions](https://github.com/wansheng8/adblock/actions/workflows/update-rules.yml/badge.svg)](https://github.com/wansheng8/adblock/actions)
[![规则更新状态](https://img.shields.io/badge/规则更新-每8小时自动更新-blue.svg)](https://github.com/wansheng8/adblock/actions)
[![规则数量](https://img.shields.io/badge/规则数量-自动统计-green.svg)](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt)
[![许可证](https://img.shields.io/badge/许可证-MIT-yellow.svg)](LICENSE)
[![Python版本](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![中文文档](https://img.shields.io/badge/文档-中文-red.svg)](README.md)

一个全自动的广告拦截规则合并与更新系统，每8小时自动从多个上游规则源获取最新规则，智能合并、去重、验证后生成统一的广告拦截规则库。

## ✨ 核心特性

### 🚀 全自动更新
- **智能调度**：每8小时自动运行，无需人工干预
- **多源同步**：从12+个知名规则源同步更新
- **失败重试**：自动处理网络错误和规则源失效

### 🔍 智能处理
- **智能去重**：自动识别并移除重复规则
- **语法验证**：严格验证规则语法，确保有效性
- **优先级排序**：按规则类型和优先级智能排序
- **冲突解决**：自动处理规则冲突和白名单例外

### 📦 完整覆盖
- **广告拦截**：开屏广告、弹窗广告、视频广告、横幅广告
- **隐私保护**：跟踪器、指纹识别、Cookie跟踪
- **安全防护**：恶意网站、挖矿脚本、网络钓鱼
- **体验优化**：社交媒体插件、点击劫持、下载劫持

### 🛠️ 易于使用
- **即开即用**：提供直接订阅链接
- **多平台支持**：兼容所有主流广告拦截器
- **中文优化**：针对中文互联网环境优化
- **详细文档**：完整的使用和故障排除指南

## 📥 订阅链接

### 主要订阅（推荐使用）
| 名称 | 描述 | 订阅链接 |
|------|------|----------|
| **完整黑名单** | 完整的广告拦截规则，包含所有过滤类型 | [点击订阅](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt) |
| **白名单** | 避免误拦截的例外规则 | [点击订阅](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/whitelist.txt) |

### 备用链接（使用CDN加速）
| CDN提供商 | 黑名单链接 | 白名单链接 |
|-----------|------------|------------|
| **jsDelivr** | [链接](https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/dist/blacklist.txt) | [链接](https://cdn.jsdelivr.net/gh/wansheng8/adblock@main/dist/whitelist.txt) |
| **GitHub Raw** | [链接](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt) | [链接](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/whitelist.txt) |
| **Statically** | [链接](https://cdn.statically.io/gh/wansheng8/adblock/main/dist/blacklist.txt) | [链接](https://cdn.statically.io/gh/wansheng8/adblock/main/dist/whitelist.txt) |

## 🚀 快速开始

### 方法一：浏览器扩展用户（推荐）

#### uBlock Origin
1. 打开 uBlock Origin 设置面板
2. 进入 "过滤器列表" 标签页
3. 滚动到底部 "导入" 区域
4. 粘贴订阅链接：
   ```
   https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt
   ```
5. 点击 "应用更改"，然后点击 "更新现在"

#### AdGuard 浏览器扩展
1. 点击 AdGuard 图标 → 设置 ⚙️
2. 选择 "常规" → "过滤器"
3. 点击 "添加自定义过滤器"
4. 输入名称和订阅链接
5. 点击 "添加"，然后启用过滤器

### 方法二：系统级拦截

#### AdGuard Home / Pi-hole
```bash
# AdGuard Home
1. 登录管理界面 → 过滤器 → DNS黑名单
2. 点击 "添加黑名单"
3. 名称: "AdBlock 合并规则"
4. URL: https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt
5. 设置更新间隔: 8小时

# Pi-hole
sudo nano /etc/pihole/adlists.list
# 添加以下行
https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt
```

#### Windows Hosts 文件
```powershell
# 1. 下载规则文件
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt" -OutFile "rules.txt"

# 2. 提取hosts格式规则（需要额外脚本转换）
# 3. 添加到 C:\Windows\System32\drivers\etc\hosts

# 刷新DNS缓存
ipconfig /flushdns
```

### 方法三：移动设备

#### AdGuard for Android/iOS
1. 打开 AdGuard 应用
2. 进入 "保护" → "DNS保护"
3. 点击 "DNS过滤器"
4. 添加新过滤器，粘贴订阅链接
5. 启用过滤器

#### Safari 用户 (iOS/macOS)
1. 安装 AdGuard for Safari
2. 打开扩展设置
3. 在 "用户规则" 中添加订阅

## 🎯 拦截内容详情

### 广告拦截
| 类型 | 描述 | 示例规则 |
|------|------|----------|
| **开屏广告** | 应用启动时的全屏广告 | `||*.splashad.*^` |
| **弹窗广告** | 各种类型的弹出窗口 | `||popad.*.js^` |
| **视频广告** | 视频播放前/中的广告 | `||*.video-ad.*^` |
| **横幅广告** | 网页内的横幅广告 | `##div[class*="ad"]` |
| **内联广告** | 文章内容中的广告 | `##.article-ad` |

### 隐私保护
- **跟踪器拦截**：Google Analytics、Facebook Pixel等
- **指纹防护**：阻止浏览器指纹识别脚本
- **Cookie控制**：限制第三方Cookie跟踪
- **位置保护**：阻止地理位置泄露

### 安全防护
- **恶意软件**：阻止已知恶意域名
- **挖矿脚本**：拦截加密货币挖矿脚本
- **钓鱼网站**：阻止已知钓鱼网站
- **欺诈网站**：拦截虚假购物、投资网站

### 体验优化
- **社交媒体按钮**：减少不必要的社交插件
- **评论插件**：优化评论加载体验
- **弹窗拦截**：阻止各种订阅弹窗
- **自动播放**：控制媒体自动播放

## 📊 规则源列表

| 名称 | 类型 | 规则数量 | 更新频率 | 状态 |
|------|------|----------|----------|------|
| AdGuard Base Filter | 广告拦截 | ~50,000+ | 每日 | ✅ |
| EasyList China | 中文广告 | ~30,000+ | 每日 | ✅ |
| Anti-AD | 中文综合 | ~40,000+ | 每日 | ✅ |
| EasyPrivacy | 隐私保护 | ~25,000+ | 每日 | ✅ |
| AdGuard Spyware | 间谍软件 | ~15,000+ | 每日 | ✅ |
| Fanboy's Annoyance | 恼人元素 | ~10,000+ | 每周 | ✅ |
| Peter Lowe's List | 广告服务器 | ~8,000+ | 每周 | ✅ |
| AdGuard DNS Filter | DNS过滤 | ~20,000+ | 每日 | ✅ |
| NEO DEV HOST | 综合规则 | ~15,000+ | 每日 | ✅ |

**总计**: 约 200,000+ 条规则（去重后）

## 🏗️ 技术架构

### 系统流程图
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   规则源同步    │───▶│   规则处理引擎   │───▶│   规则验证器    │
│  (12+个源)      │    │  (合并/去重)    │    │  (语法检查)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                            │                         │
                            ▼                         ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub Actions │◀──│    规则生成器    │◀──│    规则优化器    │
│  (自动调度)      │    │  (格式转换)     │    │  (性能优化)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────┐
│             发布到 GitHub / CDN                 │
│    • blacklist.txt (主规则)                     │
│    • whitelist.txt (例外规则)                   │
│    • metadata.json (元数据)                     │
└─────────────────────────────────────────────────┘
```

### 更新频率
- **主更新**: 每8小时自动运行（UTC 0:00, 8:00, 16:00）
- **手动触发**: 支持GitHub网页手动更新
- **紧急更新**: 规则源变更时自动触发

### 文件结构
```
adblock/
├── .github/workflows/           # GitHub Actions 工作流
│   └── update-rules.yml         # 自动更新配置
├── scripts/                     # 核心脚本
│   ├── update_rules.py          # 主更新脚本
│   ├── merge_rules.py           # 规则合并脚本
│   └── validate_rules.py        # 规则验证脚本
├── sources/                     # 规则源配置
│   └── sources.json             # 12+个规则源
├── dist/                        # 生成的文件
│   ├── blacklist.txt            # 主规则文件
│   ├── whitelist.txt            # 白名单文件
│   └── metadata.json            # 元数据信息
├── rules/                       # 规则存储
│   ├── raw/                     # 原始规则文件
│   └── processed/               # 处理后的规则
├── docs/                        # 文档
│   ├── FAQ.md                   # 常见问题
│   └── CONTRIBUTING.md          # 贡献指南
└── README.md                    # 项目说明
```

## 🔧 本地部署与开发

### 环境要求
- Python 3.9+
- Git
- 网络连接（访问GitHub和规则源）

### 快速开始
```bash
# 1. 克隆项目
git clone https://github.com/wansheng8/adblock.git
cd adblock

# 2. 创建虚拟环境（可选但推荐）
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 运行更新脚本
python scripts/update_rules.py

# 5. 查看生成的文件
ls -la dist/
cat dist/metadata.json
```

### 自定义配置
编辑 `sources/sources.json`：
```json
{
  "update_frequency": 8,
  "timezone": "Asia/Shanghai",
  "language": "zh-CN",
  "sources": [
    {
      "name": "自定义规则源",
      "url": "https://example.com/my-rules.txt",
      "type": "blacklist",
      "enabled": true,
      "priority": 1
    }
  ]
}
```

### 添加自定义规则
创建 `rules/custom_rules.txt`：
```adblock
! 我的自定义规则
! 添加时间: 2024-01-01

! 屏蔽特定网站广告
||ads.mycompany.com^
||tracking.another.com^$third-party

! 元素隐藏规则
##div[id^="ad-"]
##.ad-container

! 白名单例外
@@||mybank.com^
@@||important.service.com^$document
```

## 📈 性能与统计

### 实时统计
```bash
# 获取最新统计信息
curl -s https://raw.githubusercontent.com/wansheng8/adblock/main/dist/metadata.json | python -m json.tool

# 输出示例：
{
  "last_updated": "2024-01-01T12:00:00+08:00",
  "total_rules": 185432,
  "blacklist_rules": 180123,
  "whitelist_rules": 5309,
  "sources_used": 12,
  "next_update": "2024-01-01T20:00:00+08:00",
  "version": "20240101.1200"
}
```

### 性能优化
- **压缩存储**: 移除重复规则，减少文件大小
- **智能排序**: 按匹配频率优化规则顺序
- **语法优化**: 使用高效的正则表达式
- **缓存机制**: 支持CDN缓存，提高访问速度

## 🆘 常见问题 (FAQ)

### Q1: 规则不生效怎么办？
**解决方案**:
1. **检查订阅状态**
   ```bash
   # 测试订阅链接
   curl -I https://raw.githubusercontent.com/wansheng8/adblock/main/dist/blacklist.txt
   # 应返回 200 OK
   ```

2. **清除缓存**
   - 浏览器: Ctrl+Shift+Delete (Windows/Linux) 或 Cmd+Shift+Delete (macOS)
   - DNS: `ipconfig /flushdns` (Windows) 或 `sudo dscacheutil -flushcache` (macOS)

3. **检查规则顺序**
   - 确保本规则列表在其他规则之上
   - 禁用可能冲突的规则列表

### Q2: 遇到误拦截怎么办？
**解决方案**:
1. **临时禁用**
   - 在问题网站上暂时禁用广告拦截器

2. **添加白名单**
   ```adblock
   @@||误拦截的网站.com^
   @@||子域名.网站.com^$document
   ```

3. **报告问题**
   - 访问 [Issues页面](https://github.com/wansheng8/adblock/issues)
   - 提供: 网址、截图、浏览器信息、规则版本

### Q3: 如何验证规则是否生效？
**测试方法**:
```bash
# 方法1: 访问测试网站
https://blockads.fivefilters.org/
https://adblock-tester.com/

# 方法2: 控制台检查
# 在浏览器控制台运行
(async () => {
  const testUrl = 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js';
  try {
    const response = await fetch(testUrl, {mode: 'no-cors'});
    console.log('广告请求未被拦截');
  } catch {
    console.log('广告请求被成功拦截');
  }
})();
```

### Q4: 规则更新失败了怎么办？
**排查步骤**:
1. 查看 [Actions日志](https://github.com/wansheng8/adblock/actions)
2. 检查规则源是否可访问
3. 查看 `rules/invalid_rules.log` 错误日志
4. 手动运行更新脚本测试

## 🤝 贡献指南

我们欢迎各种形式的贡献！

### 贡献规则源
1. Fork 本仓库
2. 编辑 `sources/sources.json`
3. 添加新的规则源配置
4. 提交 Pull Request

### 报告问题
1. 访问 [Issues](https://github.com/wansheng8/adblock/issues)
2. 选择问题类型（Bug、功能建议等）
3. 提供详细的信息和复现步骤

### 开发贡献
```bash
# 1. 克隆仓库
git clone https://github.com/wansheng8/adblock.git

# 2. 创建功能分支
git checkout -b feature/新功能

# 3. 进行修改和测试
python scripts/validate_rules.py --test

# 4. 提交更改
git add .
git commit -m "feat: 添加新功能描述"

# 5. 推送到远程
git push origin feature/新功能

# 6. 创建 Pull Request
```

### 提交规范
我们使用约定式提交：
- `feat:` 新功能
- `fix:` 修复问题
- `docs:` 文档更新
- `style:` 代码格式
- `refactor:` 代码重构
- `test:` 测试相关
- `chore:` 维护任务

## 📄 许可证

本项目采用 **MIT 许可证** - 查看 [LICENSE](LICENSE) 文件了解详情。

### 使用条款
1. 本规则仅供学习和研究使用
2. 请遵守当地法律法规
3. 不得用于商业用途
4. 作者不对使用后果负责

## 🙏 致谢

### 规则源感谢
感谢以下项目的优秀规则源：
- [AdGuard Filters](https://github.com/AdguardTeam/AdguardFilters)
- [EasyList China](https://abpchina.org/forum/)
- [Anti-AD](https://github.com/privacy-protection-tools/anti-AD)
- [Peter Lowe's List](https://pgl.yoyo.org/adservers/)
- [Fanboy's List](https://www.fanboy.co.nz/)
- [NEO DEV HOST](https://github.com/neodevpro/neodevhost)

### 技术支持
- [GitHub Actions](https://github.com/features/actions) - 自动化平台
- [Python](https://python.org) - 核心编程语言
- [uBlock Origin](https://github.com/gorhill/uBlock) - 优秀的广告拦截器

### 贡献者
感谢所有为项目做出贡献的开发者！

## 📞 联系方式

- **项目主页**: [https://github.com/wansheng8/adblock](https://github.com/wansheng8/adblock)
- **问题反馈**: [GitHub Issues](https://github.com/wansheng8/adblock/issues)
- **讨论区**: [GitHub Discussions](https://github.com/wansheng8/adblock/discussions)
- **邮件联系**: 通过GitHub Issues联系

## 🔔 更新通知

### 订阅更新通知
1. **Watch仓库**: 点击仓库右上角 "Watch" 按钮
2. **RSS订阅**: `https://github.com/wansheng8/adblock/commits/main.atom`
3. **GitHub通知**: 在设置中启用仓库通知

### 更新日志
查看 [CHANGELOG.md](CHANGELOG.md) 获取详细更新记录。

## 🌟 Star历史

[![Stargazers over time](https://starchart.cc/wansheng8/adblock.svg)](https://starchart.cc/wansheng8/adblock)

---

<div align="center">
  
**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

[![Star History Chart](https://api.star-history.com/svg?repos=wansheng8/adblock&type=Date)](https://star-history.com/#wansheng8/adblock&Date)

</div>

---

*最后更新: $(date)*  
*下次自动更新: $(date -d "+8 hours")*  
*项目状态: ✅ 运行正常*
