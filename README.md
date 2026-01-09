# AdBlock 规则自动更新系统

## 📖 项目介绍

这是一个基于 GitHub Actions 的广告拦截规则自动更新系统，整合了23+个主流广告规则源，每天自动更新3次，提供三层规则的广告拦截解决方案（DNS、Hosts、浏览器）。

### 🌟 核心特性
- **自动更新**：每8小时自动更新规则（北京时间 08:00、16:00、00:00）
- **三层规则**：提供DNS、Hosts、浏览器三种格式的规则
- **严格验证**：每次更新都进行语法验证和质量检查（90%有效性阈值）
- **智能优化**：自动去重、分类和性能优化
- **开源免费**：完全开源，永久免费使用

### 🎯 拦截内容
- 🚫 视频广告、弹窗广告、横幅广告
- 🔒 用户跟踪器、隐私收集脚本
- ⚡ 恶意软件、挖矿脚本、钓鱼网站
- 🇨🇳 中国特色广告和移动端广告

## 🔗 订阅链接

| 名称 | 描述 | 订阅链接 |
|------|------|----------|
| **DNS规则** | 纯域名格式，用于DNS服务（AdGuard Home/Pi-hole等） | [原始链接](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/dns.txt) / [加速链接](https://cdn.jsdelivr.net/gh/wansheng8/adblock/dist/dns.txt) |
| **Hosts规则** | 系统hosts文件格式（0.0.0.0 + 域名） | [原始链接](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/hosts.txt) / [加速链接](https://cdn.jsdelivr.net/gh/wansheng8/adblock/dist/hosts.txt) |
| **浏览器规则** | 浏览器扩展格式（uBlock Origin/AdBlock等） | [原始链接](https://raw.githubusercontent.com/wansheng8/adblock/main/dist/filter.txt) / [加速链接](https://cdn.jsdelivr.net/gh/wansheng8/adblock/dist/filter.txt) |

## 📁 项目结构

```
adblock/
├── .github/
│   └── workflows/
│       └── update-rules.yml          # GitHub Actions 工作流配置
├── scripts/
│   ├── update_rules.py               # 主更新脚本（从23+个源获取并处理三层规则）
│   ├── validate_rules.py             # 规则验证脚本（检查三层规则语法正确性）
│   ├── format_rules.py               # 规则格式化脚本（优化和美化三层规则格式）
│   ├── merge_rules.py               # 规则合并脚本（合并自定义规则）
│   ├── fix_git.py                   # Git修复脚本（解决Git跟踪问题）
│   └── requirements.txt             # Python依赖包列表
├── sources/
│   ├── sources.json                  # 规则源配置文件（23+个规则源配置）
│   └── gz.txt                       # 额外规则源文件
├── dist/                            # 生成的规则文件目录（自动生成）
│   ├── dns.txt                      # DNS规则文件（纯域名格式）
│   ├── hosts.txt                    # Hosts规则文件（0.0.0.0格式）
│   ├── filter.txt                   # 浏览器规则文件（AdBlock语法）
│   ├── metadata.json                # 规则元数据
│   ├── validation_report.json       # 规则验证报告
│   └── advanced_statistics.md       # 高级统计报告
├── rules/                           # 规则管理目录
│   ├── raw/                         # 原始规则文件（从各个源下载）
│   ├── processed/                   # 处理后的规则（中间文件）
│   ├── custom/                      # 自定义规则目录（用户添加）
│   └── whitelist_custom.txt         # 自定义白名单规则
├── docs/
│   ├── FAQ.md                        # 常见问题
│   ├── CONTRIBUTING.md               # 贡献指南
│   └── CHANGELOG.md                  # 更新日志
├── README.md                         # 项目说明文档
├── LICENSE                           # 许可证文件
└── .gitignore                        # Git忽略文件配置
```

### 📦 文件说明

#### .github/workflows/update-rules.yml
GitHub Actions 工作流配置文件，定义了自动更新的流程和触发条件，每8小时自动运行。

#### scripts/ 目录
- **update_rules.py**：核心更新脚本，从23+个规则源获取并处理三层规则（DNS、Hosts、浏览器）
- **validate_rules.py**：规则验证脚本，检查三层规则语法正确性
- **format_rules.py**：规则格式化脚本，优化和美化三层规则格式
- **merge_rules.py**：规则合并脚本，合并自定义规则并去重
- **fix_git.py**：Git修复脚本，解决Git跟踪问题
- **requirements.txt**：Python依赖包列表（requests, beautifulsoup4, lxml）

#### sources/ 目录
- **sources.json**：主规则源配置文件，包含23+个广告规则源
- **gz.txt**：额外规则源文件，用户可自定义添加

#### dist/ 目录（自动生成）
- **dns.txt**：DNS规则文件（纯域名格式，用于DNS层面拦截）
- **hosts.txt**：Hosts规则文件（0.0.0.0 + 域名格式，用于系统hosts文件）
- **filter.txt**：浏览器规则文件（完整AdBlock语法，用于浏览器扩展）
- **metadata.json**：规则元数据，包含更新时间、规则数量等信息
- **validation_report.json**：规则验证报告，记录三层规则验证结果
- **advanced_statistics.md**：高级统计报告，详细规则分析

#### rules/ 目录
- **raw/**：从各个规则源下载的原始规则文件
- **processed/**：处理后的规则文件（中间文件）
- **custom/**：用户自定义规则目录
- **whitelist_custom.txt**：用户自定义白名单规则

## 🚀 使用方法

### 快速开始
1. 从上面的**订阅链接**表格中选择适合你的规则类型
2. 复制链接（推荐使用加速链接，速度更快）
3. 将链接导入到你的广告拦截软件中

### 具体应用场景
- **AdGuard Home/Pi-hole**：使用DNS规则链接
- **系统hosts文件**：使用Hosts规则链接
- **uBlock Origin/AdBlock**：使用浏览器规则链接

### 自定义规则
1. 在 `rules/custom/` 目录中添加自定义规则文件（.txt格式）
2. 系统会在下次自动更新时合并你的自定义规则
3. 编辑 `rules/whitelist_custom.txt` 添加白名单例外规则

## 🔄 更新机制

### 自动更新时间
- 北京时间 08:00
- 北京时间 16:00
- 北京时间 00:00（次日）

### 更新流程
1. **规则获取**：从23+个规则源获取最新规则
2. **自定义合并**：合并用户自定义规则
3. **规则验证**：检查规则语法和质量（90%有效性阈值）
4. **格式优化**：去重、分类、性能优化
5. **文件生成**：生成三层规则文件
6. **报告生成**：生成统计报告和验证报告
7. **自动提交**：检测变更并自动提交到仓库

## 📊 规则统计
每次更新后，系统会生成详细的统计信息，包括：
- DNS规则数量统计
- Hosts规则数量统计
- 浏览器规则数量统计及分类（域名拦截、元素隐藏、例外规则、高级规则）
- 规则有效性验证结果
- 文件大小和更新时间

## 🤝 贡献指南

欢迎为项目做出贡献！你可以：
1. **报告问题**：在GitHub Issues中报告bug或提出建议
2. **添加规则源**：在 `sources/gz.txt` 中添加有效的规则源
3. **分享规则**：在 `rules/custom/` 目录中添加你的自定义规则
4. **改进代码**：提交Pull Request改进脚本功能
5. **完善文档**：帮助完善FAQ和贡献指南

详细贡献指南请查看 [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)

## ❓ 常见问题

常见问题解答请查看 [docs/FAQ.md](docs/FAQ.md)

## 📄 许可证

本项目采用 MIT 许可证开源。详见 [LICENSE](LICENSE) 文件。

## 📞 项目地址

GitHub仓库：https://github.com/wansheng8/adblock

## 🔄 更新日志

详细更新记录请查看 [docs/CHANGELOG.md](docs/CHANGELOG.md)

---

**最后更新**：每8小时自动更新  
**下次更新**：系统自动安排  
**规则状态**：查看 [GitHub Actions](https://github.com/wansheng8/adblock/actions) 了解最新状态
