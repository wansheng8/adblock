# docs/CONTRIBUTING.md

# 贡献指南

感谢您对 AdBlock 规则自动更新系统的关注！我们欢迎所有形式的贡献。

## 🌟 如何贡献

### 1. 报告问题
如果您发现任何问题或有改进建议：
- 请先查看 [常见问题解答](FAQ.md) 是否已有解答
- 在 [GitHub Issues](https://github.com/wansheng8/adblock/issues) 页面创建新问题
- 请提供详细的问题描述、重现步骤和相关日志
- 如果是规则问题，请提供具体的规则示例和网址

### 2. 提交规则源
想要添加新的规则源？
1. 编辑 `sources/gz.txt` 文件
2. 添加有效的规则源URL（每行一个）
3. 确保规则源是公开可访问的
4. 提交 Pull Request

### 3. 添加自定义规则
想要分享您的自定义规则？
1. 在 `rules/custom/` 目录中创建新的规则文件（.txt格式）
2. 遵循 AdBlock 语法格式
3. 添加文件头部注释说明规则用途
4. 提交 Pull Request

### 4. 改进代码
想要改进脚本或功能？
1. Fork 这个仓库
2. 创建功能分支：`git checkout -b feature/新功能`
3. 提交更改：`git commit -m '添加了某个功能'`
4. 推送到分支：`git push origin feature/新功能`
5. 提交 Pull Request

## 📝 开发规范

### Python 代码规范
- 遵循 PEP 8 编码规范
- 使用有意义的变量名和函数名
- 添加必要的注释和文档字符串
- 确保向后兼容性

### 规则语法规范
- DNS规则：纯域名格式，每行一个
- Hosts规则：`0.0.0.0 example.com` 格式
- 浏览器规则：遵循 AdBlock 语法标准
- 避免使用通配符和正则表达式（除非必要）

### Git 提交规范
- 提交信息使用中文或英文
- 遵循约定的提交信息格式：
  ```
  类型: 简短描述
  
  详细描述（可选）
  
  相关Issue: #123
  ```
- 类型包括：feat、fix、docs、style、refactor、test、chore

## 🔧 开发环境设置

### 1. 克隆仓库
```bash
git clone https://github.com/wansheng8/adblock.git
cd adblock
```

### 2. 安装依赖
```bash
pip install -r scripts/requirements.txt
```

### 3. 运行测试
```bash
# 测试更新脚本
python scripts/update_rules.py

# 测试验证脚本
python scripts/validate_rules.py

# 测试格式化脚本
python scripts/format_rules.py
```

## 📋 贡献流程

1. **讨论想法**：在 Issues 中讨论你的想法
2. **创建分支**：从 main 分支创建新分支
3. **编写代码**：实现功能或修复问题
4. **编写测试**：确保代码的正确性
5. **提交代码**：遵循提交规范
6. **创建 PR**：提交 Pull Request
7. **代码审查**：等待维护者审查
8. **合并代码**：通过审查后合并

## 🧪 测试要求

- 所有新功能必须包含测试
- 确保现有功能不受影响
- 测试应该覆盖各种边界情况
- 运行所有现有测试确保通过

## 📚 文档要求

- 新增功能需要更新相应文档
- 更新 README.md 中的相关信息
- 保持文档与代码同步
- 添加必要的使用示例

## 🏆 成为核心贡献者

持续贡献高质量代码的贡献者可能被邀请成为核心贡献者，拥有：
- 项目的直接提交权限
- Issues 和 PR 的管理权限
- 参与项目路线图的制定

## ❓ 需要帮助？

- 查看 [常见问题解答](FAQ.md)
- 在 Issues 中提问
- 查看现有的 Pull Request 示例

---

感谢您的贡献！让我们共同打造更好的广告拦截规则系统。

