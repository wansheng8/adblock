#!/usr/bin/env python3
"""
修复 Git 跟踪问题的脚本 - 增强版
支持高级广告拦截规则语法处理
"""

import os
import sys
import shutil
from pathlib import Path
import json
from datetime import datetime


class GitFixer:
    def __init__(self):
        self.base_dir = Path.cwd()
        self.now = datetime.now()
        self.backup_dir = self.base_dir / '.git_backup'
        
    def backup_git_status(self):
        """备份当前Git状态"""
        print("📦 正在备份Git状态...")
        self.backup_dir.mkdir(exist_ok=True)
        
        # 保存当前状态
        timestamp = self.now.strftime('%Y%m%d_%H%M%S')
        backup_files = []
        
        # Git状态备份
        backup_files.append(f"git_status_{timestamp}.txt")
        os.system(f'git status > "{self.backup_dir}/git_status_{timestamp}.txt"')
        
        # Git差异备份
        backup_files.append(f"git_diff_{timestamp}.txt")
        os.system(f'git diff > "{self.backup_dir}/git_diff_{timestamp}.txt"')
        
        # Git日志备份
        backup_files.append(f"git_log_{timestamp}.txt")
        os.system(f'git log --oneline -20 > "{self.backup_dir}/git_log_{timestamp}.txt"')
        
        # 配置文件备份
        if (self.base_dir / '.gitignore').exists():
            shutil.copy2('.gitignore', self.backup_dir / f'gitignore_backup_{timestamp}')
            backup_files.append(f"gitignore_backup_{timestamp}")
        
        print(f"✅ Git状态已备份到 {self.backup_dir}/")
        print(f"  备份文件: {', '.join(backup_files)}")
        return True
    
    def check_uncommitted_changes(self):
        """检查未提交的更改"""
        print("🔍 检查未提交的更改...")
        result = os.popen('git status --porcelain').read().strip()
        
        if result:
            print("⚠️  检测到未提交的更改:")
            print("-" * 40)
            print(result)
            print("-" * 40)
            return True, result.split('\n')
        else:
            print("✅ 没有未提交的更改")
            return False, []
    
    def create_advanced_gitignore(self):
        """创建高级 .gitignore 文件（支持广告拦截规则项目）"""
        gitignore_content = """# ==============================================
# 🚀 AdBlock 规则项目专用 .gitignore
# ==============================================

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# 系统文件
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
desktop.ini

# 临时文件
*.log
*.tmp
*.temp
*.bak
*.backup
*.sav
*.old
*.orig
*.rej

# 本地配置
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
secrets.json
config.json
credentials.json

# 测试文件
*.test
*.spec
coverage/
.coveragerc
.pytest_cache/
.tox/
htmlcov/

# 文档生成
docs/_build/
docs/_static/
docs/_templates/

# 包管理
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
package-lock.json
yarn.lock

# 虚拟环境
venv/
env/
ENV/
env.bak/
venv.bak/

# 编辑器
*.swp
*.swo
*.un~
*~
*.vim

# 我们不忽略的重要目录:
# - dist/ (包含生成的规则文件) - 必须提交！
# - rules/raw/ (包含原始规则文件) - 必须提交！
# - sources/ (规则源配置) - 必须提交！
# - scripts/ (Python脚本) - 必须提交！
# - docs/ (文档) - 建议提交
# - .github/ (GitHub Actions配置) - 必须提交！

# 临时构建文件（但不忽略 dist/）
build_temp/
temp_build/

# 备份目录（自动备份）
.git_backup/
backup_*/
old_*/

# 个人笔记
*.note
*.todo
personal/

# 开发工具
.sublime-project
.sublime-workspace
.project
.settings/
"""
        
        with open('.gitignore', 'w', encoding='utf-8') as f:
            f.write(gitignore_content)
        
        print("✅ 已创建高级 .gitignore 文件")
        return True
    
    def check_ignored_files(self):
        """检查哪些文件被忽略"""
        print("🔍 检查被忽略的文件...")
        os.system('git status --ignored')
        
        # 显示详细的忽略模式
        print("\n📋 当前 .gitignore 中的忽略模式:")
        print("-" * 40)
        if Path('.gitignore').exists():
            with open('.gitignore', 'r') as f:
                for line in f:
                    if line.strip() and not line.strip().startswith('#'):
                        print(f"  {line.strip()}")
        print("-" * 40)
    
    def analyze_project_structure(self):
        """分析项目结构"""
        print("📁 分析项目结构...")
        
        important_dirs = ['dist', 'rules', 'sources', 'scripts', 'docs', '.github']
        missing_dirs = []
        
        for dir_name in important_dirs:
            dir_path = self.base_dir / dir_name
            if dir_path.exists():
                # 统计文件数量
                files = list(dir_path.rglob('*'))
                dir_files = [f for f in files if f.is_file()]
                print(f"  ├── {dir_name}/: {len(dir_files)} 个文件")
            else:
                print(f"  ├── {dir_name}/: ❌ 不存在")
                missing_dirs.append(dir_name)
        
        if missing_dirs:
            print(f"  ⚠️  缺少重要目录: {', '.join(missing_dirs)}")
        
        return len(missing_dirs) == 0
    
    def safe_git_cleanup(self):
        """安全的Git清理"""
        print("🔒 执行安全Git清理...")
        
        # 检查是否有未提交的更改
        has_changes, changes_list = self.check_uncommitted_changes()
        
        if has_changes:
            print("\n⚠️  警告: 存在未提交的更改")
            print("选择操作:")
            print("  1. 继续清理（可能会丢失未提交的更改）")
            print("  2. 取消操作")
            print("  3. 查看详细更改")
            
            choice = input("\n请输入选择 (1-3): ").strip()
            
            if choice == '2':
                print("❌ 操作已取消")
                return False
            elif choice == '3':
                print("\n📋 详细更改:")
                print("-" * 40)
                for change in changes_list:
                    print(f"  {change}")
                print("-" * 40)
                return False
        
        # 备份
        self.backup_git_status()
        
        # 清理缓存
        print("\n1. 清除Git缓存...")
        os.system('git rm -r --cached .')
        
        # 重新添加
        print("\n2. 重新添加文件...")
        os.system('git add .')
        
        # 验证添加的文件
        print("\n3. 验证添加的文件...")
        result = os.popen('git status --porcelain').read()
        added_files = [line[3:] for line in result.strip().split('\n') if line and line.startswith('A ')]
        
        print(f"  已添加 {len(added_files)} 个文件")
        
        # 显示主要规则文件
        print("\n4. 主要规则文件:")
        rule_files = ['dist/blacklist.txt', 'dist/whitelist.txt', 'sources/sources.json']
        for file in rule_files:
            if (self.base_dir / file).exists():
                size = (self.base_dir / file).stat().st_size
                print(f"  ├── {file}: {size:,} 字节")
            else:
                print(f"  ├── {file}: ❌ 不存在")
        
        print("\n✅ 安全清理完成")
        return True
    
    def git_health_check(self):
        """Git健康检查"""
        print("🩺 执行Git健康检查...")
        
        checks = []
        
        # 检查.git目录
        if (self.base_dir / '.git').exists():
            checks.append(("Git仓库", "✅ 正常"))
        else:
            checks.append(("Git仓库", "❌ 不存在"))
        
        # 检查.gitignore
        if (self.base_dir / '.gitignore').exists():
            with open('.gitignore', 'r') as f:
                content = f.read()
                if 'dist/' in content and not content.split('dist/')[1].startswith('!'):
                    checks.append((".gitignore", "⚠️  dist/被忽略（正确）"))
                else:
                    checks.append((".gitignore", "✅ 正常"))
        else:
            checks.append((".gitignore", "❌ 不存在"))
        
        # 检查远程仓库
        result = os.popen('git remote -v').read().strip()
        if result:
            checks.append(("远程仓库", "✅ 已配置"))
        else:
            checks.append(("远程仓库", "❌ 未配置"))
        
        # 显示检查结果
        print("\n📋 检查结果:")
        print("-" * 40)
        for check_name, status in checks:
            print(f"  {check_name}: {status}")
        print("-" * 40)
        
        # 统计问题
        issues = [c for c in checks if '❌' in c[1] or '⚠️' in c[1]]
        if issues:
            print(f"⚠️  发现 {len(issues)} 个问题")
        else:
            print("✅ 所有检查通过")
        
        return len(issues) == 0
    
    def run_repair(self):
        """运行完整的修复流程"""
        print("=" * 60)
        print("🔧 Git跟踪修复工具 - 增强版")
        print("=" * 60)
        
        # 1. Git健康检查
        print("\n📊 步骤1: Git健康检查")
        self.git_health_check()
        
        # 2. 项目结构分析
        print("\n📊 步骤2: 项目结构分析")
        self.analyze_project_structure()
        
        # 3. 检查.gitignore
        print("\n📊 步骤3: .gitignore检查")
        if not Path('.gitignore').exists():
            print("未找到 .gitignore 文件")
            create_now = input("是否创建? (y/N): ").strip().lower()
            if create_now == 'y':
                self.create_advanced_gitignore()
        else:
            print("已找到 .gitignore 文件")
        
        # 4. 检查被忽略的文件
        print("\n📊 步骤4: 检查被忽略的文件")
        self.check_ignored_files()
        
        # 5. 询问用户操作
        print("\n📊 步骤5: 选择修复操作")
        print("请选择操作:")
        print("  1. 🛡️  安全修复（备份后清理缓存）")
        print("  2. 📝 仅更新.gitignore文件")
        print("  3. 🔍 仅检查状态（不修改）")
        print("  4. 📤 准备提交并推送")
        print("  5. ❌ 退出")
        
        choice = input("\n请输入选择 (1-5): ").strip()
        
        if choice == '1':
            if self.safe_git_cleanup():
                print("\n✅ 修复完成!")
                print("\n📝 下一步:")
                print("  1. 查看状态: git status")
                print("  2. 提交更改: git commit -m '修复Git跟踪'")
                print("  3. 推送到远程: git push origin main")
        elif choice == '2':
            self.create_advanced_gitignore()
        elif choice == '3':
            os.system('git status')
        elif choice == '4':
            print("\n📤 准备提交并推送...")
            # 获取提交信息
            commit_msg = input("请输入提交信息 (留空使用默认): ").strip()
            if not commit_msg:
                commit_msg = f"更新广告拦截规则 - {self.now.strftime('%Y-%m-%d %H:%M')}"
            
            # 检查是否有更改
            result = os.popen('git status --porcelain').read().strip()
            if result:
                print("检测到更改，正在提交...")
                os.system(f'git add .')
                os.system(f'git commit -m "{commit_msg}"')
                print("✅ 提交完成")
                
                push_now = input("是否推送到远程? (y/N): ").strip().lower()
                if push_now == 'y':
                    os.system('git push origin main')
                    print("✅ 推送完成")
            else:
                print("没有检测到更改")
        elif choice == '5':
            print("退出")
        else:
            print("无效选择")
        
        print("\n" + "=" * 60)
        print("🎉 Git修复工具执行完成")
        print("=" * 60)


def main():
    """主函数"""
    fixer = GitFixer()
    fixer.run_repair()


if __name__ == "__main__":
    main()
