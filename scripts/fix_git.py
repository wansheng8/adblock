#!/usr/bin/env python3
"""
修复 Git 跟踪问题的脚本
"""

import os
import sys
from pathlib import Path

def fix_git_tracking():
    """修复 Git 跟踪问题"""
    print("修复 Git 跟踪问题...")
    
    # 检查当前目录
    current_dir = Path.cwd()
    print(f"当前目录: {current_dir}")
    
    # 步骤1: 清除缓存
    print("\n1. 清除 Git 缓存...")
    os.system('git rm -r --cached .')
    
    # 步骤2: 重新添加所有文件
    print("\n2. 重新添加文件...")
    os.system('git add .')
    
    # 步骤3: 检查状态
    print("\n3. 检查 Git 状态...")
    os.system('git status')
    
    print("\n✅ 修复完成!")
    print("请运行以下命令:")
    print("  git commit -m '修复 Git 跟踪'")
    print("  git push origin main")

def create_proper_gitignore():
    """创建正确的 .gitignore 文件"""
    gitignore_content = """# Python
__pycache__/
*.pyc
*.pyo
*.pyd

# IDE
.vscode/
.idea/
*.swp
*.swo

# 系统文件
.DS_Store
Thumbs.db

# 临时文件
*.log
*.tmp
*.temp

# 本地配置
.env
secrets.json

# 备份文件
*.bak
*.backup

# 我们不忽略以下重要目录:
# - dist/ (包含生成的规则文件)
# - rules/raw/ (包含原始规则文件)
# - sources/ (规则源配置)
# - scripts/ (Python脚本)
# - docs/ (文档)
# - .github/ (GitHub Actions配置)
"""
    
    with open('.gitignore', 'w', encoding='utf-8') as f:
        f.write(gitignore_content)
    
    print("✅ 已创建正确的 .gitignore 文件")

def main():
    """主函数"""
    print("=" * 60)
    print("Git 跟踪修复工具")
    print("=" * 60)
    
    # 检查是否有 .gitignore 文件
    if not Path('.gitignore').exists():
        print("未找到 .gitignore 文件，创建中...")
        create_proper_gitignore()
    
    # 显示当前 .gitignore 内容
    print("\n当前 .gitignore 内容:")
    print("-" * 40)
    if Path('.gitignore').exists():
        with open('.gitignore', 'r') as f:
            print(f.read())
    print("-" * 40)
    
    # 询问用户要执行的操作
    print("\n请选择操作:")
    print("1. 修复 Git 跟踪（清除缓存并重新添加）")
    print("2. 仅创建正确的 .gitignore 文件")
    print("3. 检查哪些文件被忽略")
    print("4. 退出")
    
    choice = input("\n请输入选择 (1-4): ").strip()
    
    if choice == '1':
        fix_git_tracking()
    elif choice == '2':
        create_proper_gitignore()
    elif choice == '3':
        os.system('git status --ignored')
    elif choice == '4':
        print("退出")
    else:
        print("无效选择")

if __name__ == "__main__":
    main()
