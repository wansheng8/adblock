#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Git修复脚本
解决Git跟踪问题，特别是大文件或路径问题
"""

import os
import sys
import subprocess
from pathlib import Path


def run_git_command(command):
    """运行Git命令并返回结果"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def fix_git_tracking():
    """修复Git跟踪问题"""
    print("🔧 开始修复Git跟踪问题")
    
    # 1. 检查Git状态
    print("\n📊 检查Git状态...")
    code, stdout, stderr = run_git_command("git status")
    
    if code != 0:
        print(f"❌ Git状态检查失败: {stderr}")
        return False
    
    print("当前Git状态:")
    print(stdout[:500])  # 只显示前500字符
    
    # 2. 清理未跟踪的文件
    print("\n🧹 清理未跟踪的文件...")
    code, stdout, stderr = run_git_command("git clean -fd")
    if code == 0:
        print("✅ 已清理未跟踪的文件")
    else:
        print(f"⚠️  清理未跟踪文件时警告: {stderr}")
    
    # 3. 重置已修改的文件
    print("\n🔄 重置已修改的文件...")
    code, stdout, stderr = run_git_command("git reset --hard")
    if code == 0:
        print("✅ 已重置所有修改")
    else:
        print(f"⚠️  重置文件时警告: {stderr}")
    
    # 4. 检查大文件
    print("\n📦 检查大文件...")
    code, stdout, stderr = run_git_command("find . -type f -size +10M | head -10")
    if stdout.strip():
        print("发现大于10MB的文件:")
        for file in stdout.strip().split('\n'):
            if file:
                print(f"  • {file}")
    
    # 5. 检查.gitignore
    print("\n📁 检查.gitignore配置...")
    gitignore_path = Path(".gitignore")
    if gitignore_path.exists():
        with open(gitignore_path, 'r') as f:
            content = f.read()
        
        required_ignores = [
            "dist/",
            "rules/raw/",
            "__pycache__/",
            "*.pyc",
            ".DS_Store"
        ]
        
        missing = []
        for ignore in required_ignores:
            if ignore not in content:
                missing.append(ignore)
        
        if missing:
            print(f"⚠️  .gitignore缺少以下条目:")
            for item in missing:
                print(f"  • {item}")
            
            # 添加缺少的条目
            with open(gitignore_path, 'a') as f:
                f.write("\n# 自动添加的条目\n")
                for item in missing:
                    f.write(f"{item}\n")
            print("✅ 已更新.gitignore文件")
        else:
            print("✅ .gitignore配置正确")
    else:
        print("❌ .gitignore文件不存在，创建中...")
        with open(gitignore_path, 'w') as f:
            f.write("""# Python
__pycache__/
*.py[cod]
*$py.class

# 规则文件
dist/
rules/raw/

# 系统文件
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# 临时文件
*.tmp
*.log
""")
        print("✅ 已创建.gitignore文件")
    
    # 6. 修复行尾问题
    print("\n🔧 修复行尾问题...")
    code, stdout, stderr = run_git_command("git config core.autocrlf input")
    if code == 0:
        print("✅ 已配置行尾转换")
    else:
        print(f"⚠️  配置行尾转换时警告: {stderr}")
    
    # 7. 重新添加所有文件
    print("\n📝 重新添加文件...")
    code, stdout, stderr = run_git_command("git add -A")
    if code == 0:
        print("✅ 已重新添加所有文件")
    else:
        print(f"⚠️  添加文件时警告: {stderr}")
    
    # 8. 最后的检查
    print("\n🔍 最终检查...")
    code, stdout, stderr = run_git_command("git status --short")
    if code == 0:
        if stdout.strip():
            print("当前有未提交的更改:")
            print(stdout)
        else:
            print("✅ 工作区干净，无未提交更改")
    else:
        print(f"⚠️  最终检查时警告: {stderr}")
    
    print("\n" + "=" * 60)
    print("✅ Git修复完成!")
    print("=" * 60)
    
    return True


def main():
    """主函数"""
    print("=" * 60)
    print("🔧 Git修复工具")
    print("=" * 60)
    
    # 检查是否在Git仓库中
    code, stdout, stderr = run_git_command("git rev-parse --git-dir")
    if code != 0:
        print("❌ 当前目录不是Git仓库")
        print("请在Git仓库根目录运行此脚本")
        return 1
    
    try:
        success = fix_git_tracking()
        if success:
            return 0
        else:
            return 1
    except KeyboardInterrupt:
        print("\n❌ 用户中断")
        return 130
    except Exception as e:
        print(f"❌ 修复过程中发生错误: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
