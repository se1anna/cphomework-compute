"""
RFC Audit Agent - 通用多语言编译构建工具链 (Polyglot Toolchain)
支持 C, C++, Rust 等工程的自动化探测、构建与测试套件准备。
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional


def build_c_cpp_project(repo_dir: Path) -> Tuple[bool, Optional[str], str]:
    """
    编译 C/C++ 工程
    返回: (success: bool, executable_path: Optional[str], build_log: str)
    """
    makefile = repo_dir / "Makefile"
    cmakelists = repo_dir / "CMakeLists.txt"

    # 1. 支持 Makefile
    if makefile.exists():
        try:
            res = subprocess.run(["make"], cwd=str(repo_dir), capture_output=True, text=True, timeout=60)
            log = res.stdout + "\n" + res.stderr
            if res.returncode == 0:
                # 寻找编译产物
                for cand in ["main", "app", "solution", "a.out", "main.exe"]:
                    p = repo_dir / cand
                    if p.exists() and os.access(p, os.X_OK if os.name != "nt" else os.F_OK):
                        return True, str(p), f"[Make Success]\n{log}"
                return True, None, f"[Make Complete]\n{log}"
            return False, None, f"[Make Failed code={res.returncode}]\n{log}"
        except Exception as e:
            return False, None, f"[Make Error] {str(e)}"

    # 2. 支持 CMake
    if cmakelists.exists() and shutil.which("cmake"):
        try:
            build_dir = repo_dir / "build"
            res1 = subprocess.run(["cmake", "-B", "build"], cwd=str(repo_dir), capture_output=True, text=True, timeout=60)
            res2 = subprocess.run(["cmake", "--build", "build"], cwd=str(repo_dir), capture_output=True, text=True, timeout=60)
            log = res1.stdout + "\n" + res2.stdout + "\n" + res2.stderr
            return (res2.returncode == 0), str(build_dir), log
        except Exception as e:
            return False, None, f"[CMake Error] {str(e)}"

    # 3. 单文件直接编译
    cpp_files = list(repo_dir.glob("*.cpp")) + list(repo_dir.glob("*.cc"))
    if cpp_files and (shutil.which("g++") or shutil.which("clang++")):
        compiler = "g++" if shutil.which("g++") else "clang++"
        target_bin = repo_dir / ("solution_bin.exe" if os.name == "nt" else "solution_bin")
        cmd = [compiler, "-O3", "-std=c++17", "-o", str(target_bin)] + [str(f) for f in cpp_files]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                return True, str(target_bin), f"[{compiler} Compilation Succeeded]"
            return False, None, f"[{compiler} Compilation Failed]:\n{res.stderr}"
        except Exception as e:
            return False, None, f"[{compiler} Execution Error] {str(e)}"

    c_files = list(repo_dir.glob("*.c"))
    if c_files and (shutil.which("gcc") or shutil.which("clang")):
        compiler = "gcc" if shutil.which("gcc") else "clang"
        target_bin = repo_dir / ("solution_bin.exe" if os.name == "nt" else "solution_bin")
        cmd = [compiler, "-O3", "-o", str(target_bin)] + [str(f) for f in c_files]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                return True, str(target_bin), f"[{compiler} Compilation Succeeded]"
            return False, None, f"[{compiler} Compilation Failed]:\n{res.stderr}"
        except Exception as e:
            return False, None, f"[{compiler} Execution Error] {str(e)}"

    return False, None, "未找到适用的 C/C++ 编译器或工程构建规则"


def build_rust_project(repo_dir: Path) -> Tuple[bool, Optional[str], str]:
    """
    构建 Rust 工程 (Cargo)
    返回: (success: bool, executable_path: Optional[str], build_log: str)
    """
    cargo_toml = repo_dir / "Cargo.toml"
    if not cargo_toml.exists() or not shutil.which("cargo"):
        return False, None, "未找到 Cargo.toml 或系统中未安装 Cargo 工具链"

    try:
        res = subprocess.run(
            ["cargo", "test", "--no-run"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=120
        )
        log = res.stdout + "\n" + res.stderr
        return (res.returncode == 0), str(repo_dir), log
    except Exception as e:
        return False, None, f"[Cargo Error] {str(e)}"
