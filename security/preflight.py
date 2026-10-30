"""
RFC Audit Agent - 阶段 0：远端预检与文件过滤引擎
在进入代码分析之前，核验文件树、总容量、拦截路径穿越与大型非代码资产。
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple
from config import (
    MAX_FILE_COUNT,
    MAX_SINGLE_CODE_FILE_BYTES,
    MAX_TOTAL_REPO_BYTES,
    FILTERED_EXTENSIONS,
    ALLOWED_CODE_EXTENSIONS
)
from core.models import PreflightResult


# 保留在沙箱中供程序使用，但不进入 LLM 源码上下文的生成物/缓存目录。
# 这些目录经常包含 fontlist、编译缓存、测试缓存或第三方依赖副本。
CONTEXT_EXCLUDED_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

EXECUTABLE_SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".pyi", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
    ".rs", ".go", ".java", ".jl", ".f90", ".f95", ".f03", ".sh", ".bash",
    ".zsh", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".rb", ".php", ".lua",
}
OPAQUE_EXECUTABLE_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib", ".exe", ".class", ".jar", ".wasm",
    ".zip", ".egg", ".whl",
}


def inspect_repository_tree(repo_dir: Path) -> PreflightResult:
    """
    全面扫描仓库目录文件树，执行安全阈值校验与非代码资产过滤
    """
    total_files = 0
    total_size = 0
    code_files: List[str] = []
    filtered_assets: List[str] = []
    risk_reasons: List[str] = []
    security_risks: List[str] = []
    submission_issues: List[str] = []
    
    lang_counter: Dict[str, int] = {
        "python": 0,
        "cpp": 0,
        "c": 0,
        "rust": 0,
        "other": 0
    }

    if not repo_dir.exists() or not repo_dir.is_dir():
        return PreflightResult(
            passed=False,
            risk_reasons=["仓库目录不存在或未能成功检出"],
            submission_issues=["仓库目录不存在或未能成功检出"],
        )

    resolved_base = repo_dir.resolve()

    for root, dirs, files in os.walk(repo_dir):
        # 忽略 .git 目录内部自身文件
        if any(part in CONTEXT_EXCLUDED_DIRS for part in Path(root).parts):
            continue
        # 不删除、不改动这些目录，只是不让它们污染静态 Agent 上下文。
        dirs[:] = [d for d in dirs if d not in CONTEXT_EXCLUDED_DIRS]

        for fname in files:
            total_files += 1
            fpath = Path(root) / fname
            
            # 1. 符号链接安全检查 (防止指向宿主机 /etc 或父目录)
            if fpath.is_symlink():
                try:
                    target = fpath.resolve()
                    if not str(target).startswith(str(resolved_base)):
                        rel_link = str(fpath.relative_to(resolved_base)).replace("\\", "/")
                        reason = f"检测到指向仓库外部的符号链接: {rel_link} -> {target}"
                        risk_reasons.append(reason)
                        security_risks.append(reason)
                        continue
                except Exception:
                    reason = f"检测到无法解析的符号链接: {fname}"
                    risk_reasons.append(reason)
                    security_risks.append(reason)
                    continue

            # 2. 检查文件名中是否有路径遍历/特殊字符
            if ".." in fname or "\0" in fname:
                reason = f"文件名包含路径穿越或截断字符: {fname}"
                risk_reasons.append(reason)
                security_risks.append(reason)
                continue

            try:
                fsize = fpath.stat().st_size
            except Exception:
                fsize = 0

            total_size += fsize
            rel_path = str(fpath.relative_to(resolved_base)).replace("\\", "/")
            suffix = fpath.suffix.lower()

            if suffix in OPAQUE_EXECUTABLE_EXTENSIONS:
                reason = f"仓库含无法静态审计的可执行二进制文件，安全审计不完整: {rel_path}"
                risk_reasons.append(reason)
                security_risks.append(reason)

            # 3. 过滤大型数据与媒体文件 (暂缓下载或跳过分析)
            if suffix in FILTERED_EXTENSIONS or fsize > MAX_SINGLE_CODE_FILE_BYTES:
                filtered_assets.append(f"{rel_path} ({round(fsize / 1024, 1)} KB)")
                if suffix in EXECUTABLE_SOURCE_EXTENSIONS and fsize > MAX_SINGLE_CODE_FILE_BYTES:
                    reason = f"可执行源码超过安全审计单文件上限，无法证明完整覆盖: {rel_path}"
                    risk_reasons.append(reason)
                    security_risks.append(reason)
                continue

            # 4. 统计合规代码文件与主语言推断
            if suffix in ALLOWED_CODE_EXTENSIONS or suffix in EXECUTABLE_SOURCE_EXTENSIONS or fpath.name in {"Makefile", "CMakeLists.txt", "Cargo.toml", "Dockerfile"}:
                code_files.append(rel_path)
                if suffix == ".py":
                    lang_counter["python"] += 1
                elif suffix in {".cpp", ".cc", ".cxx", ".hpp"}:
                    lang_counter["cpp"] += 1
                elif suffix in {".c", ".h"}:
                    lang_counter["c"] += 1
                elif suffix == ".rs" or fpath.name == "Cargo.toml":
                    lang_counter["rust"] += 1
                else:
                    lang_counter["other"] += 1

    # 5. 安全阈值判定
    if total_files == 0:
        reason = "仓库为空，未包含任何提交文件"
        risk_reasons.append(reason)
        submission_issues.append(reason)

    if total_files > MAX_FILE_COUNT:
        reason = f"仓库文件总数 ({total_files}) 超过安全配额上限 ({MAX_FILE_COUNT})，已触发安全资源限制"
        risk_reasons.append(reason)
        security_risks.append(reason)

    if total_size > MAX_TOTAL_REPO_BYTES:
        reason = f"仓库解压体积 ({round(total_size / (1024 * 1024), 1)} MB) 超过安全配额 ({round(MAX_TOTAL_REPO_BYTES / (1024 * 1024), 1)} MB)"
        risk_reasons.append(reason)
        security_risks.append(reason)

    if not code_files and total_files > 0:
        reason = "仓库内未检索到可供评测的代码或文本文件"
        risk_reasons.append(reason)
        submission_issues.append(reason)

    # 推断主要语言
    primary_lang = "python"
    max_count = 0
    for lang, count in lang_counter.items():
        if lang != "other" and count > max_count:
            max_count = count
            primary_lang = lang

    passed = len(risk_reasons) == 0

    return PreflightResult(
        passed=passed,
        total_files=total_files,
        code_files=code_files,
        filtered_assets=filtered_assets,
        repo_size_bytes=total_size,
        risk_reasons=risk_reasons,
        security_risks=security_risks,
        submission_issues=submission_issues,
        primary_language=primary_lang
    )
