"""
RFC Audit Agent - Python 虚拟环境哈希持久化复用管理器
根据 requirements.txt 的 SHA256 哈希秒级复用已构建的虚拟环境，杜绝重复下载。
"""

import sys
import os
import hashlib
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Tuple, Optional
from config import VENV_CACHE_DIR, PIP_CACHE_DIR
from security.dependency_audit import audit_venv_dependencies, audit_wheelhouse, parse_dependency_manifest
from core.exceptions import DependencyRiskException


def compute_requirements_hash(req_content: str) -> str:
    """计算依赖文件内容的 SHA256 摘要前 16 位"""
    normalized = "\n".join([line.strip() for line in req_content.splitlines() if line.strip() and not line.strip().startswith("#")])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def get_venv_python_executable(venv_dir: Path) -> Path:
    """跨平台获取虚拟环境中的 Python 可执行文件路径"""
    if os.name == "nt":
        exe = venv_dir / "Scripts" / "python.exe"
    else:
        exe = venv_dir / "bin" / "python"
    return exe


def get_or_create_cached_venv(
    repo_dir: Path,
    project_dir: Optional[str] = None,
    requirements_file: Optional[str] = None,
) -> Tuple[str, str]:
    """
    在 Agent 选定的项目目录及其父目录中查找依赖清单，构建/复用持久化虚拟环境。
    返回: (python_executable_path: str, setup_log: str)
    """
    repo_root = repo_dir.resolve()
    manifest_names = ("requirements.txt", "requirement.txt", "pyproject.toml")

    def contained_path(relative: str, label: str) -> Path:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"Agent 指定的{label}不是仓库内相对路径")
        resolved = (repo_root / path).resolve()
        if resolved != repo_root and repo_root not in resolved.parents:
            raise ValueError(f"Agent 指定的{label}越出作业仓库")
        return resolved

    if project_dir:
        search_dir = contained_path(project_dir, "项目目录")
        if not search_dir.is_dir():
            raise FileNotFoundError(f"Agent 指定的项目目录不存在: {project_dir}")
    else:
        search_dir = repo_root

    req_file: Optional[Path] = None
    if requirements_file:
        req_file = contained_path(requirements_file, "依赖清单")
        if req_file.name not in manifest_names:
            raise ValueError(f"不支持的依赖清单类型: {req_file.name}")
        if not req_file.is_file():
            raise FileNotFoundError(f"Agent 指定的依赖清单不存在: {requirements_file}")
        if req_file != repo_root and repo_root not in req_file.parents:
            raise ValueError("Agent 指定的依赖清单越出作业仓库")
    else:
        # 从 Agent 选定的作业文件夹向上找最近清单；因此 hw3/requirements.txt
        # 会优先于仓库根目录的 requirements.txt，且不会误用其他作业目录的依赖。
        current = search_dir
        while True:
            for name in manifest_names:
                candidate = current / name
                if candidate.is_file():
                    req_file = candidate
                    break
            if req_file or current == repo_root:
                break
            if repo_root not in current.parents:
                raise ValueError("Agent 指定的项目目录越出作业仓库")
            current = current.parent

    # 若未提供依赖清单，使用系统默认 Python
    if not req_file:
        return sys.executable, f"[Venv Info] 从 Agent 选定目录 `{search_dir.relative_to(repo_root) or '.'}` 向上未找到依赖清单，使用默认 Python。"
    if req_file.stat().st_size == 0:
        return sys.executable, f"[Venv Info] Agent 选定的依赖清单 `{req_file.relative_to(repo_root)}` 为空，使用默认 Python。"

    try:
        content = req_file.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise RuntimeError(f"无法读取 Agent 选择的依赖清单 `{req_file.relative_to(repo_root)}`: {e}") from e

    req_relative = req_file.relative_to(repo_root).as_posix()
    # Validate declarations before any install-side effect. A fresh cache
    # namespace prevents reuse of environments made by the previous pipeline.
    declarations = parse_dependency_manifest(req_file)
    req_hash = compute_requirements_hash(f"safe-wheel-v1\n{req_relative}\n{content}")
    target_venv_dir = VENV_CACHE_DIR / f"venv_safe_wheels_v1_{req_hash}"
    python_exe = get_venv_python_executable(target_venv_dir)

    # 1. 命中缓存：直接 0ms 复用已持久化的虚拟环境
    if target_venv_dir.exists() and python_exe.exists():
        audit_venv_dependencies(target_venv_dir)
        project_relative = search_dir.relative_to(repo_root).as_posix() or "."
        log = (f"[Venv Cache Hit] Agent 选择 `{project_relative}`；"
               f"使用依赖清单 `{req_relative}`，命中缓存 ({req_hash})。")
        return str(python_exe), log

    # 2. Download wheels only, inspect the archives as data, then install locally.
    # This avoids executing student-provided PEP 517/build-system hooks.
    setup_logs = [f"[Venv Cache Miss] 首次遇到依赖哈希 ({req_hash})，正在创建独立持久化环境..."]
    try:
        install_home = target_venv_dir / "install-home"
        install_tmp = target_venv_dir / "install-tmp"
        install_home.mkdir(parents=True, exist_ok=True)
        install_tmp.mkdir(parents=True, exist_ok=True)
        install_env = {
            "PATH": os.pathsep.join((str(python_exe.parent), "/usr/local/bin", "/usr/bin", "/bin")),
            "HOME": str(install_home),
            "TMPDIR": str(install_tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PIP_CONFIG_FILE": os.devnull,
            # Keep the curated mirror in the otherwise-sanitized installer
            # environment; pip ignores the worker's inherited environment.
            "PIP_INDEX_URL": os.environ.get(
                "PIP_INDEX_URL", "https://pypi.mirrors.ustc.edu.cn/simple"
            ),
            "PIP_DEFAULT_TIMEOUT": os.environ.get("PIP_DEFAULT_TIMEOUT", "30"),
            "PIP_RETRIES": os.environ.get("PIP_RETRIES", "5"),
            "PIP_CACHE_DIR": str(PIP_CACHE_DIR),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # 创建 venv
        subprocess.run(
            [sys.executable, "-m", "venv", str(target_venv_dir)],
            check=True,
            capture_output=True,
            timeout=60,
            env=install_env,
        )
        if declarations:
            with tempfile.TemporaryDirectory(prefix="cphomework-wheel-audit-") as temp_name:
                temp_dir = Path(temp_name)
                wheelhouse = temp_dir / "wheelhouse"
                wheelhouse.mkdir()
                safe_requirements = temp_dir / "requirements.txt"
                safe_requirements.write_text("\n".join(declarations) + "\n", encoding="utf-8")
                download_cmd = [
                    str(python_exe), "-m", "pip", "download",
                    "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
                    "--cache-dir", str(PIP_CACHE_DIR), "--dest", str(wheelhouse),
                    "-r", str(safe_requirements),
                ]
                downloaded = subprocess.run(
                    download_cmd, capture_output=True, text=True, timeout=180, env=install_env,
                )
                if downloaded.returncode != 0:
                    raise RuntimeError(
                        f"仅 wheel 依赖下载失败 (退出码 {downloaded.returncode}); 未运行构建后端"
                    )
                audit_wheelhouse(wheelhouse)
                install_cmd = [
                    str(python_exe), "-m", "pip", "install", "--no-index",
                    "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
                    "--find-links", str(wheelhouse), "-r", str(safe_requirements),
                ]
                installed = subprocess.run(
                    install_cmd, capture_output=True, text=True, timeout=180, env=install_env,
                )
                if installed.returncode != 0:
                    raise RuntimeError(f"已审计 wheel 安装失败 (退出码 {installed.returncode})")

        audit_venv_dependencies(target_venv_dir)
        project_relative = search_dir.relative_to(repo_root).as_posix() or "."
        setup_logs.append(
            f"[Venv Success] Agent 选择 `{project_relative}`；"
            f"`{req_relative}` 已通过预检、wheel-only 安装和安装后审计；缓存键 `{req_hash}`。"
        )
        return str(python_exe), "\n".join(setup_logs)

    except DependencyRiskException:
        # 恶意依赖审计结果必须原样向上报告，不能回退到系统 Python。
        shutil.rmtree(target_venv_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(target_venv_dir, ignore_errors=True)
        raise RuntimeError(f"虚拟环境初始化失败，未执行学生代码: {e}") from e
