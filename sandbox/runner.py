"""
RFC Audit Agent - 沙箱动态执行器 (Sandbox Runner)
集成旁路资源监控 (Sidecar Monitor)、持久化虚拟环境与多语言编译工具链。
"""

import os
import sys
import re
import ast
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

from config import SANDBOX_TIMEOUT_SEC
from core.models import DynamicRunResult, RuntimeMetrics
from core.exceptions import DependencyRiskException
from core.sidecar_monitor import SidecarProcessMonitor
from env_manager.python_venv import get_or_create_cached_venv
from env_manager.polyglot_toolchain import build_c_cpp_project, build_rust_project


def _classify_missing_import(
    repo_dir: Path,
    project_path: Path,
    requirements_file: Optional[str],
    stderr: str,
) -> Optional[str]:
    """Attribute ModuleNotFoundError only after checking the selected project's manifest."""
    match = re.search(r"No module named ['\"]([^'\"]+)['\"]", stderr)
    if not match:
        return None
    module = match.group(1).split(".", 1)[0]
    if module in getattr(sys, "stdlib_module_names", set()):
        return None

    manifest_names = ("requirements.txt", "requirement.txt", "pyproject.toml")
    manifest = None
    if requirements_file:
        candidate = (repo_dir / requirements_file).resolve()
        if candidate.is_file() and repo_dir.resolve() in candidate.parents:
            manifest = candidate
    else:
        current = project_path
        while current == repo_dir.resolve() or repo_dir.resolve() in current.parents:
            manifest = next((current / name for name in manifest_names if (current / name).is_file()), None)
            if manifest or current == repo_dir.resolve():
                break
            current = current.parent

    if manifest is None:
        return (
            f"STUDENT_MISSING_REQUIREMENTS_TXT: 第三方模块 `{module}` 未安装；"
            "核对所选作业目录及其父目录后未发现 requirements.txt、requirement.txt 或 pyproject.toml。"
        )

    try:
        manifest_text = manifest.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    # Conservative import-name check: do not blame the student when the manifest
    # visibly declares the missing module; that points to setup/environment failure.
    import_to_distribution = {
        "PIL": "pillow", "cv2": "opencv-python", "yaml": "pyyaml",
        "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    }
    candidates = {module.lower(), import_to_distribution.get(module, "").lower()} - {""}
    declared = any(
        re.search(
            rf"(?im)(?<![\w.-])['\"]?{re.escape(name)}(?:['\"]?\s*(?:[<>=!~;\[\],:]|$))",
            manifest_text,
        )
        for name in candidates
    )
    if declared:
        return f"DECLARED_DEPENDENCY_ENVIRONMENT_FAILURE: `{module}` 已在 `{manifest.relative_to(repo_dir.resolve())}` 声明，但运行时仍无法导入。"
    return (
        f"STUDENT_DEPENDENCY_DECLARATION_MISSING: 第三方模块 `{module}` 未安装，且所选依赖清单 "
        f"`{manifest.relative_to(repo_dir.resolve())}` 未找到对应声明。"
    )


def find_entry_file(repo_dir: Path, language: str) -> Optional[Path]:
    """递归静态发现最可能的作业入口，不依赖固定 homework.py 文件名。"""
    if language == "python":
        candidates = []
        ignored_parts = {".git", "__pycache__", ".venv", "venv", "node_modules"}
        for path in repo_dir.rglob("*.py"):
            if not path.is_file() or ignored_parts.intersection(path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError):
                continue

            has_main_guard = False
            has_top_level_call = False
            semantic_calls = 0
            imports_scientific = False
            for node in ast.walk(tree):
                if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
                    test = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                    if "__name__" in test and "__main__" in test:
                        has_main_guard = True
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in getattr(node, "names", [])]
                    if any(n.startswith(("numpy", "matplotlib", "scipy", "pandas")) for n in names):
                        imports_scientific = True
                if isinstance(node, ast.Call):
                    semantic_calls += 1
                    if isinstance(node.func, ast.Attribute) and node.func.attr in {
                        "savefig", "plot", "show", "write", "to_csv", "dump"
                    }:
                        semantic_calls += 4
                    if isinstance(node, (ast.Call,)) and isinstance(node.func, ast.Name):
                        if node.func.id in {"print", "main", "run", "execute"}:
                            has_top_level_call = True

            # 仅使用静态证据排序：入口保护、输出行为、科学计算语义、路径浅度。
            depth = len(path.relative_to(repo_dir).parts)
            name = path.name.lower()
            score = 0
            score += 1000 if has_main_guard else 0
            score += 150 if has_top_level_call else 0
            score += min(semantic_calls, 50)
            score += 80 if imports_scientific else 0
            score -= 250 if name.startswith(("test_", "test-")) or name.endswith("_test.py") else 0
            score -= depth * 5
            score += min(path.stat().st_size // 1024, 50)
            candidates.append((score, path))

        if candidates:
            candidates.sort(key=lambda item: (-item[0], str(item[1])))
            return candidates[0][1]
    return None


def execute_code_sandbox(
    repo_dir: Path,
    language: str = "python",
    custom_args: Optional[list] = None,
    timeout_sec: int = SANDBOX_TIMEOUT_SEC,
    entry_file: Optional[str] = None,
    project_dir: Optional[str] = None,
    requirements_file: Optional[str] = None,
) -> DynamicRunResult:
    """
    在受控沙箱环境下动态执行作业代码并全程进行旁路物理资源采样
    """
    custom_args = custom_args or []
    setup_logs = []
    repo_dir = Path(repo_dir).resolve()
    requested_project = Path(project_dir or ".")
    project_path = (repo_dir / requested_project).resolve()
    if (requested_project.is_absolute() or ".." in requested_project.parts
            or (project_path != repo_dir and repo_dir not in project_path.parents)
            or not project_path.is_dir()):
        return DynamicRunResult(
            executed=False, exit_code=-1,
            stderr="Agent 指定的项目目录不存在或越出作业仓库，未执行学生代码",
            error_summary="Agent 项目目录无效",
        )
    cmd = []
    cwd = str(project_path)

    # 1. 语言运行时准备
    if language == "python":
        try:
            python_exe, venv_log = get_or_create_cached_venv(
                repo_dir,
                project_dir=project_path.relative_to(repo_dir).as_posix(),
                requirements_file=requirements_file,
            )
        except DependencyRiskException as exc:
            evidence = exc.details or exc.reason
            return DynamicRunResult(
                executed=False,
                exit_code=-3,
                stderr=f"依赖安全审计发现明确风险，学生代码未运行: {exc.reason}; {evidence}",
                error_summary="DEPENDENCY_SECURITY_VIOLATION",
            )
        except Exception as exc:
            return DynamicRunResult(
                executed=False,
                exit_code=-2,
                stderr=f"动态执行环境未就绪，未运行学生代码: {type(exc).__name__}: {exc}",
                error_summary="依赖环境安装/初始化失败，学生代码未运行",
            )
        setup_logs.append(venv_log)
        selected_entry = Path(entry_file) if entry_file else find_entry_file(repo_dir, "python")
        if not selected_entry:
            return DynamicRunResult(
                executed=False,
                exit_code=-1,
                stderr=(
                    "静态遍历未发现可运行的 Python 源文件；未要求固定命名的 main.py/solution.py，"
                    "需由评阅 Agent 根据作业契约判断提交是否包含可执行实现。"
                ),
                error_summary="静态遍历未发现可运行的 Python 源文件"
            )
        if selected_entry.is_absolute():
            try:
                selected_entry = selected_entry.relative_to(repo_dir)
            except ValueError:
                return DynamicRunResult(executed=False, exit_code=-1,
                    stderr="Agent 给出的入口文件不在作业目录内", error_summary="入口路径越界")
        if ".." in selected_entry.parts or selected_entry.suffix.lower() != ".py":
            return DynamicRunResult(executed=False, exit_code=-1,
                stderr="Agent 给出的入口必须是作业目录内的 Python 文件", error_summary="入口命令未通过安全校验")
        entry_path = (repo_dir / selected_entry).resolve()
        if not entry_path.is_file() or repo_dir.resolve() not in entry_path.parents:
            return DynamicRunResult(executed=False, exit_code=-1,
                stderr="Agent 给出的入口文件不存在或越出作业目录", error_summary="入口文件无效")
        setup_logs.append(
            f"[Agent Entry Plan] 执行: python {selected_entry}; "
            "由 Agent 根据静态审计与作业契约选择，不要求固定文件名或 __main__。"
        )
        cmd = [python_exe, str(entry_path)] + custom_args

    elif language in {"cpp", "c"}:
        success, bin_path, build_log = build_c_cpp_project(repo_dir)
        setup_logs.append(build_log)
        if not success or not bin_path:
            return DynamicRunResult(
                executed=False,
                exit_code=1,
                stderr=f"编译构建失败:\n{build_log}",
                error_summary="C/C++ 编译构建未通过"
            )
        cmd = [bin_path] + custom_args

    elif language == "rust":
        cmd = ["cargo", "test", "--", "--nocapture"] + custom_args

    else:
        return DynamicRunResult(
            executed=False,
            exit_code=-1,
            stderr=f"暂不支持的语言执行环境: {language}",
            error_summary="不支持的编程语言"
        )

    # 2. 启动子进程并装配旁路监控器 (Sidecar Monitor)
    try:
        # 严格白名单纯净环境变量注入 (杜绝向学生代码泄露任何 API Key、Token、系统配置或内部服务拓扑)
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(repo_dir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "PYTHONPATH": os.pathsep.join(dict.fromkeys((str(project_path), str(repo_dir)))),
        }
        # 跨平台系统运行时必需变量 (Windows 动态链接与进程初始化支持)
        for sys_key in ["SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP"]:
            if sys_key in os.environ:
                safe_env[sys_key] = os.environ[sys_key]
        # 硬件加速与虚拟环境定向转发
        for hw_key in ["LD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "VIRTUAL_ENV"]:
            if hw_key in os.environ:
                safe_env[hw_key] = os.environ[hw_key]

        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=safe_env
        )

        # 启动高频旁路资源监控 (物理内存/CPU/CUDA显存)
        monitor = SidecarProcessMonitor(proc.pid, sample_interval_sec=0.1)
        monitor.start()

        try:
            stdout, stderr = proc.communicate(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            metrics = monitor.stop()
            return DynamicRunResult(
                executed=True,
                exit_code=-9,
                stdout=stdout[:8192],
                stderr=f"[Hard Timeout] 进程执行超出硬时限 ({timeout_sec}s)，已被强制终止 (SIGKILL)。\n{stderr[:4096]}",
                error_summary=f"沙箱执行硬超时 (>{timeout_sec}s)",
                metrics=metrics
            )

        metrics = monitor.stop()

        full_stdout = ("\n".join(setup_logs) + "\n\n" + stdout).strip() if setup_logs else stdout

        # 简易解析测试断言输出 (如 pass / total)
        tests_passed = len(re.findall(r"\b(PASS|OK|passed)\b", stdout, re.IGNORECASE))
        tests_failed = len(re.findall(r"\b(FAIL|FAILED|error)\b", stdout + stderr, re.IGNORECASE))
        total_tests = max(1, tests_passed + tests_failed) if tests_passed > 0 else 0
        error_summary = None if proc.returncode == 0 else f"进程退出码为非零: {proc.returncode}"
        if proc.returncode != 0 and language == "python":
            dependency_cause = _classify_missing_import(
                repo_dir, project_path, requirements_file, stderr
            )
            if dependency_cause:
                error_summary = dependency_cause

        return DynamicRunResult(
            executed=True,
            exit_code=proc.returncode,
            stdout=full_stdout[:16384],
            stderr=stderr[:16384],
            tests_total=total_tests,
            tests_passed=tests_passed,
            error_summary=error_summary,
            entry_file=str(selected_entry),
            metrics=metrics
        )

    except Exception as e:
        return DynamicRunResult(
            executed=False,
            exit_code=-1,
            stderr=f"沙箱调起失败: {str(e)}",
            error_summary=str(e)
        )
