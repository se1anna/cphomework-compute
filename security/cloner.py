"""
RFC Audit Agent - 安全浅克隆与工作区隔离模块
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple
from config import WORKSPACE_DIR
from core.models import TaskPayload
from security.clone_planner import ALWAYS_METADATA, choose_sparse_paths


SSH_KNOWN_HOSTS_FILE = os.getenv("GIT_SSH_KNOWN_HOSTS_FILE", "/run/secrets/git-ssh/known_hosts")


def _ssh_repo_url(repo_url: str) -> str:
    """Use the worker's read-only SSH identity for GitHub/Gitee HTTPS URLs too."""
    value = repo_url.strip()
    match = re.fullmatch(r"https://(github\.com|gitee\.com)/([^?#]+?)(?:\.git)?/?", value, re.IGNORECASE)
    if match:
        host, path = match.groups()
        return f"git@{host.lower()}:{path}.git"
    return value


def _stage_ssh_key(deploy_key: Optional[str]) -> str:
    """Stage this task's in-memory deploy key as a 0600 tmpfs file."""
    if not deploy_key or not deploy_key.strip():
        raise FileNotFoundError("任务报文未提供本次仓库所需的 deployKey")
    # Control-plane JSON/proxy layers may deliver literal escaped newlines,
    # including mixed payloads containing both escaped and real newlines.
    # Normalize transport encoding before writing the short-lived key file.
    key = deploy_key.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    key = key.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    if len(key.encode("utf-8")) > 128 * 1024:
        raise ValueError("任务 deployKey 过大，拒绝加载")
    if "-----BEGIN " not in key or " PRIVATE KEY-----" not in key:
        if key.startswith("***"):
            raise ValueError("任务 deployKey 是脱敏占位符，不是实际私钥")
        raise ValueError("任务 deployKey 不是受支持的 OpenSSH/PEM 私钥格式")
    fd, staged = tempfile.mkstemp(prefix="cphw-git-key-", dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(key)
    os.chmod(staged, 0o600)
    return staged


def prepare_student_workspace(task: TaskPayload) -> Tuple[bool, Path, str]:
    """
    为任务创建独立的工作区目录，并安全浅克隆学生代码仓库
    返回: (success: bool, target_workdir: Path, log: str)
    """
    task_workspace = WORKSPACE_DIR / f"run_{task.taskId}"
    if task_workspace.exists():
        shutil.rmtree(task_workspace, ignore_errors=True)
    task_workspace.mkdir(parents=True, exist_ok=True)

    clone_logs = []

    # 构建受限安全 git clone 参数:
    # 1. 深度截断 (--depth 1)
    # 2. 禁止跟随 HTTP 重定向 (防内网 SSRF 探测)
    # 3. 限制大型对象下载 (--filter=blob:limit=15m 防超大二进制 DoS)
    cmd = [
        "git",
        "-c", "http.followRedirects=false",
        "-c", "transfer.fsckObjects=true",
        "clone",
        "--depth", "1",
        "--filter=blob:none",
        "--no-checkout",
    ]
    if task.branch and task.branch.strip() and not task.branch.strip().startswith("-"):
        cmd.extend(["-b", task.branch.strip()])
    clone_url = _ssh_repo_url(task.repoUrl)
    cmd.extend([clone_url, str(task_workspace)])

    # 严格隔离 Git 进程环境变量 (禁用交互式终端提示并防御机密泄漏)
    staged_key = None
    git_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "HOME": str(task_workspace),
    }
    for sys_key in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"]:
        if sys_key in os.environ:
            git_env[sys_key] = os.environ[sys_key]

    try:
        if clone_url.startswith("git@") or clone_url.startswith("ssh://"):
            if not Path(SSH_KNOWN_HOSTS_FILE).is_file():
                return False, task_workspace, "计算节点未配置 Git SSH known_hosts"
            staged_key = _stage_ssh_key(task.deployKey)
            git_env["GIT_SSH_COMMAND"] = (
                f"ssh -i {staged_key} "
                f"-o IdentitiesOnly=yes -o BatchMode=yes "
                f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={SSH_KNOWN_HOSTS_FILE}"
            )
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
            env=git_env
        )
        if res.returncode != 0:
            err = res.stderr or res.stdout
            return False, task_workspace, f"Git 克隆失败 (退出码 {res.returncode}):\n{err}"

        # Only the Git metadata has been fetched so far.  Let the metadata-only
        # planner choose the relevant source/config paths before any blobs are
        # materialized in the worktree.
        tree_res = subprocess.run(
            ["git", "-C", str(task_workspace), "ls-tree", "-r", "--name-only", "-z", "HEAD"],
            capture_output=True, timeout=45, env=git_env,
        )
        if tree_res.returncode != 0:
            err = (tree_res.stderr or tree_res.stdout).decode("utf-8", errors="replace")
            return False, task_workspace, f"Git 元数据目录树读取失败: {err}"
        try:
            # `ls-tree --name-only` C-quotes non-ASCII paths by default.
            # `-z` emits raw NUL-delimited path bytes, preserving UTF-8 names
            # such as Chinese filenames for the planner and sparse-checkout.
            tree = [path.decode("utf-8") for path in tree_res.stdout.split(b"\0") if path]
        except UnicodeDecodeError as exc:
            return (
                False,
                task_workspace,
                f"Git 仓库路径不是有效 UTF-8，拒绝不完整检出: {exc}",
            )
        gitignore = ""
        ignore_res = subprocess.run(
            ["git", "-C", str(task_workspace), "show", "HEAD:.gitignore"],
            capture_output=True, text=True, timeout=15, env=git_env,
        )
        if ignore_res.returncode == 0:
            gitignore = ignore_res.stdout
        selected, planner_log = choose_sparse_paths(task, tree, gitignore)

        # An explicitly supplied subpath is authoritative, but still only
        # safe tracked source/config files under that path are materialized.
        requested_subpath = (task.subpath or "").strip().lstrip("/\\")
        if requested_subpath and requested_subpath not in {"."}:
            selected = [
                path for path in selected
                if (path in ALWAYS_METADATA and "/" not in path)
                or path == requested_subpath
                or path.startswith(requested_subpath.rstrip("/\\") + "/")
            ]
            if not selected:
                return False, task_workspace, f"指定子路径未找到可检出的安全代码文件: `{requested_subpath}`"

        sparse_res = subprocess.run(
            ["git", "-C", str(task_workspace), "sparse-checkout", "set", "--no-cone", "--stdin"],
            input="".join(f"/{path}\n" for path in selected),
            capture_output=True, text=True, timeout=45, env=git_env,
        )
        if sparse_res.returncode != 0:
            return False, task_workspace, f"Git sparse-checkout 失败: {sparse_res.stderr or sparse_res.stdout}"

        # `clone --no-checkout` leaves the worktree empty.  On the Git version
        # used by the worker, `sparse-checkout set` updates the sparse patterns
        # and index but does not materialize blobs by itself.  Explicitly
        # apply the index or preflight will incorrectly report an empty repo.
        materialize_res = subprocess.run(
            ["git", "-C", str(task_workspace), "read-tree", "-mu", "HEAD"],
            capture_output=True, text=True, timeout=45, env=git_env,
        )
        if materialize_res.returncode != 0:
            return False, task_workspace, (
                "Git sparse-checkout 文件落地失败: "
                f"{materialize_res.stderr or materialize_res.stdout}"
            )
        materialized = [path for path in selected if (task_workspace / path).is_file()]
        if not materialized:
            return False, task_workspace, "Git sparse-checkout 返回成功但未落地任何选定文件"
        clone_logs.append(f"仓库元数据已读取，仅检出 {len(selected)} 个任务相关文件 ({planner_log})")

        # 子路径支持 (Monorepo)
        target_dir = task_workspace
        if task.subpath and task.subpath.strip() and task.subpath.strip() not in {".", "/"}:
            clean_sub = task.subpath.strip().lstrip("/\\")
            sub_path = task_workspace / clean_sub
            try:
                # 严格防御路径穿越
                if not sub_path.resolve().is_relative_to(task_workspace.resolve()):
                    return False, task_workspace, "检测到非法路径穿越尝试"
            except Exception:
                return False, task_workspace, "子路径解析异常"

            if sub_path.exists() and sub_path.is_dir():
                target_dir = sub_path
                clone_logs.append(f"切换至子路径目录: {clean_sub}")
            else:
                return False, task_workspace, f"学生指定的子路径不存在: `{clean_sub}`"

        return True, target_dir, "\n".join(clone_logs)

    except subprocess.TimeoutExpired:
        return False, task_workspace, "Git 克隆网络超时 (>45s)，请检查仓库公开访问权限与网络连通性。"
    except Exception as e:
        return False, task_workspace, f"工作区准备发生未预料异常: {str(e)}"
    finally:
        if staged_key:
            try:
                os.unlink(staged_key)
            except FileNotFoundError:
                pass
