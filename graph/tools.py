"""
RFC Audit Agent - Agent 专用沙箱执行工具 (Sandbox Tools)
"""

from pathlib import Path
from typing import Optional, Dict, Any
from sandbox.runner import execute_code_sandbox
from core.models import DynamicRunResult


def sandbox_runner_tool(
    repo_dir: str,
    language: str = "python",
    custom_args: Optional[list] = None,
    entry_file: Optional[str] = None,
    project_dir: Optional[str] = None,
    requirements_file: Optional[str] = None,
) -> DynamicRunResult:
    """
    Agent 动态调起隔离沙箱执行代码，并实时采集旁路物理资源的工具
    """
    return execute_code_sandbox(
        repo_dir=Path(repo_dir),
        language=language,
        custom_args=custom_args,
        entry_file=entry_file,
        project_dir=project_dir,
        requirements_file=requirements_file,
    )
