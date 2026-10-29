"""Metadata-only planning for safe, task-focused sparse checkouts."""

from __future__ import annotations

import json
import re
from typing import Dict, Iterable, List, Sequence

import requests

from config import (
    ALLOWED_CODE_EXTENSIONS,
    FILTERED_EXTENSIONS,
    LLM_MAX_OUTPUT_TOKENS,
    LLM_REQUEST_TIMEOUT_SEC,
    OPENAI_API_BASE,
    OPENAI_API_KEY,
    OPENAI_MODEL,
)
from core.models import TaskPayload


EXCLUDED_DIRS = {
    ".git", ".cache", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".nox", ".venv", "venv", "env", "node_modules",
    "build", "dist", "target", "site-packages",
}
ALWAYS_METADATA = {
    "README", "README.md", "README.txt", "requirements.txt", "pyproject.toml",
    "setup.py", "setup.cfg", "environment.yml", "Pipfile", "Cargo.toml",
    "go.mod", "package.json", ".gitignore",
}


def _safe_path(path: str) -> bool:
    """Allow only tracked source/config paths, never generated/cache assets."""
    value = path.replace("\\", "/").strip().lstrip("/")
    parts = value.split("/")
    if not value or ".." in parts or any(part in EXCLUDED_DIRS for part in parts):
        return False
    lower = value.lower()
    if any(lower.endswith(ext) for ext in FILTERED_EXTENSIONS):
        return False
    name = parts[-1]
    return name in ALWAYS_METADATA or any(lower.endswith(ext) for ext in ALLOWED_CODE_EXTENSIONS)


def _week_tokens(task: TaskPayload) -> List[str]:
    text = " ".join([
        task.get_effective_title(), task.assignmentOverview or "", task.get_effective_details(),
    ])
    tokens = set()
    patterns = (
        r"(?:第\s*(\d+)\s*周|week[_ -]?(\d+))",
        r"(?:hw|homework|作业)[_ -]?(\d+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            number = next((x for x in match.groups() if x), None)
            if number:
                n = int(number)
                tokens.update({
                    f"week_{n}", f"week{n}", f"week-{n}", f"第{n}周",
                    f"hw_{n}", f"hw{n}", f"hw-{n}",
                    f"homework_{n}", f"homework{n}", f"homework-{n}",
                })
    return sorted(tokens)


def _fallback_paths(task: TaskPayload, tree: Sequence[str]) -> List[str]:
    safe = [p for p in tree if _safe_path(p)]
    tokens = _week_tokens(task)
    matched = [p for p in safe if any(token.lower() in p.lower().split("/") for token in tokens)]
    requested_subpath = (task.subpath or "").strip().strip("/")
    scoped = [p for p in safe if p == requested_subpath or p.startswith(requested_subpath + "/")] if requested_subpath else []
    selected = matched or scoped or safe
    root_meta = [p for p in safe if "/" not in p and p in ALWAYS_METADATA]
    # Preserve the manifests nearest the selected source files so sparse checkout
    # doesn't silently drop hw3/requirements.txt from a multi-homework repository.
    selected_manifests = set()
    manifests = {p for p in safe if p.rsplit("/", 1)[-1] in ALWAYS_METADATA}
    for path in selected:
        if path.rsplit("/", 1)[-1] in ALWAYS_METADATA:
            continue
        parts = path.split("/")[:-1]
        directories = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
        for directory in directories:
            for name in ("requirements.txt", "requirement.txt", "pyproject.toml"):
                candidate = f"{directory}/{name}" if directory else name
                if candidate in manifests:
                    selected_manifests.add(candidate)
                    break
            if any((f"{directory}/{name}" if directory else name) in manifests
                   for name in ("requirements.txt", "requirement.txt", "pyproject.toml")):
                break
    return sorted(set(root_meta) | set(selected) | selected_manifests)


def _parse_paths(content: str) -> List[str]:
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.I)
    match = re.search(r"\{.*\}", cleaned, flags=re.S)
    if not match:
        raise ValueError("Clone Planner 未返回 JSON")
    data = json.loads(match.group(0))
    paths = data.get("paths", [])
    if not isinstance(paths, list):
        raise ValueError("Clone Planner paths 不是数组")
    return [str(x)[:512] for x in paths[:300]]


def _nearest_dependency_manifests(paths: Iterable[str], safe_tree: Sequence[str]) -> set[str]:
    manifests = {p for p in safe_tree if p.rsplit("/", 1)[-1] in {"requirements.txt", "requirement.txt", "pyproject.toml"}}
    result: set[str] = set()
    for path in paths:
        if path.rsplit("/", 1)[-1] in ALWAYS_METADATA:
            continue
        parts = path.split("/")[:-1]
        directories = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
        for directory in directories:
            candidates = [f"{directory}/{name}" if directory else name
                          for name in ("requirements.txt", "requirement.txt", "pyproject.toml")]
            found = next((candidate for candidate in candidates if candidate in manifests), None)
            if found:
                result.add(found)
                break
    return result


def choose_sparse_paths(task: TaskPayload, tree: Sequence[str], gitignore: str = "") -> tuple[List[str], str]:
    """Ask the metadata-only Agent for paths, then validate and expand them locally."""
    safe_tree = sorted({p.replace("\\", "/") for p in tree if _safe_path(p)})
    fallback = _fallback_paths(task, safe_tree)
    if not OPENAI_API_BASE or not OPENAI_API_KEY or not safe_tree:
        return fallback, "metadata planner unavailable; used safe local week/source fallback"

    system = """你是仓库取材规划 Agent，只能根据作业元数据、Git 目录树和 .gitignore 选择需要检出的路径。
不要执行任何仓库代码，不要要求密钥，不要输出 shell 命令。
如果仓库按 week_1/week_2/第3周 或 hw1/hw_1/homework1 等目录拆分多次作业，
必须结合本次题目与 assignment ID 选中对应作业目录，不要混用别的作业代码或依赖；
同时选择根目录通用配置，以及所选作业目录中最近的 requirements.txt / pyproject.toml。
不要选择 .git、缓存、__pycache__、虚拟环境、
node_modules、构建产物、模型权重、媒体、压缩包或大数据文件。
只输出 JSON：{"paths":["..."],"reason":"..."}。
paths 只能来自给定 tree，或者是 tree 中目录的前缀。"""
    payload: Dict[str, object] = {
        "assignment": {
            "title": task.get_effective_title(),
            "overview": task.assignmentOverview or "",
            "details": task.get_effective_details(),
            "subpath_hint": task.subpath or "",
        },
        "tree": safe_tree,
        "gitignore": (gitignore or "")[:12000],
    }
    try:
        response = requests.post(
            OPENAI_API_BASE.rstrip("/") + "/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={"model": OPENAI_MODEL, "temperature": 1.0, "max_tokens": min(4000, LLM_MAX_OUTPUT_TOKENS),
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]},
            timeout=(15, LLM_REQUEST_TIMEOUT_SEC),
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"].get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Clone Planner 返回空 content")
        requested = _parse_paths(content)
        selected: set[str] = set()
        for requested_path in requested:
            prefix = requested_path.replace("\\", "/").strip().lstrip("/").rstrip("/")
            if not prefix or ".." in prefix.split("/"):
                continue
            for path in safe_tree:
                if path == prefix or path.startswith(prefix + "/"):
                    selected.add(path)
        selected.update(p for p in safe_tree if "/" not in p and p in ALWAYS_METADATA)
        selected.update(_nearest_dependency_manifests(selected, safe_tree))
        if not selected:
            return fallback, "metadata planner selected no valid paths; used safe local fallback"
        return sorted(selected), "metadata planner selected and locally validated sparse paths"
    except Exception as exc:
        return fallback, f"metadata planner unavailable ({type(exc).__name__}); used safe local fallback"
