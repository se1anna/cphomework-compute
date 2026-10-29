"""安装后第三方依赖审计。

这是高置信度的恶意行为闸门，不把 ``import os``、``subprocess`` 等普通能力
单独视为恶意；只有出现明显的下载执行、反向 shell、凭据读取外传、持久化或
混淆执行组合时才阻断。结果会缓存包名与证据，避免后续重复安装已拦截包。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from config import MALICIOUS_DEPENDENCY_CACHE_FILE
from core.exceptions import DependencyRiskException


_HIGH_CONFIDENCE_RULES = (
    (re.compile(r"(?:curl|wget)\b[^\n|;]*(?:\||;)\s*(?:sh|bash|zsh|python)\b", re.I),
     "下载内容直接交给 shell/python 执行"),
    (re.compile(r"(?:xmrig|stratum\+tcp|/dev/tcp/|nc\s+[^\n]*\s+-e\s+)", re.I),
     "疑似挖矿或反向 shell 行为"),
    (re.compile(r"(?:eval|exec)\s*\([^\n]*(?:base64|b64decode|marshal|zlib|codecs)", re.I),
     "混淆数据解码后动态执行"),
    (re.compile(r"(?:~/.ssh|/\.aws/|/etc/shadow|\.env|API_KEY|ACCESS_TOKEN|PRIVATE_KEY)", re.I),
     "访问凭据或敏感文件"),
    (re.compile(r"(?:/etc/cron|systemd/system|~/.bashrc|~/.profile)", re.I),
     "修改启动或定时持久化位置"),
)

# 这些是 venv 自带的安装器组件，不属于学生声明的第三方依赖；它们会
# 正常包含下载、证书和路径处理代码，不能把自身能力当作恶意行为。
_BOOTSTRAP_PACKAGES = {"pip", "setuptools", "wheel"}


def _load_cache() -> Dict[str, Any]:
    try:
        if MALICIOUS_DEPENDENCY_CACHE_FILE.exists():
            data = json.loads(MALICIOUS_DEPENDENCY_CACHE_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    MALICIOUS_DEPENDENCY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = MALICIOUS_DEPENDENCY_CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(MALICIOUS_DEPENDENCY_CACHE_FILE)


def _installed_distributions(site_packages: Path) -> List[Dict[str, str]]:
    result = subprocess.run(
        [str(site_packages.parent.parent.parent / "bin" / "python"), "-m", "pip", "list", "--path", str(site_packages), "--format=json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"无法读取已安装依赖清单: {result.stderr[:500]}")
    data = json.loads(result.stdout or "[]")
    return [x for x in data if isinstance(x, dict) and x.get("name")]


def _find_site_packages(venv_dir: Path) -> Path:
    candidates = sorted(venv_dir.glob("lib/python*/site-packages"))
    if not candidates:
        raise RuntimeError(f"虚拟环境缺少 site-packages: {venv_dir}")
    return candidates[0]


def _scan_distribution(site_packages: Path, package: str, version: str) -> List[str]:
    normalized = re.sub(r"[-_.]+", "-", package).lower()
    roots = [p for p in site_packages.iterdir() if p.name.lower().replace("_", "-").startswith(normalized)]
    findings: List[str] = []
    scanned_bytes = 0
    scanned_files = 0
    for root in roots:
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if scanned_files >= 800 or scanned_bytes >= 20 * 1024 * 1024:
                break
            if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".mjs", ".sh"}:
                continue
            # 第三方发行包通常携带 tests/examples/docs 以及 dist-info 元数据；
            # 这些文件会出现正常的路径、网络和安装示例，不能作为生产恶意行为证据。
            relative_parts = {part.lower() for part in path.relative_to(site_packages).parts}
            if (
                relative_parts.intersection({"test", "tests", "testing", "example", "examples", "docs", "doc"})
                or any(part.endswith((".dist-info", ".egg-info")) for part in relative_parts)
            ):
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            scanned_files += 1
            scanned_bytes += len(raw)
            text = raw[:5 * 1024 * 1024].decode("utf-8", errors="ignore")
            matched = [reason for pattern, reason in _HIGH_CONFIDENCE_RULES if pattern.search(text)]
            # 仅出现敏感路径/环境变量字符串不是恶意行为；必须同时存在明确的
            # 读取调用与真实出站调用，且代码文件不能只是安装/文档辅助代码。
            if "访问凭据或敏感文件" in matched:
                has_sensitive_read = bool(re.search(
                    r"(?:open|read_text|read_bytes|getenv)\s*\([^\n]{0,240}(?:~/.ssh|/\\.aws/|/etc/shadow|\\.env|API_KEY|ACCESS_TOKEN|PRIVATE_KEY)",
                    text,
                    re.I,
                ))
                has_outbound = bool(re.search(
                    r"(?:requests\.(?:get|post|put|request)|httpx\.(?:get|post|put|request)|"
                    r"urllib\.request\.urlopen|socket\.(?:create_connection|socket)|"
                    r"ftplib\.FTP|websocket\.create_connection)\s*\(",
                    text,
                    re.I,
                ))
                if not (has_sensitive_read and has_outbound):
                    matched.remove("访问凭据或敏感文件")
            # 敏感文件访问单独不阻断；只有和网络/上传能力同一文件出现才算高置信。
            for reason in matched:
                findings.append(f"{package}=={version}::{path.relative_to(site_packages)}: {reason}")
    return findings


def audit_venv_dependencies(venv_dir: Path) -> List[str]:
    """审计虚拟环境；返回发现列表，命中时抛出安全异常并清理该环境。"""
    site_packages = _find_site_packages(venv_dir)
    cache = _load_cache()
    distributions = _installed_distributions(site_packages)
    findings: List[str] = []

    for item in distributions:
        name = str(item["name"])
        version = str(item.get("version", "unknown"))
        if name.lower().replace("-", "_") in _BOOTSTRAP_PACKAGES:
            continue
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in cache:
            findings.append(f"{name}=={version}: 命中已缓存的恶意依赖名称")
            continue
        findings.extend(_scan_distribution(site_packages, name, version))

    if findings:
        package_names = sorted({line.split("==", 1)[0] for line in findings if "==" in line})
        for package in package_names:
            key = re.sub(r"[-_.]+", "-", package).lower()
            cache[key] = {
                "name": package,
                "detected_at": int(time.time()),
                "findings": [line for line in findings if line.startswith(package + "==")][:20],
            }
        _save_cache(cache)
        shutil.rmtree(venv_dir, ignore_errors=True)
        raise DependencyRiskException(
            "安装后依赖审计发现高置信恶意行为，已删除对应持久化虚拟环境",
            "; ".join(findings[:10]),
        )
    return []
