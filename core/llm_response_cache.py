"""Private, bounded cache of JSON bodies returned by model API calls.

Requests/prompts and authorization headers are deliberately never recorded.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_CACHE_DIR = Path(os.environ.get("LLM_RESPONSE_CACHE_DIR", "/app/logs/llm-response-cache"))
_MAX_FILE_BYTES = 10 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 100 * 1024 * 1024
_RETENTION_DAYS = 14


def cache_llm_response(response: Any, operation: str) -> None:
    """Append one JSON response. Failures here must never affect grading."""
    try:
        raw = response.content
        if not isinstance(raw, bytes) or len(raw) > _MAX_RESPONSE_BYTES:
            return
        body = response.json()
        record = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "http_status": int(response.status_code),
            "response_bytes": len(raw),
            "response_json": body,
        }
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > _MAX_RESPONSE_BYTES:
            return
        with _LOCK:
            _CACHE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(_CACHE_DIR, 0o700)
            now = time.time()
            for old in _CACHE_DIR.glob("responses-*.jsonl*"):
                try:
                    if now - old.stat().st_mtime > _RETENTION_DAYS * 86400:
                        old.unlink()
                except OSError:
                    pass
            day = datetime.now(timezone.utc).strftime("%Y%m%d")
            index = 0
            while True:
                suffix = f".{index}" if index else ""
                path = _CACHE_DIR / f"responses-{day}.jsonl{suffix}"
                if not path.exists() or path.stat().st_size + len(encoded) <= _MAX_FILE_BYTES:
                    break
                index += 1
            fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "ab", closefd=False) as stream:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                    stream.write(encoded)
                    stream.flush()
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                os.close(fd)
            files = sorted(_CACHE_DIR.glob("responses-*.jsonl*"), key=lambda item: item.stat().st_mtime)
            total = sum(item.stat().st_size for item in files)
            while total > _MAX_TOTAL_BYTES and files:
                oldest = files.pop(0)
                size = oldest.stat().st_size
                oldest.unlink()
                total -= size
    except Exception:
        return
