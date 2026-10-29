"""Persistent, secret-safe audit log for claimed tasks and grading outcomes."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Mapping


_LOCK = threading.Lock()
_LOG_PATH = Path(os.getenv("AUDIT_LOG_FILE", "/app/logs/audit.jsonl"))


def _safe(value: Any, limit: int = 32000) -> Any:
    """Keep logs JSON-safe and bounded; never log environment/config secrets."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value).replace("\x00", "")
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def write_event(event: str, *, task: Any = None, report: Any = None,
                phase: str = "", error: str = "", **fields: Any) -> None:
    """Append one structured event.  Logs contain metadata/results, never secrets."""
    record: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "worker_id": os.getenv("WORKER_ID", ""),
    }
    if phase:
        record["phase"] = phase
    if task is not None:
        record["task"] = {
            "task_id": _safe(getattr(task, "taskId", ""), 256),
            "student_id": _safe(getattr(task, "studentId", ""), 256),
            "assignment_id": _safe(getattr(task, "assignmentId", ""), 256),
            "round": getattr(task, "currentRound", None),
            "round_label": _safe(getattr(task, "currentRoundLabel", ""), 256),
        }
    if report is not None:
        record["result"] = {
            "score": getattr(report, "score", None),
            "details": _safe(getattr(report, "details", "")),
        }
    if error:
        record["error"] = _safe(error, 4096)
    for key, value in fields.items():
        # Callers must pass only non-secret, bounded metadata.
        record[key] = _safe(value)

    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            with _LOG_PATH.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
    except OSError as exc:
        # Logging must never prevent the grading state machine from closing a task.
        print(f"[AuditLog Error] 无法写入审计日志: {exc}", flush=True)
