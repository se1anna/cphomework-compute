"""Persistent per-worker JSONL for process output and grading audit events."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, TextIO
from config import WORKER_ID as _WORKER_ID


_LOCK = threading.RLock()
_LOG_PATH = Path(os.getenv("AUDIT_LOG_FILE", "/app/logs/audit.jsonl"))
_SECRET_PATTERNS = (
    # Credentials embedded in URLs, common bearer/API tokens and private-key blocks.
    (re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@", re.IGNORECASE), r"\1[REDACTED]@"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED PRIVATE KEY]"),
)


def _redact_output(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.replace("\x00", "")


def _append_record(record: dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with _LOG_PATH.open("a", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()


class _TeeStream:
    """Write unchanged to Docker stdout/stderr and persist line records to JSONL."""

    def __init__(self, original: TextIO, event: str):
        self._original = original
        self._event = event
        self._pending = ""
        self._thread_lock = threading.Lock()
        self._inside_private_key = False

    @property
    def encoding(self):
        return getattr(self._original, "encoding", None)

    def writable(self):
        return True

    def isatty(self):
        return self._original.isatty()

    def fileno(self):
        return self._original.fileno()

    def write(self, text: str) -> int:
        if not isinstance(text, str):
            text = str(text)
        written = self._original.write(text)
        with self._thread_lock:
            self._pending += text
            while "\n" in self._pending:
                line, self._pending = self._pending.split("\n", 1)
                self._persist(line)
        return written

    def flush(self):
        self._original.flush()
        with self._thread_lock:
            if self._pending:
                self._persist(self._pending)
                self._pending = ""

    def _persist(self, message: str):
        # Empty-queue polling is intentionally noisy on Docker stdout, but not useful
        # in the durable audit trail; keep task work, errors and audit events instead.
        if self._event == "stdout" and "评测队列暂无待办作业，休眠" in message:
            return
        if "-----BEGIN " in message and "PRIVATE KEY-----" in message:
            self._inside_private_key = True
            message = "[REDACTED PRIVATE KEY BLOCK]"
        elif self._inside_private_key:
            is_end = "-----END " in message and "PRIVATE KEY-----" in message
            message = "[REDACTED PRIVATE KEY BLOCK]"
            if is_end:
                self._inside_private_key = False
        try:
            _append_record({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": self._event,
                "worker_id": _WORKER_ID,
                "message": _redact_output(message),
            })
        except OSError as exc:
            # Bypass the tee to prevent recursive logging failures.
            try:
                self._original.write(f"[AuditLog Error] unable to persist {self._event}: {exc}\n")
                self._original.flush()
            except Exception:
                pass


def install_stream_capture() -> None:
    """Tee stdout/stderr into this worker's JSONL while preserving Docker logs."""
    if not isinstance(sys.stdout, _TeeStream):
        sys.stdout = _TeeStream(sys.stdout, "stdout")
    if not isinstance(sys.stderr, _TeeStream):
        sys.stderr = _TeeStream(sys.stderr, "stderr")


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
        "worker_id": _WORKER_ID,
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

    try:
        _append_record(record)
    except OSError as exc:
        # Logging must never prevent the grading state machine from closing a task.
        try:
            sys.__stderr__.write(f"[AuditLog Error] 无法写入审计日志: {exc}\n")
            sys.__stderr__.flush()
        except Exception:
            pass
