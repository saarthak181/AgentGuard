"""Append-only JSONL audit sink with recursive secret redaction."""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization|credential", re.I)
BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
ASSIGNMENT = re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)")


def redact(value: Any, key: str = "") -> Any:
    if SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return ASSIGNMENT.sub(lambda m: f"{m.group(1)}=[REDACTED]", BEARER.sub(r"\1[REDACTED]", value))
    if value is None or type(value) in (bool, int, float):
        return value
    return str(value)


class AuditLogError(RuntimeError):
    """Raised when an audit event cannot be persisted to every configured sink."""


class AuditLogger:
    def __init__(self, path: str | Path = "logs/agent_actions.jsonl",
                 persist: Callable[[dict[str, Any]], None] | None = None):
        self.path = Path(path)
        self.persist = persist
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> dict[str, Any]:
        safe = redact(entry)
        if not safe.get("timestamp"):
            safe["timestamp"] = datetime.now(timezone.utc).isoformat()
        safe.setdefault("action_id", str(uuid4()))
        try:
            line = json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(line + "\n")
                    stream.flush()
                if self.persist:
                    self.persist(safe)
        except Exception as exc:
            raise AuditLogError(f"audit persistence failed: {exc}") from exc
        return safe
