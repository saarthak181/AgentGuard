"""Mandatory deterministic rules, intentionally independent of model inference."""

from __future__ import annotations

import json
import re
from typing import Any

SENSITIVE_RE = re.compile(r"(?:^|[/\\._-])(secrets?|credentials?|passwords?|\.ssh|id_rsa|private[_-]?key)(?:$|[/\\._-])", re.I)
CREDENTIAL_RE = re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+")
EXTERNAL_RE = re.compile(r"(?:https?://|s3://|ftp://|webhook|upload|send_email|external_transfer)", re.I)
INJECTION_RE = re.compile(r"(?i)(ignore (?:all )?(?:previous|prior) instructions|reveal (?:the )?(?:system )?prompt|bypass (?:the )?security|exfiltrat|override (?:the )?guard)")


def mandatory_denial(tool: str, arguments: dict[str, Any]) -> str | None:
    """Return a stable, non-ML reason when a request violates a hard restriction."""
    filename = arguments.get("filename")
    if isinstance(filename, str) and any(part == ".." for part in re.split(r"[/\\]+", filename)):
        return "path traversal is not allowed"
    target = arguments.get("filename") or arguments.get("query") or arguments.get("destination")
    if target and SENSITIVE_RE.search(str(target)):
        return "sensitive resource access is prohibited by deterministic policy"
    serialized = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
    if CREDENTIAL_RE.search(serialized):
        return "credential exposure attempt is prohibited by deterministic policy"
    return None
