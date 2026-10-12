"""Deterministic, past-only feature extraction shared by training and inference."""

from __future__ import annotations

import json
from typing import Any, Iterable

from security.rules import CREDENTIAL_RE, EXTERNAL_RE, INJECTION_RE, SENSITIVE_RE

FEATURE_NAMES = (
    "tool_search_files", "tool_read_file", "tool_calculator", "tool_transfer", "tool_other",
    "recent_action_count", "repeated_call_count", "failed_action_count",
    "sensitive_resource_indicator", "external_communication_indicator", "tool_switch_frequency",
    "recent_denied_count", "credential_exposure_indicator", "prompt_injection_indicator",
    "excessive_action_indicator", "argument_size", "sensitive_then_external_indicator",
)
FEATURE_SCHEMA_VERSION = "agentguard-behavior-v1"
TOOL_CATEGORIES = ("search_files", "read_file", "calculator", "transfer")
def _canonical_target(event: dict[str, Any]) -> str:
    return str(event.get("target_resource") or "").casefold()


def _arguments_text(event: dict[str, Any]) -> str:
    try:
        return json.dumps(event.get("arguments", {}), ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(event.get("arguments", ""))


def extract_features(event: dict[str, Any], history: Iterable[dict[str, Any]] = ()) -> dict[str, float]:
    """Use only request data and prior history; label/family/trace metadata are ignored."""
    prior = list(history)[-20:]
    tool = str(event.get("tool", event.get("action", "unknown"))).casefold()
    args_text = _arguments_text(event)
    target = _canonical_target(event)
    combined = f"{target} {args_text}"
    prior_tools = [str(item.get("tool", item.get("action", "unknown"))).casefold() for item in prior]
    same_target = sum(1 for item in prior if str(item.get("tool", item.get("action", "unknown"))).casefold() == tool
                     and _canonical_target(item) == target)
    switches = sum(1 for a, b in zip(prior_tools, prior_tools[1:]) if a != b)
    failed = sum(1 for item in prior if str(item.get("status", "")).casefold() in {"failed", "error"})
    denied = sum(1 for item in prior if str(item.get("status", "")).casefold() in {"blocked", "review_required", "rejected"})
    had_sensitive = any(SENSITIVE_RE.search(_canonical_target(item)) for item in prior)
    external = bool(EXTERNAL_RE.search(combined) or tool in {"upload_file", "send_email", "http_request", "transfer"})
    return {
        "tool_search_files": float(tool == "search_files"),
        "tool_read_file": float(tool == "read_file"),
        "tool_calculator": float(tool == "calculator"),
        "tool_transfer": float(tool in {"transfer", "upload_file", "send_email", "http_request"}),
        "tool_other": float(tool not in TOOL_CATEGORIES and tool not in {"upload_file", "send_email", "http_request"}),
        "recent_action_count": float(len(prior)),
        "repeated_call_count": float(same_target),
        "failed_action_count": float(failed),
        "sensitive_resource_indicator": float(bool(SENSITIVE_RE.search(combined))),
        "external_communication_indicator": float(external),
        "tool_switch_frequency": float(switches / max(1, len(prior_tools) - 1)),
        "recent_denied_count": float(denied),
        "credential_exposure_indicator": float(bool(CREDENTIAL_RE.search(args_text))),
        "prompt_injection_indicator": float(bool(INJECTION_RE.search(combined))),
        "excessive_action_indicator": float(len(prior) >= 6),
        "argument_size": float(min(len(args_text), 4096)),
        "sensitive_then_external_indicator": float(had_sensitive and external),
    }


def feature_vector(event: dict[str, Any], history: Iterable[dict[str, Any]] = ()) -> list[float]:
    features = extract_features(event, history)
    if tuple(features) != FEATURE_NAMES:
        raise ValueError("feature schema order changed")
    return [features[name] for name in FEATURE_NAMES]
