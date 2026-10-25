"""Central, explainable hybrid risk assessment.

The score is an operational risk indicator, not a calibrated probability.  The
only probability in an assessment is the model's uncalibrated ML output.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from security.rules import EXTERNAL_RE, SENSITIVE_RE

POLICY_VERSION = "hybrid-risk-v1"
BEHAVIOR_WINDOW_MINUTES = 15


def _within_window(event: dict[str, Any], now: datetime) -> bool:
    """Use timestamped events in a short session window; test doubles without a
    timestamp are treated as current rather than silently discarded."""
    timestamp = event.get("timestamp")
    if not timestamp:
        return True
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return now - parsed.astimezone(timezone.utc) <= timedelta(minutes=BEHAVIOR_WINDOW_MINUTES)
    except (TypeError, ValueError):
        return False


def assess(tool: str, spec: dict[str, Any], arguments: dict[str, Any],
           history: Iterable[dict[str, Any]], ml: dict[str, Any]) -> dict[str, Any]:
    """Return one authoritative 0-100 score from distinct evidence sources."""
    now = datetime.now(timezone.utc)
    prior = [item for item in list(history)[-20:] if _within_window(item, now)]
    inherent = int(spec.get("inherent_risk", 10))
    # Validation and mandatory restrictions are handled before assessment.  A
    # permitted, in-scope request has no contextual penalty.
    contextual = 0
    target = str(arguments.get("destination") or arguments.get("filename") or arguments.get("query") or "")
    denied_same_target = sum(item.get("status") in {"blocked", "rejected"} and str(item.get("target_resource") or "") == target for item in prior)
    repeats = sum(item.get("tool") == tool and item.get("arguments") == arguments for item in prior)
    external_attempt = bool(EXTERNAL_RE.search(target) or tool in {"upload_file", "send_email", "http_request", "transfer"})
    prior_sensitive = any(SENSITIVE_RE.search(str(item.get("target_resource") or "")) for item in prior)
    attempted_bypass = any(token in " ".join(str(value) for value in arguments.values()).casefold()
                           for token in ("bypass approval", "escalate permission", "grant admin"))
    evidence: list[str] = []
    behavioral = 0
    if denied_same_target >= 2:
        behavioral = 60
        evidence.append("repeated denied attempts against the same target")
    if prior_sensitive and external_attempt:
        behavioral = max(behavioral, 80)
        evidence.append("sensitive-resource access followed by external transfer attempt")
    # Repeating legitimate requests is intentionally not a risk signal by itself.
    if repeats > 2 and denied_same_target:
        behavioral = max(behavioral, 70)
        evidence.append("repeated denied identical action")
    if attempted_bypass:
        behavioral = max(behavioral, 75)
        evidence.append("attempt to bypass approval or escalate permissions")
    ml_indicator = int(ml["risk_score"])
    score = round(.40 * inherent + .30 * contextual + .20 * behavioral + .10 * ml_indicator)
    return {"policy_version": POLICY_VERSION, "inherent_risk": inherent,
            "contextual_risk": contextual, "behavioral_risk": behavioral,
            "ml_risk": ml_indicator, "final_risk_score": max(0, min(100, score)),
            "behavioral_evidence": evidence, "history_window": len(prior),
            "behavior_window_minutes": BEHAVIOR_WINDOW_MINUTES,
            "formula": "0.40I + 0.30C + 0.20B + 0.10M"}
