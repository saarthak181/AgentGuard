"""Central, explainable hybrid risk assessment.

The score is an operational risk indicator, not a calibrated probability.  The
only probability in an assessment is the model's uncalibrated ML output.
"""
from __future__ import annotations

from typing import Any, Iterable

POLICY_VERSION = "hybrid-risk-v1"


def assess(tool: str, spec: dict[str, Any], arguments: dict[str, Any],
           history: Iterable[dict[str, Any]], ml: dict[str, Any]) -> dict[str, Any]:
    """Return one authoritative 0-100 score from distinct evidence sources."""
    prior = list(history)[-20:]
    inherent = int(spec.get("inherent_risk", 10))
    # Validation and mandatory restrictions are handled before assessment.  A
    # permitted, in-scope request has no contextual penalty.
    contextual = 0
    denied = sum(item.get("status") in {"blocked", "rejected"} for item in prior)
    repeats = sum(item.get("tool") == tool and item.get("arguments") == arguments for item in prior)
    behavioral = min(100, denied * 30 + max(0, repeats - 2) * 15)
    ml_indicator = int(ml["risk_score"])
    score = round(.40 * inherent + .30 * contextual + .20 * behavioral + .10 * ml_indicator)
    return {"policy_version": POLICY_VERSION, "inherent_risk": inherent,
            "contextual_risk": contextual, "behavioral_risk": behavioral,
            "ml_risk": ml_indicator, "final_risk_score": max(0, min(100, score)),
            "formula": "0.40I + 0.30C + 0.20B + 0.10M"}
