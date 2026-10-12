"""Provisional thresholds mapping integer risk indicators to enforcement decisions."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskThresholds:
    allow_max: int = 30
    review_max: int = 70

    def __post_init__(self):
        if not (0 <= self.allow_max < self.review_max <= 100):
            raise ValueError("thresholds must satisfy 0 <= allow_max < review_max <= 100")

    def classify(self, score: int) -> str:
        if type(score) is not int or not 0 <= score <= 100:
            raise ValueError("risk score must be an integer from 0 to 100")
        if score <= self.allow_max:
            return "ALLOW"
        if score <= self.review_max:
            return "REVIEW"
        return "BLOCK"

    @classmethod
    def from_env(cls):
        return cls(int(os.getenv("AGENTGUARD_ALLOW_MAX", "30")), int(os.getenv("AGENTGUARD_REVIEW_MAX", "70")))
