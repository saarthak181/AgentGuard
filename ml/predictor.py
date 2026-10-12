"""Validated model loading and risk scoring. Scores are indicators, not calibration."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, feature_vector
DEFAULT_ARTIFACTS = Path(__file__).resolve().parent / "artifacts"


class RiskUnavailable(RuntimeError):
    """Model, feature, or inference failure; the guard must fail closed."""


class RiskPredictor:
    def __init__(self, artifact_path: str | Path | None = None):
        self.artifact_path = Path(artifact_path) if artifact_path else DEFAULT_ARTIFACTS / "model_bundle.joblib"
        self.bundle: dict[str, Any] | None = None
        self.load_error: str | None = None
        try:
            loaded = joblib.load(self.artifact_path)
            if tuple(loaded.get("feature_names", ())) != FEATURE_NAMES:
                raise ValueError("model feature names do not match inference schema")
            if loaded.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
                raise ValueError("model feature schema version is incompatible")
            if not hasattr(loaded.get("estimator"), "predict_proba"):
                raise ValueError("model does not support probability prediction")
            self.bundle = loaded
        except Exception as exc:
            self.load_error = f"{type(exc).__name__}: {exc}"

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    def status(self) -> dict[str, Any]:
        return {"status": "ready" if self.ready else "unavailable",
                "model_version": self.bundle.get("model_version") if self.bundle else None,
                "selected_model": self.bundle.get("selected_model") if self.bundle else None,
                "error": None if self.ready else "model artifact unavailable or incompatible"}

    def predict(self, event: dict[str, Any], history: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
        if self.bundle is None:
            raise RiskUnavailable(f"risk model unavailable: {self.load_error}")
        try:
            vector = np.asarray([feature_vector(event, history)], dtype=float)
            probability = float(self.bundle["estimator"].predict_proba(vector)[0][1])
        except Exception as exc:
            raise RiskUnavailable(f"risk inference failed: {exc}") from exc
        if not math.isfinite(probability) or probability < 0 or probability > 1:
            raise RiskUnavailable("model returned an invalid malicious probability")
        score = int(round(100 * probability))
        return {"probability": probability, "risk_score": score,
                "model_version": self.bundle["model_version"],
                "selected_model": self.bundle["selected_model"]}
