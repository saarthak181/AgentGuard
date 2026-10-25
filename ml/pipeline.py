"""Train, compare, evaluate, and inspect behavioral classification models."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (average_precision_score, brier_score_loss, confusion_matrix, f1_score,
                             log_loss, precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

from .dataset import ATTACK_FAMILIES, generate_dataset, read_jsonl, write_jsonl
from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, feature_vector

DEFAULT_DATASET = Path("ml/data/synthetic_traces.jsonl")
DEFAULT_ARTIFACTS = Path("ml/artifacts")
MODEL_VERSION = "agentguard-behavior-v2"


def build_matrix(events: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str | None]]:
    histories: dict[str, list[dict[str, Any]]] = {}
    x, y, groups, families = [], [], [], []
    for event in sorted(events, key=lambda e: (e["trace_id"], e["event_index"])):
        sid = str(event["session_id"])
        history = histories.setdefault(sid, [])
        x.append(feature_vector(event, history))
        y.append(int(event["label"]))
        groups.append(str(event["trace_id"]))
        families.append(event.get("trace_attack_family", event.get("attack_family")))
        # Current outcome enters history only for subsequent observations.
        history.append({"tool": event["tool"], "target_resource": event.get("target_resource"), "status": event["status"]})
    return np.asarray(x, dtype=float), np.asarray(y, dtype=int), np.asarray(groups), families


def _rule_baseline(features: np.ndarray) -> np.ndarray:
    indexes = {name: i for i, name in enumerate(FEATURE_NAMES)}
    positive = (features[:, indexes["sensitive_resource_indicator"]] > 0
                ) | (features[:, indexes["external_communication_indicator"]] > 0
                ) | (features[:, indexes["credential_exposure_indicator"]] > 0
                ) | (features[:, indexes["prompt_injection_indicator"]] > 0
                ) | (features[:, indexes["excessive_action_indicator"]] > 0
                ) | (features[:, indexes["sensitive_then_external_indicator"]] > 0
                ) | (features[:, indexes["repeated_call_count"]] >= 3
                ) | (features[:, indexes["failed_action_count"]] >= 3)
    return positive.astype(int)


def _metrics(y_true: np.ndarray, pred: np.ndarray, probability: np.ndarray) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "false_negative_rate": float(fn / max(1, fn + tp)),
        "pr_auc": float(average_precision_score(y_true, probability)) if len(np.unique(y_true)) > 1 else None,
    }


def _calibration_metrics(y_true: np.ndarray, probability: np.ndarray, bins: int = 10) -> dict[str, Any]:
    """Held-out calibration metrics; equal-width bins are documented for reproducibility."""
    probabilities = np.clip(np.asarray(probability, dtype=float), 0, 1)
    ece = 0.0
    reliability = []
    for lower in np.linspace(0, 1, bins, endpoint=False):
        upper = lower + 1 / bins
        mask = (probabilities >= lower) & ((probabilities < upper) if upper < 1 else (probabilities <= upper))
        if mask.any():
            mean_prediction = float(probabilities[mask].mean())
            observed_frequency = float(y_true[mask].mean())
            ece += float(mask.mean()) * abs(mean_prediction - observed_frequency)
            reliability.append({"lower": float(lower), "upper": float(upper), "count": int(mask.sum()),
                                "mean_prediction": mean_prediction, "observed_frequency": observed_frequency})
    return {"brier_score": float(brier_score_loss(y_true, probabilities)),
            "log_loss": float(log_loss(y_true, probabilities, labels=[0, 1])),
            "expected_calibration_error": ece, "bins": bins, "reliability_curve": reliability}


def split_by_trace(x: np.ndarray, y: np.ndarray, groups: np.ndarray,
                   test_size: float = .25, seed: int = 2026) -> tuple[np.ndarray, np.ndarray]:
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(x, y, groups=groups))
    if set(groups[train_idx]) & set(groups[test_idx]):
        raise AssertionError("trace leakage across split")
    return train_idx, test_idx


def split_trace_partitions(x: np.ndarray, y: np.ndarray, groups: np.ndarray, seed: int = 2026,
                           test_size: float = .2, validation_size: float = .2):
    """Create stratified, disjoint trace partitions without leaking a trace.

    The validation partition is calibration-only; the final test partition is
    never used to fit a model, calibrator, or selection threshold.
    """
    if not 0 < test_size < 1 or not 0 < validation_size < 1 or test_size + validation_size >= 1:
        raise ValueError("test_size and validation_size must be positive and sum to less than 1")
    if len(set(groups)) < 6:
        raise ValueError("at least six independent traces are required for train, calibration, and test partitions")
    test_folds = max(2, round(1 / test_size))
    first = StratifiedGroupKFold(n_splits=test_folds, shuffle=True, random_state=seed)
    first_splits = list(first.split(x, y, groups=groups))
    train_validation_idx, test_idx = first_splits[seed % len(first_splits)]
    relative_validation_size = validation_size / (1 - test_size)
    validation_folds = max(2, round(1 / relative_validation_size))
    second = StratifiedGroupKFold(n_splits=validation_folds, shuffle=True, random_state=seed + 1)
    second_splits = list(second.split(x[train_validation_idx], y[train_validation_idx],
                                     groups=groups[train_validation_idx]))
    train_rel, validation_rel = second_splits[(seed + 1) % len(second_splits)]
    train_idx = train_validation_idx[train_rel]
    validation_idx = train_validation_idx[validation_rel]
    if (set(groups[train_idx]) & set(groups[validation_idx]) or
            set(groups[train_idx]) & set(groups[test_idx]) or
            set(groups[validation_idx]) & set(groups[test_idx])):
        raise AssertionError("trace leakage across data partitions")
    return train_idx, validation_idx, test_idx


def train_and_evaluate(dataset_path: str | Path = DEFAULT_DATASET,
                       artifact_dir: str | Path = DEFAULT_ARTIFACTS,
                       seed: int = 2026, test_size: float = .25) -> dict[str, Any]:
    dataset_path = Path(dataset_path)
    if not dataset_path.exists():
        events = generate_dataset(seed)
        write_jsonl(events, dataset_path)
    events = read_jsonl(dataset_path)
    if not events or {int(item["label"]) for item in events} != {0, 1}:
        raise ValueError("dataset must contain both normal (0) and malicious (1) labels")
    x, y, groups, families = build_matrix(events)
    train_idx, validation_idx, test_idx = split_trace_partitions(
        x, y, groups, seed=seed, test_size=test_size, validation_size=.2)
    if any(len(set(y[idx])) < 2 for idx in (train_idx, validation_idx, test_idx)):
        raise ValueError("group split must contain both classes in training, validation, and test sets")
    x_train, y_train = x[train_idx], y[train_idx]
    negatives, positives = np.bincount(y_train, minlength=2)

    models = {
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(n_estimators=240, min_samples_leaf=2,
                                                   class_weight="balanced_subsample", random_state=seed, n_jobs=1)),
        ]),
        "xgboost": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", XGBClassifier(n_estimators=220, max_depth=4, learning_rate=.055,
                                         subsample=.85, colsample_bytree=.9, reg_lambda=2,
                                         scale_pos_weight=float(negatives / max(1, positives)),
                                         objective="binary:logistic", eval_metric="logloss",
                                         random_state=seed, n_jobs=1, verbosity=0)),
        ]),
    }
    evaluations: dict[str, Any] = {}
    validation_metrics: dict[str, Any] = {}
    fitted = {}
    for name, model in models.items():
        model.fit(x_train, y_train)  # All preprocessing is fitted on training rows only.
        validation_probability = model.predict_proba(x[validation_idx])[:, 1]
        validation_pred = (validation_probability >= .5).astype(int)
        validation_metrics[name] = _metrics(y[validation_idx], validation_pred, validation_probability)
        test_probability = model.predict_proba(x[test_idx])[:, 1]
        test_pred = (test_probability >= .5).astype(int)
        evaluations[name] = _metrics(y[test_idx], test_pred, test_probability)
        fitted[name] = model
    validation_rule = _rule_baseline(x[validation_idx])
    validation_metrics["rule_baseline"] = _metrics(y[validation_idx], validation_rule, validation_rule.astype(float))
    test_rule = _rule_baseline(x[test_idx])
    evaluations["rule_baseline"] = _metrics(y[test_idx], test_rule, test_rule.astype(float))
    selected = max(("random_forest", "xgboost"),
                   key=lambda name: (validation_metrics[name]["f1"], validation_metrics[name]["pr_auc"] or 0))

    test_families = [families[i] for i in test_idx]
    family_metrics = {}
    validation_raw = fitted[selected].predict_proba(x[validation_idx])[:, 1]
    # Logistic (Platt) calibration is fitted only on the dedicated validation
    # partition; the held-out test partition is never used to fit it.
    calibrator = LogisticRegression(random_state=seed).fit(validation_raw.reshape(-1, 1), y[validation_idx])
    selected_raw_probability = fitted[selected].predict_proba(x[test_idx])[:, 1]
    selected_probability = calibrator.predict_proba(selected_raw_probability.reshape(-1, 1))[:, 1]
    for family in ATTACK_FAMILIES:
        mask = np.array([item == family for item in test_families], dtype=bool)
        if mask.any():
            pred = (selected_probability[mask] >= .5).astype(int)
            family_metrics[family] = _metrics(y[test_idx][mask], pred, selected_probability[mask])
            family_metrics[family]["support"] = int(mask.sum())
        else:
            family_metrics[family] = {"support": 0, "recall": None}

    artifact_dir = Path(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    metadata = {
        "model_version": MODEL_VERSION, "selected_model": selected, "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES), "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed, "dataset_path": str(dataset_path), "dataset_sha256": dataset_hash,
        "dataset_events": len(events), "dataset_traces": len(set(groups)),
        "train_traces": len(set(groups[train_idx])), "validation_traces": len(set(groups[validation_idx])),
        "evaluation_traces": len(set(groups[test_idx])),
        "train_events": len(train_idx), "validation_events": len(validation_idx), "evaluation_events": len(test_idx),
        "class_counts_train": {"normal": int(negatives), "malicious": int(positives)},
        "split_strategy": "StratifiedGroupKFold by trace_id; all trace events stay in one partition",
        "model_selection": "best Random Forest or XGBoost validation F1; final metrics use untouched test partition",
        "preprocessing": "SimpleImputer(median), fitted on training partition only",
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "xgboost": xgboost.__version__},
        "probability_semantics": "raw classifier score plus sigmoid-calibrated score; final AgentGuard risk is separate",
    }
    bundle = {"estimator": fitted[selected], "calibrator": calibrator, "model_version": MODEL_VERSION,
              "selected_model": selected, "feature_schema_version": FEATURE_SCHEMA_VERSION,
              "feature_names": list(FEATURE_NAMES), "metadata": metadata}
    # Write then replace so a concurrently starting backend sees either the
    # previous complete artifact or the new complete artifact, never a partial
    # joblib stream.
    artifact_path = artifact_dir / "model_bundle.joblib"
    temporary_artifact = artifact_path.with_suffix(".joblib.tmp")
    joblib.dump(bundle, temporary_artifact)
    temporary_artifact.replace(artifact_path)
    report = {"metadata": metadata, "selected_model": selected, "validation_metrics": validation_metrics,
              "metrics": evaluations,
              "per_attack_family": family_metrics, "threshold": .5,
              "calibration": {"method": "sigmoid logistic regression fitted on validation partition", "validation_events": len(validation_idx),
                              "test_raw": _calibration_metrics(y[test_idx], selected_raw_probability),
                              "test_calibrated": _calibration_metrics(y[test_idx], selected_probability),
                              "test_raw_classification": _metrics(y[test_idx], (selected_raw_probability >= .5).astype(int), selected_raw_probability),
                              "test_calibrated_classification": evaluations[selected]},
              "warning": "Synthetic-data evaluation only; does not establish real-world detection performance."}
    (artifact_dir / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (artifact_dir / "training_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return report


def inspect_artifact(artifact_dir: str | Path = DEFAULT_ARTIFACTS) -> dict[str, Any]:
    artifact_dir = Path(artifact_dir)
    bundle = joblib.load(artifact_dir / "model_bundle.joblib")
    # Loading and checking the exact schema is also the backend's readiness contract.
    if tuple(bundle.get("feature_names", ())) != FEATURE_NAMES or bundle.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("model artifact feature schema is incompatible")
    return {key: bundle[key] for key in ("model_version", "selected_model", "feature_schema_version", "feature_names", "metadata")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train", help="train and evaluate models using a trace-aware split")
    train.add_argument("--dataset", default=str(DEFAULT_DATASET))
    train.add_argument("--artifact-dir", default=str(DEFAULT_ARTIFACTS))
    train.add_argument("--seed", type=int, default=2026)
    train.add_argument("--test-size", type=float, default=.25)
    inspect = sub.add_parser("inspect", help="verify and summarize the selected model artifact")
    inspect.add_argument("--artifact-dir", default=str(DEFAULT_ARTIFACTS))
    evaluate = sub.add_parser("evaluate", help="print the persisted held-out evaluation report")
    evaluate.add_argument("--artifact-dir", default=str(DEFAULT_ARTIFACTS))
    args = parser.parse_args()
    if args.command == "train":
        print(json.dumps(train_and_evaluate(args.dataset, args.artifact_dir, args.seed, args.test_size), indent=2))
    elif args.command == "inspect":
        print(json.dumps(inspect_artifact(args.artifact_dir), indent=2))
    else:
        report_path = Path(args.artifact_dir) / "evaluation.json"
        print(report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
