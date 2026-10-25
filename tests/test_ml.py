import json

import numpy as np
import pytest

from ml.dataset import ATTACK_FAMILIES, generate_dataset, write_jsonl
from ml.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_features, feature_vector
from ml.pipeline import build_matrix, split_by_trace, split_trace_partitions, train_and_evaluate
from ml.policy import RiskThresholds
from ml.predictor import RiskPredictor, RiskUnavailable


class StaticEstimator:
    def __init__(self, probability):
        self.probability = probability
        self.classes_ = np.asarray([0, 1])

    def predict_proba(self, x):
        return np.asarray([[1 - self.probability, self.probability] for _ in x])


class ReversedEstimator:
    classes_ = np.asarray([1, 0])

    def predict_proba(self, x):
        return np.asarray([[.8, .2] for _ in x])


def test_dataset_generation_is_reproducible_and_has_required_families():
    a = generate_dataset(11, 10, 3)
    b = generate_dataset(11, 10, 3)
    assert a == b
    assert {event["attack_family"] for event in a if event["attack_family"]} == set(ATTACK_FAMILIES)
    assert {event["label"] for event in a} == {0, 1}


def test_labels_and_attack_family_do_not_change_features():
    event = {"tool": "calculator", "arguments": {"expression": "1+2"}, "target_resource": None,
             "label": 0, "attack_family": None, "trace_attack_family": None, "trace_id": "a"}
    changed = {**event, "label": 1, "attack_family": "suspicious_sequence",
               "trace_attack_family": "suspicious_sequence", "trace_id": "z"}
    assert extract_features(event) == extract_features(changed)
    assert tuple(extract_features(event)) == FEATURE_NAMES


def test_feature_extraction_is_past_only_and_bounded():
    event = {"tool": "calculator", "arguments": {"expression": "1+1"}, "label": 0}
    history = [{"tool": "read_file", "target_resource": "sales.txt", "status": "allowed"}]
    baseline = extract_features(event, history)
    changed_current_outcome = {**event, "status": "blocked", "label": 1}
    assert extract_features(changed_current_outcome, history) == baseline
    assert baseline["recent_action_count"] == 1
    assert extract_features(event, history * 40)["recent_action_count"] == 20


def test_training_and_inference_feature_schema_is_stable():
    events = generate_dataset(9, 8, 2)
    matrix, labels, groups, _ = build_matrix(events)
    assert matrix.shape[1] == len(FEATURE_NAMES)
    assert set(labels) == {0, 1}
    sample = next(event for event in events if event["event_index"] == 0)
    assert len(feature_vector(sample)) == matrix.shape[1]


def test_split_keeps_whole_traces_together():
    events = generate_dataset(8, 20, 5)
    x, y, groups, _ = build_matrix(events)
    train, test = split_by_trace(x, y, groups, seed=8)
    assert not set(groups[train]) & set(groups[test])
    assert set(y[train]) == set(y[test]) == {0, 1}


def test_model_selection_validation_and_test_splits_do_not_overlap():
    events = generate_dataset(10, 30, 8)
    x, y, groups, _ = build_matrix(events)
    train, validation, test = split_trace_partitions(x, y, groups, seed=10)
    assert not set(groups[train]) & set(groups[validation])
    assert not set(groups[train]) & set(groups[test])
    assert not set(groups[validation]) & set(groups[test])


def test_actual_training_evaluation_and_serialization(tmp_path):
    dataset = write_jsonl(generate_dataset(202, 40, 12), tmp_path / "traces.jsonl")
    report = train_and_evaluate(dataset, tmp_path / "artifacts", seed=19)
    assert report["selected_model"] in {"random_forest", "xgboost"}
    assert set(report["metrics"]) == {"rule_baseline", "random_forest", "xgboost"}
    assert set(report["per_attack_family"]) == set(ATTACK_FAMILIES)
    assert (report["metadata"]["train_traces"] + report["metadata"]["validation_traces"] +
            report["metadata"]["evaluation_traces"]) == 136
    assert set(report["validation_metrics"]) == set(report["metrics"])
    assert report["calibration"]["validation_events"] > 0
    assert report["calibration"]["test_raw"]["bins"] == 10
    assert report["calibration"]["test_calibrated"]["reliability_curve"]
    predictor = RiskPredictor(tmp_path / "artifacts" / "model_bundle.joblib")
    assert predictor.ready
    score = predictor.predict({"tool": "calculator", "arguments": {"expression": "1+1"}})
    assert 0 <= score["risk_score"] <= 100
    assert score["raw_ml_probability"] is not None
    assert score["calibrated_ml_probability"] is not None


@pytest.mark.parametrize(("score", "decision"), [(0, "ALLOW"), (30, "ALLOW"), (31, "REVIEW"),
                                                     (70, "REVIEW"), (71, "BLOCK"), (100, "BLOCK")])
def test_risk_threshold_boundaries(score, decision):
    assert RiskThresholds().classify(score) == decision


def test_thresholds_are_configurable_and_validated():
    thresholds = RiskThresholds(20, 80)
    assert thresholds.classify(20) == "ALLOW" and thresholds.classify(21) == "REVIEW"
    assert thresholds.classify(80) == "REVIEW" and thresholds.classify(81) == "BLOCK"
    with pytest.raises(ValueError):
        RiskThresholds(70, 30)
    with pytest.raises(ValueError):
        RiskThresholds().classify(101)


def test_threshold_environment_configuration(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ALLOW_MAX", "20")
    monkeypatch.setenv("AGENTGUARD_REVIEW_MAX", "80")
    assert RiskThresholds.from_env() == RiskThresholds(20, 80)
    monkeypatch.setenv("AGENTGUARD_REVIEW_MAX", "10")
    with pytest.raises(ValueError):
        RiskThresholds.from_env()


def test_probability_is_mapped_to_rounded_zero_to_hundred_score(tmp_path):
    import joblib

    artifact = tmp_path / "scoring.joblib"
    joblib.dump({"estimator": StaticEstimator(.306), "model_version": "test",
                 "selected_model": "test", "feature_schema_version": FEATURE_SCHEMA_VERSION,
                 "feature_names": list(FEATURE_NAMES)}, artifact)
    result = RiskPredictor(artifact).predict({"tool": "calculator", "arguments": {"expression": "1+1"}})
    assert result["risk_score"] == 31 and result["raw_ml_probability"] == .306 and result["calibrated_ml_probability"] is None


def test_predictor_uses_malicious_class_label_not_a_fixed_column(tmp_path):
    import joblib
    artifact = tmp_path / "reversed.joblib"
    joblib.dump({"estimator": ReversedEstimator(), "model_version": "test", "selected_model": "test",
                 "feature_schema_version": FEATURE_SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES)}, artifact)
    assert RiskPredictor(artifact).predict({"tool": "calculator", "arguments": {"expression": "1+1"}})["raw_ml_probability"] == .8


def test_missing_and_corrupt_models_are_unavailable(tmp_path):
    missing = RiskPredictor(tmp_path / "missing.joblib")
    assert not missing.ready
    with pytest.raises(RiskUnavailable):
        missing.predict({"tool": "calculator", "arguments": {"expression": "1+1"}})
    corrupt_path = tmp_path / "corrupt.joblib"
    corrupt_path.write_text("not a model", encoding="utf-8")
    assert not RiskPredictor(corrupt_path).ready


def test_incompatible_sklearn_artifact_fails_explicitly(tmp_path):
    import joblib

    artifact = tmp_path / "incompatible.joblib"
    joblib.dump({"estimator": StaticEstimator(.2), "model_version": "test", "selected_model": "test",
                 "feature_schema_version": FEATURE_SCHEMA_VERSION, "feature_names": list(FEATURE_NAMES),
                 "metadata": {"versions": {"scikit_learn": "0.0.0"}}}, artifact)
    predictor = RiskPredictor(artifact)
    assert not predictor.ready
    with pytest.raises(RiskUnavailable, match="trained with scikit-learn 0.0.0"):
        predictor.predict({"tool": "calculator", "arguments": {"expression": "1+1"}})


@pytest.mark.parametrize("probability", [-.1, 1.1, float("nan"), float("inf")])
def test_invalid_model_probabilities_fail_closed(tmp_path, probability):
    import joblib

    artifact = tmp_path / "invalid.joblib"
    joblib.dump({"estimator": StaticEstimator(probability), "model_version": "invalid",
                 "selected_model": "test", "feature_schema_version": FEATURE_SCHEMA_VERSION,
                 "feature_names": list(FEATURE_NAMES)}, artifact)
    predictor = RiskPredictor(artifact)
    with pytest.raises(RiskUnavailable, match="invalid malicious probability"):
        predictor.predict({"tool": "calculator", "arguments": {"expression": "1+1"}})
