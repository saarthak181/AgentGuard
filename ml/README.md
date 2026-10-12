# AgentGuard behavioral ML

The current tested environment is Python 3.14.3. Use Python 3.12 or newer for the declared XGBoost/NumPy dependency set.

## Reproduce the synthetic run

From the repository root in PowerShell:

```powershell
python -m ml.dataset --seed 2026 --output ml/data/synthetic_traces.jsonl
python -m ml.pipeline train --dataset ml/data/synthetic_traces.jsonl --artifact-dir ml/artifacts --seed 2026 --test-size 0.25
python -m ml.pipeline evaluate --artifact-dir ml/artifacts
python -m ml.pipeline inspect --artifact-dir ml/artifacts
```

`model_bundle.joblib` contains the selected estimator, exact feature names/order, schema version, model version, and training metadata. `evaluation.json` stores validation selection metrics and untouched test metrics. `training_metadata.json` records the random seed, package versions, event/trace counts, split counts, dataset path, and SHA-256 provenance. Load only model artifacts you trust; joblib artifacts are executable Python serialization formats.

## Dataset and split

The fixed seed generated 480 independent synthetic traces: 160 normal traces and 40 traces for each of eight attack families (sensitive access, credential exposure, external transfer, tool misuse, repeated loops, prompt injection, excessive operations, and suspicious sequences). The generated event file has 2,952 events (2,439 labeled normal and 513 malicious). It includes legitimate file search/read/calculation, hard-negative benign security vocabulary, and less obvious malicious variants. `label` (0/1), `attack_family`, and `trace_attack_family` are dataset ground truth only and are ignored by inference feature extraction.

The split is by `trace_id`: 264 training traces, 96 validation traces, and 120 final test traces (728 events). Model selection uses validation F1; test metrics are calculated after selection on a separate partition. All events from a trace stay in one partition. Median imputation is fitted inside each model pipeline on training rows only. Random Forest uses `balanced_subsample`; XGBoost uses `scale_pos_weight` from training labels.

The training set is synthetic and scenario-authored. It is useful for checking pipeline reproducibility, feature wiring, evaluation code, and basic model behavior. It does not represent the diversity of production agents, adversarial adaptation, or real user behavior, and its metrics do not establish real-world detection performance. Some per-family results are perfect because the synthetic scenario is recognizable; treat those as a sign of dataset simplicity, not demonstrated security efficacy. Obtain independently sourced, reviewed traces and external evaluation before relying on this detector operationally.

## Inference features

`ml.features.FEATURE_NAMES` is the canonical ordered numeric schema shared by training and inference:

| Feature | Meaning at decision time |
| --- | --- |
| `tool_search_files`, `tool_read_file`, `tool_calculator`, `tool_transfer`, `tool_other` | One-hot current tool family |
| `recent_action_count` | Number of previous session actions in the bounded 20-event window |
| `repeated_call_count` | Prior calls matching current tool and target |
| `failed_action_count` | Prior failed/error outcomes |
| `sensitive_resource_indicator` | Sensitive path or resource vocabulary in current request |
| `external_communication_indicator` | External transfer vocabulary, URL, or transfer tool in request |
| `tool_switch_frequency` | Fraction of prior adjacent actions that switched tools |
| `recent_denied_count` | Prior blocked/review/rejected outcomes |
| `credential_exposure_indicator` | Credential-like key/value pattern in request arguments |
| `prompt_injection_indicator` | Known instruction-override phrases in request arguments |
| `excessive_action_indicator` | Six or more actions already in the recent window |
| `argument_size` | JSON argument text length, capped at 4,096 characters |
| `sensitive_then_external_indicator` | Earlier sensitive target followed by a current external action |

Features use only the current request and prior history. Current result, future actions, and ground-truth labels are excluded. The categories and indicators are deterministic heuristics, not semantic understanding.

## Measured comparison

This run used seed 2026, scikit-learn 1.9.1, XGBoost 3.4.1, and model-selection threshold 0.5. Model selection chose **Random Forest** by validation F1 (0.9121 vs XGBoost 0.9008). XGBoost had slightly higher validation PR-AUC, so no claim is made that XGBoost is superior. The selected model is saved as `agentguard-behavior-v1`.

Final untouched test results (positive class = malicious):

| Model | Precision | Recall | F1 | False-positive rate | PR-AUC | TN / FP / FN / TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule baseline | 0.3882 | 0.7444 | 0.5103 | 0.2622 | 0.3357 | 439 / 156 / 34 / 99 |
| Random Forest (selected) | 0.8421 | 0.9624 | 0.8982 | 0.0403 | 0.9753 | 571 / 24 / 5 / 128 |
| XGBoost | 0.8217 | 0.9699 | 0.8897 | 0.0471 | 0.9789 | 567 / 28 / 4 / 129 |

Per-family selected-model test F1 / recall / support (support includes all events in test traces for that family):

| Attack family | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| Sensitive access | 1.0000 | 0.7143 | 0.8333 | 21 |
| Credential exposure | 1.0000 | 1.0000 | 1.0000 | 27 |
| External transfer | 1.0000 | 1.0000 | 1.0000 | 30 |
| Tool misuse | 1.0000 | 1.0000 | 1.0000 | 24 |
| Repeated loop | 1.0000 | 1.0000 | 1.0000 | 70 |
| Prompt injection | 1.0000 | 1.0000 | 1.0000 | 48 |
| Excessive operations | 1.0000 | 0.9333 | 0.9655 | 117 |
| Suspicious sequence | 1.0000 | 1.0000 | 1.0000 | 40 |

These are measurements on this synthetic split only. They are not calibrated-probability estimates and must not be used as a real-world security claim.

## Risk score use

The model produces a validated malicious-class score with the specified mapping `risk_score = round(100 * predicted_malicious_probability)`. It is a model-derived indicator, not a calibrated probability. Provisional inclusive thresholds are 0–30 ALLOW, 31–70 REVIEW, and 71–100 BLOCK. Configure the upper bounds with `AGENTGUARD_ALLOW_MAX` and `AGENTGUARD_REVIEW_MAX`, maintaining `0 <= allow < review <= 100`.

Any load/schema/feature/inference/database-history failure blocks the operation. Mandatory deterministic restrictions run independently before ML; no score can override them. The API health response reports `model.status`, selected model, and version. Model artifacts are loaded at process startup, so restart the backend after retraining or replacing one.

The dashboard reads `/model`, which returns the currently loaded predictor status alongside the evaluation artifact metadata, selected-model metrics, and per-attack-family metrics when the report is available. It displays a missing/unavailable state instead of deriving or filling in metrics. The UI labels the checked-in report as synthetic-data evaluation.
