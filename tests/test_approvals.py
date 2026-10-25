import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from agent.tools import TOOL_REGISTRY
from backend.database import get_session, persist_action
from backend.main import app
from backend.models import ActionRecord, PendingApproval
from security.guard import AgentGuard
from security.logger import AuditLogger
from security.logger import AuditLogError
from ml.predictor import RiskPredictor


class FixedPredictor:
    def __init__(self, score=50, error=None):
        self.score, self.error, self.calls = score, error, 0

    @property
    def ready(self):
        return self.error is None

    def status(self):
        return {"status": "ready" if self.ready else "unavailable", "model_version": "test-model"}

    def predict(self, event, history):
        self.calls += 1
        if self.error:
            raise self.error
        return {"risk_score": self.score, "probability": self.score / 100,
                "model_version": "test-model", "selected_model": "mock"}


def make_guard(tmp_path, predictor=None, tool=None, ttl=60):
    spec = dict(TOOL_REGISTRY["calculator"])
    # These tests exercise the approval lifecycle using a harmless stand-in
    # for a high-impact operation.  Production calculator metadata remains
    # low risk and is not reviewed for ordinary arithmetic.
    spec["minimum_decision"] = "REVIEW"
    spec["inherent_risk"] = 75
    if tool is not None:
        spec["function"] = tool
    return AgentGuard({"calculator": spec}, AuditLogger(tmp_path / "agent_actions.jsonl", persist=persist_action),
                      session_id="approval-tests", predictor=predictor or FixedPredictor(),
                      approver_token="authorized-secret", approval_ttl_seconds=ttl)


def request_review(guard):
    return guard.execute("calculator", {"expression": "1+1"})


def test_deterministic_sensitive_rule_overrides_ml_allow(tmp_path):
    predictor = FixedPredictor(score=0)
    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(tmp_path / "agent_actions.jsonl", persist=persist_action),
                      session_id="mandatory-rule", predictor=predictor, approver_token="authorized-secret")
    result = guard.execute("read_file", {"filename": "secrets.txt"})
    assert result.status == "blocked" and result.decision == "block"
    assert predictor.calls == 0


def test_missing_model_fails_closed(tmp_path):
    predictor = RiskPredictor(tmp_path / "missing.joblib")
    result = make_guard(tmp_path, predictor=predictor).execute("calculator", {"expression": "1+1"})
    assert result.status == "blocked" and "risk model unavailable" in result.error


def test_inference_exception_fails_closed(tmp_path):
    predictor = FixedPredictor(error=RuntimeError("inference exploded"))
    result = make_guard(tmp_path, predictor=predictor).execute("calculator", {"expression": "1+1"})
    assert result.status == "blocked" and "fail-safe" in result.error


def test_history_database_failure_fails_closed(tmp_path, monkeypatch):
    import backend.database as database

    called = []
    predictor = FixedPredictor(score=0)
    guard = make_guard(tmp_path, predictor=predictor, tool=lambda **args: called.append(args))

    def database_error(*_args, **_kwargs):
        raise RuntimeError("history store down")

    monkeypatch.setattr(database, "recent_actions", database_error)
    result = guard.execute("calculator", {"expression": "1+1"})
    assert result.status == "blocked" and called == [] and predictor.calls == 0
    assert "history store down" in result.error


def test_review_stays_pending_and_unexecuted(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args) or {"result": 2})
    result = request_review(guard)
    assert result.status == "review_required" and result.approval_id and calls == []
    db = get_session()
    try:
        pending = db.get(PendingApproval, result.approval_id)
        audit = db.get(ActionRecord, result.action_id)
        assert pending and pending.status == "pending" and audit.status == "review_required"
        line = json.loads((tmp_path / "agent_actions.jsonl").read_text(encoding="utf-8"))
        assert line["action_id"] == pending.action_id == result.action_id
    finally:
        db.close()


def test_approved_action_executes_exactly_once_and_is_audited(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args) or {"result": 2})
    pending = request_review(guard)
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    duplicate = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["executed"] and calls == [{"expression": "1+1"}]
    assert duplicate["status"] == "already_resolved" and len(calls) == 1
    db = get_session()
    try:
        records = db.scalars(select(ActionRecord).where(ActionRecord.related_action_id == pending.action_id)).all()
        assert {r.tool for r in records} == {"approval", "calculator"}
        assert all(r.approval_id == pending.approval_id for r in records)
        approval = next(r for r in records if r.tool == "approval")
        assert approval.status == "approved" and approval.executed is False
    finally:
        db.close()


def test_rejected_action_never_executes(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args))
    pending = request_review(guard)
    result = guard.resolve_approval(pending.approval_id, "reject", "alice", "authorized-secret")
    assert result["status"] == "rejected" and not result["executed"] and calls == []


def test_approved_tool_failure_is_audited(tmp_path):
    calls = []

    def fail(**_args):
        calls.append(True)
        raise RuntimeError("approved tool failed")

    guard = make_guard(tmp_path, tool=fail)
    pending = request_review(guard)
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "failed" and result["executed"] is False and calls == [True]
    db = get_session()
    try:
        execution = db.scalar(select(ActionRecord).where(ActionRecord.approval_id == pending.approval_id,
                                                         ActionRecord.tool == "calculator"))
        assert execution and execution.status == "failed" and "approved tool failed" in execution.result_summary
    finally:
        db.close()


def test_final_audit_failure_after_approved_execution_is_explicit(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args) or {"result": 2})
    original_record = guard.logger.record
    record_count = 0

    def fail_only_completion(entry):
        nonlocal record_count
        record_count += 1
        if record_count == 3:  # review request, approval decision, then execution outcome
            raise AuditLogError("completion sink unavailable")
        return original_record(entry)

    guard.logger.record = fail_only_completion
    pending = request_review(guard)
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "audit_uncertain" and result["executed"] is True
    assert calls == [{"expression": "1+1"}]


def test_unauthorized_approval_is_rejected_without_execution(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args))
    pending = request_review(guard)
    result = guard.resolve_approval(pending.approval_id, "approve", "mallory", "wrong-token")
    assert result["status"] == "unauthorized" and calls == []
    db = get_session()
    try:
        assert db.get(PendingApproval, pending.approval_id).status == "pending"
    finally:
        db.close()


def test_expired_approval_cannot_execute(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args), ttl=1)
    pending = request_review(guard)
    db = get_session()
    try:
        db.execute(update(PendingApproval).where(PendingApproval.approval_id == pending.approval_id)
                   .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        db.commit()
    finally:
        db.close()
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "expired" and calls == []


def test_modified_approval_arguments_are_rejected(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args))
    pending = request_review(guard)
    db = get_session()
    try:
        db.execute(update(PendingApproval).where(PendingApproval.approval_id == pending.approval_id)
                   .values(arguments_json=json.dumps({"expression": "9+9"})))
        db.commit()
    finally:
        db.close()
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "rejected" and calls == []


def test_modified_approval_expiry_is_rejected(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args))
    pending = request_review(guard)
    db = get_session()
    try:
        db.execute(update(PendingApproval).where(PendingApproval.approval_id == pending.approval_id)
                   .values(expires_at=datetime.now(timezone.utc) + timedelta(days=5)))
        db.commit()
    finally:
        db.close()
    result = guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "rejected" and calls == []


def test_approval_is_bound_to_requester_identity(tmp_path):
    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args))
    pending = request_review(guard)
    other_guard = AgentGuard(guard.tools, guard.logger, session_id="other-session", predictor=guard.predictor,
                             approver_token="authorized-secret")
    result = other_guard.resolve_approval(pending.approval_id, "approve", "alice", "authorized-secret")
    assert result["status"] == "rejected" and calls == []


def test_api_requires_approver_and_executes_reviewed_action(tmp_path, monkeypatch):
    import backend.main as api

    calls = []
    guard = make_guard(tmp_path, tool=lambda **args: calls.append(args) or {"result": 2})
    monkeypatch.setattr(api, "runtime_guard", guard)
    pending = request_review(guard)
    client = TestClient(app)
    assert client.get("/approvals/pending").status_code == 401
    listed = client.get("/approvals/pending", headers={"X-Approver-Token": "authorized-secret"})
    assert listed.status_code == 200 and listed.json()["items"][0]["approval_id"] == pending.approval_id
    assert listed.json()["items"][0]["reason"] and isinstance(listed.json()["items"][0]["history"], list)
    approved = client.post(f"/approvals/{pending.approval_id}", headers={"X-Approver-Token": "authorized-secret"},
                           json={"decision": "approve", "approver_id": "alice"})
    assert approved.status_code == 200 and approved.json()["executed"] and len(calls) == 1
