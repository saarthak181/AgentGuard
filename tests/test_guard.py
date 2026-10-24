import json

from agent.tools import TOOL_REGISTRY, calculator
from security.guard import AgentGuard
from security.logger import AuditLogger


def test_allowed_tool_executes_once(tmp_path):
    calls = []
    guard = AgentGuard({"echo": {"function": lambda value: calls.append(value) or {"value": value}, "parameters": {"value": "string"}}},
                       AuditLogger(tmp_path / "actions.jsonl"))
    result = guard.execute("echo", {"value": "hello"})
    assert calls == ["hello"] and result.status == "allowed" and result.audit_persisted


def test_blocked_tool_never_executes(tmp_path):
    calls = []
    guard = AgentGuard({"echo": {"function": lambda **kw: calls.append(kw), "parameters": {"value": "string"}}}, AuditLogger(tmp_path / "actions.jsonl"))
    result = guard.execute("echo", {"value": "x"}, forced_block_reason="policy blocked")
    assert result.status == "blocked" and calls == []


def test_unknown_tool_never_executes(tmp_path):
    calls = []
    guard = AgentGuard({"echo": {"function": lambda **kw: calls.append(kw), "parameters": {}}}, AuditLogger(tmp_path / "actions.jsonl"))
    result = guard.execute("run_code", {})
    assert result.status == "blocked" and calls == [] and "not allowlisted" in result.reason


def test_invalid_arguments_rejected_before_call(tmp_path):
    calls = []
    guard = AgentGuard({"echo": {"function": lambda **kw: calls.append(kw), "parameters": {"value": "string"}}}, AuditLogger(tmp_path / "actions.jsonl"))
    result = guard.execute("echo", {"value": 3})
    assert result.status == "blocked" and calls == []


def test_tool_exceptions_handled_as_failed(tmp_path):
    def fail():
        raise RuntimeError("tool broke")
    guard = AgentGuard({"fail": {"function": fail, "parameters": {}}}, AuditLogger(tmp_path / "actions.jsonl"))
    result = guard.execute("fail", {})
    assert result.status == "failed" and result.decision == "allow" and result.error == "tool broke"
    assert result.executed is True


def test_all_outcomes_have_same_result_shape(tmp_path):
    class SafePredictor:
        def predict(self, *_args):
            return {"risk_score": 0, "probability": 0.0, "model_version": "test"}

    guard = AgentGuard({"ok": {"function": lambda: 1, "parameters": {}}, "fail": {
        "function": lambda: (_ for _ in ()).throw(RuntimeError("failure")), "parameters": {}}},
        AuditLogger(tmp_path / "actions.jsonl"), predictor=SafePredictor())
    results = [guard.execute("ok", {}), guard.execute("missing", {}), guard.execute("fail", {})]
    assert all(set(r.to_dict()) == {"action_id", "tool", "status", "decision", "reason", "result", "duration_ms", "audit_persisted", "error", "risk_score", "risk_probability", "model_version", "approval_id", "executed"} for r in results)
    assert [item.executed for item in results] == [True, False, True]


def test_phase_one_tools_preserved_through_guard(tmp_path, documents):
    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(tmp_path / "actions.jsonl"))
    assert guard.execute("search_files", {"query": "sales"}).result == {"files": ["sales_report.txt"]}
    assert "January: 12000" in guard.execute("read_file", {"filename": "sales_report.txt"}).result["content"]
    assert guard.execute("calculator", {"expression": "12000+15000"}).result["result"] == 27000


def test_audit_action_id_matches_jsonl_entry(tmp_path):
    path = tmp_path / "actions.jsonl"
    guard = AgentGuard({"calc": {"function": calculator, "parameters": {"expression": "string"}}}, AuditLogger(path))
    result = guard.execute("calc", {"expression": "4+5"})
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["action_id"] == result.action_id


def test_audit_failure_is_explicit_in_execution_result(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    calls = []
    guard = AgentGuard({"effect": {"function": lambda: calls.append(True), "parameters": {}}},
                       AuditLogger(blocker / "actions.jsonl"))
    result = guard.execute("effect", {})
    assert calls == [] and result.status == "blocked"
    assert result.audit_persisted is False and "pre-execution audit failed" in result.error


def test_safe_calculator_has_low_hybrid_risk(tmp_path):
    class BenignPredictor:
        def predict(self, *_args):
            return {"risk_score": 0, "probability": 0.0, "model_version": "test"}

    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(tmp_path / "actions.jsonl"), predictor=BenignPredictor())
    result = guard.execute("calculator", {"expression": "25*4"})
    assert result.status == "allowed" and result.risk_score == 0


def test_side_effect_policy_requires_review_even_with_low_ml_signal(tmp_path):
    from backend.database import persist_action
    class BenignPredictor:
        def predict(self, *_args):
            return {"risk_score": 0, "probability": 0.0, "model_version": "test"}

    tool = {"write": {"function": lambda value: value, "parameters": {"value": "string"},
                       "minimum_decision": "REVIEW", "inherent_risk": 75}}
    result = AgentGuard(tool, AuditLogger(tmp_path / "actions.jsonl", persist=persist_action), predictor=BenignPredictor()).execute("write", {"value": "x"})
    assert result.status == "review_required" and result.executed is False
