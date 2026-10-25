from datetime import datetime, timedelta, timezone

from agent.tools import TOOL_REGISTRY
from backend.database import persist_action, recent_actions
from security.guard import AgentGuard
from security.logger import AuditLogger
from security.risk import assess


ML_ZERO = {"risk_score": 0, "probability": 0.0, "model_version": "test"}


def test_benign_report_and_repeated_calculations_stay_low_risk():
    history = [
        {"tool": "read_file", "arguments": {"filename": "sales_report.txt"},
         "target_resource": "sales_report.txt", "status": "allowed"},
        {"tool": "calculator", "arguments": {"expression": "1+1"},
         "target_resource": None, "status": "allowed"},
    ] * 3
    result = assess("calculator", TOOL_REGISTRY["calculator"], {"expression": "1+1"}, history, ML_ZERO)
    assert result["behavioral_risk"] == 0
    assert result["behavioral_evidence"] == []


def test_repeated_unauthorized_target_access_is_explained():
    history = [{"tool": "read_file", "arguments": {"filename": "blocked.txt"},
                "target_resource": "blocked.txt", "status": "blocked"}] * 2
    result = assess("read_file", TOOL_REGISTRY["read_file"], {"filename": "blocked.txt"}, history, ML_ZERO)
    assert result["behavioral_risk"] >= 60
    assert "repeated denied attempts against the same target" in result["behavioral_evidence"]


def test_sensitive_then_actual_external_destination_is_high_risk():
    spec = {"inherent_risk": 10}
    history = [{"tool": "read_file", "arguments": {"filename": "secrets.txt"},
                "target_resource": "secrets.txt", "status": "allowed"}]
    result = assess("upload_file", spec, {"destination": "https://example.test/upload"}, history, ML_ZERO)
    assert result["behavioral_risk"] == 80
    assert "sensitive-resource access followed by external transfer attempt" in result["behavioral_evidence"]


def test_old_history_is_outside_the_behavior_window():
    old = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    history = [{"tool": "read_file", "arguments": {"filename": "blocked.txt"}, "timestamp": old,
                "target_resource": "blocked.txt", "status": "blocked"}] * 3
    result = assess("read_file", TOOL_REGISTRY["read_file"], {"filename": "blocked.txt"}, history, ML_ZERO)
    assert result["history_window"] == 0 and result["behavioral_risk"] == 0


def test_persisted_history_is_isolated_by_session_and_agent(tmp_path):
    class Predictor:
        def status(self):
            return {"status": "ready"}

        def predict(self, *_args):
            return ML_ZERO

    tool = {"echo": {"function": lambda value: {"value": value}, "parameters": {"value": "string"}}}
    logger = AuditLogger(tmp_path / "audit.jsonl", persist=persist_action)
    AgentGuard(tool, logger, agent_id="agent-a", session_id="session-a", predictor=Predictor()).execute("echo", {"value": "a"})
    AgentGuard(tool, logger, agent_id="agent-b", session_id="session-b", predictor=Predictor()).execute("echo", {"value": "b"})
    assert len(recent_actions("session-a", agent_id="agent-a")) == 1
    assert recent_actions("session-a", agent_id="agent-b") == []
