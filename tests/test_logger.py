import json

import pytest
from sqlalchemy import select

from backend.database import get_session, persist_action
from backend.models import ActionRecord, SecurityEvent
from security.logger import AuditLogError, AuditLogger, redact


def sample(action_id="action-1", **overrides):
    value = {"timestamp": None, "agent_id": "test-agent", "session_id": "session-1", "action_id": action_id,
             "tool": "read_file", "action": "read_file", "arguments": {"filename": "rêport.txt", "nested": [1, {"safe": "✓"}]},
             "target_resource": "rêport.txt", "result_summary": "read ok", "status": "allowed",
             "decision": "allow", "reason": "policy", "duration_ms": 1.25}
    value.update(overrides)
    return value


def test_jsonl_has_required_fields(tmp_path):
    entry = AuditLogger(tmp_path / "actions.jsonl").record(sample())
    assert {"timestamp", "agent_id", "session_id", "action_id", "tool", "arguments", "target_resource", "result_summary", "status", "decision", "reason", "duration_ms"} <= entry.keys()


def test_events_append_without_overwrite(tmp_path):
    log = AuditLogger(tmp_path / "actions.jsonl")
    log.record(sample("one")); log.record(sample("two"))
    assert [json.loads(line)["action_id"] for line in (tmp_path / "actions.jsonl").read_text(encoding="utf-8").splitlines()] == ["one", "two"]


def test_secrets_redacted_recursively():
    value = redact({"password": "abc", "nested": [{"api_key": "secret"}, "Bearer abc.def token=xyz"]})
    assert value["password"] == "[REDACTED]" and value["nested"][0]["api_key"] == "[REDACTED]"
    assert "abc.def" not in value["nested"][1] and "xyz" not in value["nested"][1]


def test_unicode_and_nested_arguments_preserved(tmp_path):
    entry = AuditLogger(tmp_path / "actions.jsonl").record(sample())
    assert entry["arguments"]["nested"][1]["safe"] == "✓"
    assert "rêport" in (tmp_path / "actions.jsonl").read_text(encoding="utf-8")


def test_logging_failure_is_explicit(tmp_path):
    file_path = tmp_path / "blocker"
    file_path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(AuditLogError, match="audit persistence failed"):
        AuditLogger(file_path / "actions.jsonl").record(sample())


def test_action_id_correlates_jsonl_and_database(tmp_path):
    entry = sample("correlated-action")
    logger = AuditLogger(tmp_path / "actions.jsonl", persist=persist_action)
    logger.record(entry)
    db = get_session()
    try:
        action = db.get(ActionRecord, "correlated-action")
        event = db.scalar(select(SecurityEvent).where(SecurityEvent.action_id == "correlated-action"))
        line = json.loads((tmp_path / "actions.jsonl").read_text(encoding="utf-8"))
        assert action and event and action.action_id == event.action_id == line["action_id"]
    finally:
        db.close()
