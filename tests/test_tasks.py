import json
import types

from fastapi.testclient import TestClient

from agent.agent import Agent
from backend import main
from backend.database import configure_database
from backend.database import get_session
from backend.models import ActionRecord, TaskRecord


def _decision(action):
    return json.dumps(action)


def _agent_factory(*responses):
    replies = iter(responses)

    def build(*, model, max_steps, timeout, guard):
        return Agent(model=model, max_steps=max_steps, timeout=timeout,
                     llm=lambda _messages: next(replies), guard=guard)

    return build


def test_task_submission_runs_existing_guarded_agent_and_persists_linked_actions(monkeypatch):
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "tool", "name": "calculator", "arguments": {"expression": "44*55"}}),
        _decision({"action": "final", "answer": "44 times 55 is 2420."}),
    ))
    client = TestClient(main.app)
    response = client.post("/tasks", json={"task": "Calculate 44 * 55."})
    assert response.status_code == 202
    task_id, session_id = response.json()["task_id"], response.json()["session_id"]
    detail = client.get(f"/tasks/{task_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "completed"
    assert "2420" in body["answer"]
    assert body["analytics"]["total_actions"] == 1
    assert body["analytics"]["allowed"] == 1
    assert body["analytics"]["tools_used"] == ["calculator"]
    action = body["actions"][0]
    assert len(body["security_events"]) == 1
    assert body["security_events"][0]["action_id"] == action["action_id"]
    assert action["task_id"] == task_id
    assert action["session_id"] == session_id
    assert action["executed"] is True
    assert action["arguments"] == {"expression": "44*55"}
    page = client.get("/actions", params={"task_id": task_id})
    assert page.json()["total"] == 1
    history = client.get(f"/sessions/{session_id}/tasks")
    assert history.json()[0]["task_id"] == task_id
    with open("logs/agent_actions.jsonl", encoding="utf-8") as stream:
        entries = [json.loads(line) for line in stream]
    assert any(item["action_id"] == action["action_id"] and item["task_id"] == task_id for item in entries)


def test_blocked_tool_is_recorded_for_task_and_never_runs(monkeypatch, tmp_path):
    called = []
    original = main.TOOL_REGISTRY["read_file"]["function"]
    monkeypatch.setitem(main.TOOL_REGISTRY["read_file"], "function", lambda **_kwargs: called.append(True))
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "tool", "name": "read_file", "arguments": {"filename": "../secret.txt"}}),
        _decision({"action": "final", "answer": "That path is blocked."}),
    ))
    body = TestClient(main.app).post("/tasks", json={"task": "Read ../secret.txt"}).json()
    detail = TestClient(main.app).get(f"/tasks/{body['task_id']}").json()
    assert called == []
    assert detail["analytics"]["blocked"] == 1
    assert detail["actions"][0]["status"] == "blocked"
    assert detail["actions"][0]["executed"] is False
    monkeypatch.setitem(main.TOOL_REGISTRY["read_file"], "function", original)


def test_input_validation_unknown_task_and_pagination_filter():
    client = TestClient(main.app)
    assert client.post("/tasks", json={"task": "  "}).status_code == 422
    assert client.post("/tasks", json={"task": "x" * 4001}).status_code == 422
    assert client.get("/tasks/not-a-task").status_code == 404
    assert client.get("/tasks/not-a-task/actions").status_code == 404
    assert client.get("/tasks", params={"limit": 1000}).status_code == 405


def test_agent_incomplete_or_tool_failure_is_not_reported_as_success(monkeypatch):
    malformed = lambda _messages: "{malformed"
    monkeypatch.setattr(main, "Agent", lambda *, model, max_steps, timeout, guard:
                        Agent(model=model, max_steps=2, timeout=timeout, llm=malformed, guard=guard))
    client = TestClient(main.app)
    submitted = client.post("/tasks", json={"task": "Do a thing."}).json()
    result = client.get(f"/tasks/{submitted['task_id']}").json()
    assert result["status"] == "failed"
    assert result["error"]


def test_ollama_or_runner_failure_is_persisted_as_failed(monkeypatch):
    def fail(*, model, max_steps, timeout, guard):
        raise RuntimeError("Ollama unavailable")

    monkeypatch.setattr(main, "Agent", fail)
    client = TestClient(main.app)
    submitted = client.post("/tasks", json={"task": "calculate"}).json()
    result = client.get(f"/tasks/{submitted['task_id']}").json()
    assert result["status"] == "failed"
    assert "Ollama unavailable" in result["error"]


def test_task_persistence_failure_returns_service_error(monkeypatch):
    monkeypatch.setattr(main, "create_task", lambda *_args: (_ for _ in ()).throw(RuntimeError("disk")))
    response = TestClient(main.app).post("/tasks", json={"task": "calculate"})
    assert response.status_code == 503
    assert response.json()["detail"] == "task could not be persisted"


def test_agent_status_reports_configured_local_model_without_inference(monkeypatch):
    shown = []

    class Client:
        def __init__(self, timeout):
            assert timeout == 2

        def show(self, model):
            shown.append(model)

    monkeypatch.setenv("AGENTGUARD_MODEL", "local-test-model")
    monkeypatch.setitem(__import__("sys").modules, "ollama", types.SimpleNamespace(Client=Client))
    response = TestClient(main.app).get("/agent/status")
    assert response.json() == {"status": "ready", "provider": "ollama", "model": "local-test-model"}
    assert shown == ["local-test-model"]


def test_task_history_is_available_after_database_reconfiguration(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "final", "answer": "This task is persisted."}),
    ))
    url = f"sqlite:///{(tmp_path / 'restart.db').as_posix()}"
    configure_database(url)
    client = TestClient(main.app)
    submitted = client.post("/tasks", json={"task": "persist me"}).json()
    configure_database(url)
    restored = TestClient(main.app).get(f"/tasks/{submitted['task_id']}")
    assert restored.status_code == 200
    assert restored.json()["status"] == "completed"
    assert restored.json()["answer"] == "This task is persisted."


def test_task_detail_analytics_are_derived_from_persisted_actions(monkeypatch):
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "tool", "name": "calculator", "arguments": {"expression": "1/0"}}),
        _decision({"action": "final", "answer": "I could not calculate that."}),
    ))
    client = TestClient(main.app)
    task = client.post("/tasks", json={"task": "divide"}).json()
    detail = client.get(f"/tasks/{task['task_id']}").json()
    assert detail["analytics"]["total_actions"] == 1
    assert detail["analytics"]["failed"] == 1
    assert detail["status"] == "failed"
    assert detail["analytics"]["average_risk_score"] is not None


def test_sales_report_acceptance_runs_through_task_api_and_real_guard(documents, monkeypatch):
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "tool", "name": "search_files", "arguments": {"query": "sales"}}),
        _decision({"action": "tool", "name": "read_file", "arguments": {"filename": "sales_report.txt"}}),
        _decision({"action": "tool", "name": "calculator", "arguments": {"expression": "12000+15000+18000+21000"}}),
        _decision({"action": "final", "answer": "Sales total 66000, with North India the best region."}),
    ))
    client = TestClient(main.app)
    submitted = client.post("/tasks", json={"task": "Find the sales report, read it, calculate the total sales, and tell me the best region."}).json()
    detail = client.get(f"/tasks/{submitted['task_id']}").json()
    assert detail["status"] == "completed"
    assert "66000" in detail["answer"] and "North India" in detail["answer"]
    assert detail["analytics"]["tools_used"] == ["search_files", "read_file", "calculator"]
    assert detail["analytics"]["total_actions"] == 3
    assert all(action["task_id"] == submitted["task_id"] for action in detail["actions"])


def test_reviewed_action_stays_pending_then_correlates_approval_and_execution(monkeypatch):
    class Predictor:
        def status(self):
            return {"status": "ready", "selected_model": "test"}

        def predict(self, *_args):
            return {"risk_score": 55, "probability": 0.55, "model_version": "test"}

    monkeypatch.setenv("AGENTGUARD_APPROVER_TOKEN", "local-test-token")
    monkeypatch.setattr(main.runtime_guard, "predictor", Predictor())
    calls = []
    original = main.TOOL_REGISTRY["calculator"]["function"]
    monkeypatch.setitem(main.TOOL_REGISTRY["calculator"], "function", lambda expression: calls.append(expression) or {"result": 2420})
    monkeypatch.setitem(main.TOOL_REGISTRY["calculator"], "minimum_decision", "REVIEW")
    monkeypatch.setattr(main, "Agent", _agent_factory(
        _decision({"action": "tool", "name": "calculator", "arguments": {"expression": "44*55"}}),
        _decision({"action": "final", "answer": "The calculation is pending review."}),
    ))
    client = TestClient(main.app)
    submitted = client.post("/tasks", json={"task": "Calculate 44 * 55."}).json()
    pending_task = client.get(f"/tasks/{submitted['task_id']}").json()
    assert pending_task["status"] == "review_required"
    assert pending_task["analytics"]["review_required"] == 1
    assert calls == []
    pending = client.get("/approvals/pending", headers={"X-Approver-Token": "local-test-token"}).json()["items"]
    approval_id = pending[0]["approval_id"]
    unauthorized = client.post(f"/approvals/{approval_id}", json={"decision": "approve", "approver_id": "test"})
    assert unauthorized.status_code == 401
    assert calls == []
    approved = client.post(f"/approvals/{approval_id}", headers={"X-Approver-Token": "local-test-token"},
                           json={"decision": "approve", "approver_id": "test"})
    assert approved.status_code == 200 and approved.json()["executed"] is True
    assert calls == ["44*55"]
    duplicate = client.post(f"/approvals/{approval_id}", headers={"X-Approver-Token": "local-test-token"},
                            json={"decision": "approve", "approver_id": "test"})
    assert duplicate.status_code == 409
    assert calls == ["44*55"]
    resolved = client.get(f"/tasks/{submitted['task_id']}").json()
    assert resolved["status"] == "approval_resolved"
    assert sum(item["task_id"] == submitted["task_id"] for item in resolved["actions"]) == 4
    assert resolved["analytics"]["blocked"] == 1
    assert sum(item["executed"] for item in resolved["actions"]) == 1
    monkeypatch.setitem(main.TOOL_REGISTRY["calculator"], "function", original)

