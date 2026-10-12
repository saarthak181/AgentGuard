from fastapi.testclient import TestClient

from backend.database import init_db, persist_action
from backend.main import app
from security.logger import AuditLogger


def add(action_id, tool, status):
    AuditLogger("logs/agent_actions.jsonl", persist=persist_action).record({
        "timestamp": None, "agent_id": "api-test", "session_id": "s1", "action_id": action_id,
        "tool": tool, "action": tool, "arguments": {"value": "✓"}, "target_resource": None,
        "result_summary": status, "status": status, "decision": "allow" if status == "allowed" else "block",
        "reason": "test", "duration_ms": 2,
    })


def test_database_initializes_cleanly_and_health_works():
    init_db()
    response = TestClient(app).get("/health")
    assert response.status_code == 200 and response.json()["database"] == "ok"


def test_root_and_actions_api():
    add("api-1", "calculator", "allowed")
    client = TestClient(app)
    assert client.get("/").status_code == 200
    response = client.get("/actions")
    assert response.status_code == 200 and response.json()["total"] == 1
    assert response.json()["items"][0]["action_id"] == "api-1"


def test_stats_match_persisted_records():
    add("api-allowed", "calculator", "allowed")
    add("api-blocked", "unknown", "blocked")
    add("api-failed", "read_file", "failed")
    add("api-review", "calculator", "review_required")
    result = TestClient(app).get("/stats").json()
    assert result == {"total_actions": 4, "allowed": 1, "blocked": 1, "failed": 1,
                      "review_required": 1, "security_incidents": 3}


def test_pagination_filters_and_validation():
    add("page-1", "calculator", "allowed")
    add("page-2", "calculator", "allowed")
    add("page-3", "search_files", "blocked")
    client = TestClient(app)
    assert client.get("/actions", params={"limit": 1, "offset": 1}).json()["total"] == 3
    filtered = client.get("/actions", params={"status": "blocked", "tool": "search_files"}).json()
    assert filtered["total"] == 1
    assert client.get("/actions", params={"limit": 0}).status_code == 422
    assert client.get("/actions", params={"status": "other"}).status_code == 422


def test_openapi_documentation_is_available():
    response = TestClient(app).get("/openapi.json")
    assert response.status_code == 200 and "/actions" in response.json()["paths"]
    assert "/model" in response.json()["paths"] and "/sessions/{session_id}/actions" in response.json()["paths"]


def test_event_and_session_explorer_endpoints():
    add("explorer-allowed", "calculator", "allowed")
    add("explorer-blocked", "unknown", "blocked")
    client = TestClient(app)
    events = client.get("/events", params={"event_type": "blocked"}).json()
    assert events["total"] == 1 and events["items"][0]["action_id"] == "explorer-blocked"
    sessions = client.get("/sessions").json()["items"]
    assert sessions[0]["session_id"] == "s1" and sessions[0]["action_count"] == 2
    history = client.get("/sessions/s1/actions").json()
    assert history["total"] == 2 and {x["action_id"] for x in history["items"]} == {"explorer-allowed", "explorer-blocked"}


def test_authorization_preflight_rows_are_not_shown_as_executed_actions():
    add("internal-auth", "calculator", "authorization_granted")
    add("final-outcome", "calculator", "allowed")
    client = TestClient(app)
    assert client.get("/actions").json()["total"] == 1
    assert client.get("/events").json()["total"] == 1
    assert client.get("/stats").json()["total_actions"] == 1


def test_model_metadata_and_authorized_threshold_settings(monkeypatch):
    import backend.main as api
    monkeypatch.setenv("AGENTGUARD_APPROVER_TOKEN", "local-test-secret")
    before = api.runtime_guard.thresholds
    client = TestClient(app)
    model = client.get("/model").json()
    assert model["status"] == "ready" and model["metadata"]["dataset_events"] > 0
    assert client.put("/settings", json={"allow_max": 35, "review_max": 65}).status_code == 401
    assert client.put("/settings", headers={"X-Approver-Token": "local-test-secret"},
                      json={"allow_max": 70, "review_max": 60}).status_code == 422
    response = client.put("/settings", headers={"X-Approver-Token": "local-test-secret"},
                          json={"allow_max": 35, "review_max": 65})
    assert response.status_code == 200 and response.json() == {"allow_max": 35, "review_max": 65}
    api.runtime_guard.thresholds = before


def test_local_dashboard_cors_allows_api_and_approver_header():
    response = TestClient(app).options("/approvals/pending", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-approver-token",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "x-approver-token" in response.headers["access-control-allow-headers"].lower()


def test_health_reports_database_failure_as_unavailable(monkeypatch):
    import backend.main as api

    def fail():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(api, "ping", fail)
    response = TestClient(app).get("/health")
    assert response.status_code == 503 and response.json()["detail"] == "database unavailable"


def test_health_reports_model_readiness():
    from backend.main import runtime_guard

    response = TestClient(app).get("/health").json()
    assert response["model"]["status"] == "ready"
    assert response["model"]["model_version"] == runtime_guard.model_status["model_version"]


def test_health_reports_degraded_status_if_model_unavailable(tmp_path, monkeypatch):
    import backend.main as api
    from agent.tools import TOOL_REGISTRY
    from security.guard import AgentGuard
    from ml.predictor import RiskPredictor

    missing = AgentGuard(TOOL_REGISTRY, predictor=RiskPredictor(tmp_path / "absent.joblib"))
    monkeypatch.setattr(api, "runtime_guard", missing)
    response = TestClient(app).get("/health").json()
    assert response["status"] == "degraded" and response["model"]["status"] == "unavailable"


def test_phase_two_database_is_migrated_additively(tmp_path):
    import sqlite3

    from backend.database import configure_database, get_session, init_db
    from backend.models import ActionRecord

    path = tmp_path / "phase2.db"
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE actions (
            action_id VARCHAR(36) PRIMARY KEY, timestamp DATETIME NOT NULL, agent_id VARCHAR(100) NOT NULL,
            session_id VARCHAR(100) NOT NULL, tool VARCHAR(100) NOT NULL, arguments_json TEXT NOT NULL,
            target_resource VARCHAR(512), result_summary TEXT NOT NULL, status VARCHAR(30) NOT NULL,
            decision VARCHAR(30) NOT NULL, reason TEXT NOT NULL, duration_ms FLOAT NOT NULL
        );
        CREATE TABLE security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT, action_id VARCHAR(36) NOT NULL UNIQUE,
            event_type VARCHAR(40) NOT NULL, decision VARCHAR(30) NOT NULL, reason TEXT NOT NULL
        );
        INSERT INTO actions VALUES ('old-action', '2026-01-01T00:00:00', 'a', 's', 'calculator', '{}', NULL, 'kept', 'allowed', 'allow', 'old row', 1.0);
    """)
    connection.commit(); connection.close()
    configure_database(f"sqlite:///{path.as_posix()}")
    init_db()
    db = get_session()
    try:
        old = db.get(ActionRecord, "old-action")
        assert old and old.result_summary == "kept" and old.risk_score is None
    finally:
        db.close()
