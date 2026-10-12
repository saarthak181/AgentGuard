# FastAPI API reference

Start locally with `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`; interactive OpenAPI docs are at `/docs`.

| Route | Purpose |
| --- | --- |
| `GET /` | Service identity and docs path. |
| `GET /health` | Database and loaded model readiness. Returns 503 when database ping fails; model absence is reported as degraded. |
| `GET /agent/status` | Ollama/model availability and the configured model name; does not run inference. |
| `POST /tasks` | Persist and run `{ "task": "...", "session_id": "optional-existing-session" }` through the existing Agent and AgentGuard; task text limit is 4,000 characters. Returns HTTP 202. |
| `GET /tasks/{task_id}` | Persisted task status, backend-derived action analytics, and sanitized actions. |
| `GET /tasks/{task_id}/actions?limit=50&offset=0` | Bounded task-specific action history. |
| `GET /sessions/{session_id}/tasks?limit=50` | Persisted conversation task history; this does not imply model memory between tasks. |
| `GET /actions?limit=50&offset=0&status=&tool=&task_id=` | Paginated persisted action history; maximum page size 200. |
| `GET /stats` | Aggregate persisted allowed, blocked, failed, and review-required outcomes, plus a security incident count (blocked + failed + review-required). |
| `GET /events?limit=50&offset=0&event_type=` | Paginated audit/security events joined to action details. |
| `GET /sessions?limit=50` | Recent session IDs and persisted action counts. |
| `GET /sessions/{session_id}/actions?limit=50&offset=0` | Ordered action history for the requested session. |
| `GET /model` | Runtime predictor status and persisted evaluation metadata/metrics when available. |
| `GET /settings` | Active process allow/review risk thresholds. |
| `PUT /settings` | Validated threshold update; requires `X-Approver-Token`. Values must satisfy `0 <= allow_max < review_max <= 100`. Applies until restart. |
| `GET /approvals/pending?limit=50` | Pending approvals with redacted arguments, original explanation, session ID, and up to five recent session actions; requires `X-Approver-Token`. |
| `POST /approvals/{approval_id}` | Submit `{ "decision": "approve"|"reject", "approver_id": "..." }`; requires `X-Approver-Token`. The guard performs the authorization, expiry, integrity, policy, and exact tool/argument revalidation before any approved execution. |

List routes validate bounded page sizes and return database errors as service-unavailable responses rather than success-shaped empty data. SQLite initializes reproducibly through `backend.database.init_db()`; additive SQLite/PostgreSQL migrations preserve older action rows while adding task linkage and explicit execution state. The browser dashboard's two localhost origins are the CORS defaults; override only with a comma-separated trusted-origin list in `AGENTGUARD_CORS_ORIGINS`.
