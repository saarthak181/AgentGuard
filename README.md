# AgentGuard

AgentGuard is a local, tool-using Python agent with a FastAPI security backend and a Next.js dashboard. The agent can use only the registered `search_files`, `read_file`, and `calculator` tools. All tool requests pass through `AgentGuard`, deterministic mandatory rules, model-backed risk policy, human review where required, and append-only audit persistence before an allowed action is executed. Blocking remains entirely in the backend; the dashboard is an observer and reviewer client.

The behavioral model is a provisional synthetic-data model. Do not interpret its score or synthetic evaluation as calibrated or established real-world performance. Phase 4 does not add Claude Code, MCP, or Comet integrations.

## Architecture and API

- `agent/`: Ollama agent and constrained tool registry.
- `security/`: execution boundary, mandatory rules, risk decision, approval revalidation, and redacted JSONL logger.
- `ml/`: trace-aware synthetic data, training/evaluation, trusted model artifact loading, and policy thresholds.
- `backend/`: FastAPI routes and additive SQLAlchemy/SQLite persistence.
- `frontend/`: responsive Next.js/React/TypeScript security console with the existing dashboard and a task chat, persisted conversation selector, live task polling, action inspector, risk analytics, approval queue, model evaluation, and settings.

The API retains `/`, `/health`, `/actions`, `/stats`, `/approvals/pending`, and `POST /approvals/{approval_id}`. Chat submits tasks to `POST /tasks`, polls `GET /tasks/{task_id}`, loads per-task actions from `GET /tasks/{task_id}/actions`, and restores conversations with `GET /sessions/{session_id}/tasks`. `GET /agent/status` checks the configured Ollama model without generating a response. Task and action records are persisted in the same database used by the dashboard; each tool action is linked to both task and session IDs and executes through AgentGuard. The frontend polls persisted records, it does not invent agent activity. Dashboard data is read from `/events`, `/sessions`, `/sessions/{session_id}/actions`, and `/model`. Authorized policy threshold reads/updates use `/settings`; updates require `X-Approver-Token`. Local browser origins `http://localhost:3000` and `http://127.0.0.1:3000` are permitted by default. Configure additional exact origins with `AGENTGUARD_CORS_ORIGINS` (comma-separated).

Action and event list endpoints use bounded pagination. `/stats` includes the security incident count (blocked, failed, and review-required decisions); authorized pending approvals include the original explanation and recent session history. The API does not provide arbitrary SQL, filesystem access, or unrestricted configuration editing. Approval endpoints revalidate tool allowlisting, arguments, target integrity, expiration, and current model policy before execution; duplicate approval claims are atomically rejected.

Task prompts are limited to 4,000 characters and redacted before persistence. A conversation is a persisted list of tasks; prior task messages are not injected as model memory. Tasks requiring approval pause in `review_required`; approve/reject them in the existing Approvals page. After an approved tool executes, submit a follow-up task if the original request needs more agent steps. Task status and action analytics are derived from backend records. Task cancellation is not exposed because the current synchronous agent loop cannot safely cancel a tool call after authorization.

Threshold changes through `/settings` update the running process and reset when the backend restarts. For persistent defaults, set `AGENTGUARD_ALLOW_MAX` and `AGENTGUARD_REVIEW_MAX` before starting FastAPI. Thresholds must satisfy `0 <= allow_max < review_max <= 100`.

## Setup and startup (Windows PowerShell)

Prerequisites: Python 3.12+, Node.js 20.9+, npm, and Ollama. Run commands from the repository root unless the block says `frontend`.

```powershell
# Python environment and backend/agent dependencies
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Prepare local data, initialize SQLite, and train/evaluate the model
New-Item -ItemType Directory -Force data | Out-Null
$env:AGENTGUARD_DATABASE_URL = "sqlite:///./data/agentguard.db"
python -c "from backend.database import init_db; init_db()"
python -m ml.dataset --seed 2026 --output ml/data/synthetic_traces.jsonl
python -m ml.pipeline train --dataset ml/data/synthetic_traces.jsonl --artifact-dir ml/artifacts --seed 2026 --test-size 0.25
python -m ml.pipeline evaluate --artifact-dir ml/artifacts
python -m ml.pipeline inspect --artifact-dir ml/artifacts

# Optional real Ollama-backed agent run (start Ollama and pull the model first)
ollama pull llama3.2:3b
python main.py "Find the sales report, read it, calculate the total sales, and tell me the best region."
```

Start the backend in a PowerShell terminal:

```powershell
.\.venv\Scripts\Activate.ps1
$env:AGENTGUARD_DATABASE_URL = "sqlite:///./data/agentguard.db"
python -c "from backend.database import init_db; init_db()"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```powershell
Set-Location frontend
npm ci
npm run dev -- --hostname 127.0.0.1
```

Open `http://127.0.0.1:3000`, choose **Chat**, enter a task, and press Enter (Shift+Enter inserts a newline). FastAPI docs are at `http://127.0.0.1:8000/docs`. The dashboard refreshes data every 15 seconds. Use Settings to change the backend URL. Approval and threshold mutations require the backend's `AGENTGUARD_APPROVER_TOKEN`, entered in the UI for the current browser session. Set it in the backend terminal before startup; never put it in source code or a URL.

Use `AGENTGUARD_DATABASE_URL` to configure a different SQLAlchemy database URL. SQLite is the default. Set `AGENTGUARD_MODEL_PATH` for a trusted alternate model artifact. Documents belong in `data\document\`; supported text extensions are `.txt`, `.md`, `.csv`, `.json`, and `.log`, with a 1 MB file limit. `read_file` rejects traversal and resolved paths outside that directory.

## Tests and quality checks

```powershell
# Full backend, ML, agent, database, API, and integration regressions
python -m pytest -q

# Frontend (from frontend\)
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

Python tests use temporary directories and SQLite databases and mock model/LLM calls in the core suite. The sales report acceptance workflow also runs through the task API and existing guard, reads the report file, calculates **66000**, and returns **North India**; no live Ollama service is required by the automated tests. Frontend tests cover chat submission, persisted task analytics/actions, errors, dashboard loading states, API errors/redaction, live metric display, search/filter/pagination, and both approve/reject request flows.

## Model evaluation

The checked-in artifact selected Random Forest on validation F1. On the held-out synthetic evaluation partition (728 events, 120 traces), the report records precision **0.8421**, recall **0.9624**, F1 **0.8982**, false-positive rate **0.0403**, and PR-AUC **0.9753**. The dashboard reads these values and per-attack-family support/metrics from the evaluation report and labels the evaluation synthetic. These metrics do not establish production detection performance. Missing or incompatible model artifacts are shown as unavailable, and the backend guard follows its fail-closed policy.

## Security and operational notes

- JSONL audit records append at `logs/agent_actions.jsonl` and share their action IDs with SQLite records. Credentials are redacted before persistence; failed persistence is reported and does not claim success.
- Approval credentials are held in `sessionStorage` by the browser UI. The dashboard never performs tool execution itself.
- The settings page exposes only validated allow/review thresholds. Dynamic changes last for the current backend process; use environment values for startup defaults.
- If health is degraded, inspect the `model` object; if it returns 503, check database configuration and filesystem permissions.
- `frontend/scripts/next.mjs` prefers native SWC and falls back to the matching SWC WASM package when the host cannot load its native binary. WASM builds are slower; `npm run dev` and `npm run build` both use this fallback automatically.
