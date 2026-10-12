# AgentGuard deterministic rules and review enforcement

Every tool call enters `AgentGuard.execute`. It validates the explicit registry and arguments, applies mandatory deterministic rules, extracts current/past-only model features, obtains a validated risk score, writes a durable authorization event, then runs the function only for ALLOW. Unknown tools, traversal, sensitive resource attempts, credential exposure patterns, model failures, and invalid score/inference results are blocked independently of the ML classifier.

## Decisions

- **ALLOW (0–30):** only after deterministic validation, model inference, history access, and pre-execution JSONL/SQLite audit persistence all succeed.
- **REVIEW (31–70):** operation remains unexecuted. A pending approval is stored with the original action ID, tool, exact arguments, target, model score/version, creation time, and expiry (15 minutes by default).
- **BLOCK (71–100):** operation does not execute.
- **Fail-safe:** model loading, feature extraction, inference, history database, or pre-execution audit failures block the request. Thresholds are configurable using `AGENTGUARD_ALLOW_MAX` and `AGENTGUARD_REVIEW_MAX`.

Deterministic rules live in `security/rules.py`, separately from `ml/features.py` and the learned model. Hard blocks always win, even when a model would predict ALLOW. Each persisted event has a unique action ID shared by its JSONL and database entry. An `authorization_granted` record is required before an allowed function runs; the final event records its outcome.

## Human approval

Configure a strong secret outside source control as `AGENTGUARD_APPROVER_TOKEN`. Reviewers list pending operations with `GET /approvals/pending` and `X-Approver-Token`, then submit `POST /approvals/{approval_id}` with `{"decision":"approve|reject","approver_id":"..."}` and the same header.

Approval IDs bind the pending record to the action ID, tool, arguments, target, and expiry using a SHA-256 integrity digest. A constant-time shared-token comparison authorizes the reviewer. Approval claims use an atomic database state transition, so concurrent or duplicate requests cannot invoke the tool twice. Before an approved run, the guard checks integrity and expiry, revalidates the registry and deterministic rules, reloads history, and repeats model inference; a new BLOCK or any inference failure prevents execution. A human approval can release a still-REVIEW action, but never a hard rule or new BLOCK. Rejections, approvals, executions, and failures get separate linked audit events.

Without `AGENTGUARD_APPROVER_TOKEN`, approvals are unavailable. This local phase has no user directory, identity provider, or reviewer role management; any holder of the configured shared secret can act as an approver. A process crash after the atomic claim leaves an approval in `processing`; it cannot be executed a second time automatically and requires operator review.

## Dashboard boundary

The Next.js dashboard is a client for read-only monitoring and authenticated approval/settings requests. It does not run tools, select policy outcomes, or replace backend enforcement. FastAPI allows only the configured local dashboard CORS origins (`AGENTGUARD_CORS_ORIGINS`); keep this list limited to trusted origins. Approval and threshold mutation routes require the approver token, while thresholds submitted to `/settings` are range-checked by the backend. Runtime threshold updates are in-memory and reset on restart; configure environment thresholds for startup policy.
