from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .database import create_task, get_db, list_pending_approvals, ping, update_task
from .models import ActionRecord, PendingApproval, SecurityEvent, TaskRecord
from .schemas import (ActionOut, ActionsPage, ApprovalRequest, ApprovalResult, SettingsUpdate,
                      StatsOut, TaskAnalytics, TaskDetail, TaskOut, TaskSecurityEvent, TaskSubmit)
from agent.agent import Agent
from agent.tools import TOOL_REGISTRY
from security.guard import AgentGuard
from security.logger import redact

app = FastAPI(title="AgentGuard API", version="3.0.0", description="Local agent security, audit, behavioral risk, and human review API.")
runtime_guard = AgentGuard(TOOL_REGISTRY)


def _task_out(row: TaskRecord) -> TaskOut:
    return TaskOut(task_id=row.task_id, session_id=row.session_id, task=row.task_text,
                   status=row.status, answer=row.answer, error=row.error,
                   created_at=row.created_at, updated_at=row.updated_at, duration_ms=row.duration_ms)


def _execute_task(task_id: str, session_id: str, task: str) -> None:
    started = time.perf_counter()
    try:
        update_task(task_id, status="running", now=datetime.now(timezone.utc))
        guard = AgentGuard(TOOL_REGISTRY, session_id=session_id, task_id=task_id,
                           predictor=runtime_guard.predictor, thresholds=runtime_guard.thresholds)
        agent = Agent(model=os.getenv("AGENTGUARD_MODEL", "llama3.2:3b"),
                      max_steps=int(os.getenv("AGENTGUARD_MAX_STEPS", "8")),
                      timeout=float(os.getenv("AGENTGUARD_LLM_TIMEOUT", "60")), guard=guard)
        result = agent.run(task)
        tool_failures = [call for call in result.tool_calls
                         if call.get("execution", {}).get("status") == "failed"]
        review_pending = any(call.get("execution", {}).get("status") == "review_required"
                             for call in result.tool_calls)
        success = result.completed and not tool_failures and not review_pending and all(
            call.get("execution", {}).get("audit_persisted", False) for call in result.tool_calls)
        status = "completed" if success else "review_required" if review_pending else "failed"
        update_task(task_id, status=status, now=datetime.now(timezone.utc),
                    answer=redact(result.answer),
                    error=None if success or review_pending else "Agent did not complete successfully; inspect action decisions and errors.",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3))
    except Exception as exc:
        safe_error = str(redact(str(exc)))[:1000]
        try:
            update_task(task_id, status="failed", now=datetime.now(timezone.utc), error=safe_error,
                        duration_ms=round((time.perf_counter() - started) * 1000, 3))
        except Exception:
            # The original row remains queued/running and will not be presented as completed.
            pass


def _task_detail(db: Session, row: TaskRecord) -> TaskDetail:
    records = db.scalars(select(ActionRecord).where(ActionRecord.task_id == row.task_id,
                                                    ActionRecord.status != "authorization_granted")
                         .order_by(ActionRecord.timestamp, ActionRecord.action_id)).all()
    scores = [item.risk_score for item in records if item.risk_score is not None]
    analytics = TaskAnalytics(total_actions=len(records),
        allowed=sum(item.status == "allowed" for item in records),
        blocked=sum(item.status == "blocked" for item in records),
        review_required=sum(item.status == "review_required" for item in records),
        failed=sum(item.status == "failed" for item in records),
        highest_risk_score=max(scores) if scores else None,
        average_risk_score=round(sum(scores) / len(scores), 2) if scores else None,
        tools_used=list(dict.fromkeys(item.tool for item in records if item.tool != "approval")))
    actions_out = [ActionOut(action_id=item.action_id, timestamp=item.timestamp, agent_id=item.agent_id,
        session_id=item.session_id, task_id=item.task_id, executed=item.executed, tool=item.tool, arguments=json.loads(item.arguments_json),
        target_resource=item.target_resource, result_summary=item.result_summary, status=item.status,
        decision=item.decision, reason=item.reason, duration_ms=item.duration_ms,
        risk_score=item.risk_score, risk_probability=item.risk_probability, model_version=item.model_version,
        related_action_id=item.related_action_id, approval_id=item.approval_id) for item in records]
    event_rows = db.execute(select(SecurityEvent, ActionRecord).join(
        ActionRecord, SecurityEvent.action_id == ActionRecord.action_id).where(
            ActionRecord.task_id == row.task_id, ActionRecord.status != "authorization_granted")
        .order_by(ActionRecord.timestamp, SecurityEvent.event_id)).all()
    security_events = [TaskSecurityEvent(event_id=event.event_id, action_id=event.action_id,
        event_type=event.event_type, decision=event.decision, reason=event.reason,
        timestamp=action.timestamp, tool=action.tool, risk_score=action.risk_score)
        for event, action in event_rows]
    return TaskDetail(**_task_out(row).model_dump(), analytics=analytics, actions=actions_out,
                      security_events=security_events)
_frontend_origins = [origin.strip() for origin in os.getenv(
    "AGENTGUARD_CORS_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000"
).split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_frontend_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "OPTIONS"],
                   allow_headers=["Content-Type", "X-Approver-Token"])


@app.get("/")
def root():
    return {"name": "AgentGuard", "version": "2.0.0", "docs": "/docs"}


@app.get("/health")
def health():
    try:
        ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    model = runtime_guard.model_status
    return {"status": "ok" if model["status"] == "ready" else "degraded",
            "database": "ok", "model": model}


@app.get("/agent/status")
def agent_status():
    model_name = os.getenv("AGENTGUARD_MODEL", "llama3.2:3b")
    try:
        import ollama
        ollama.Client(timeout=2).show(model_name)
        return {"status": "ready", "provider": "ollama", "model": model_name}
    except ImportError:
        return {"status": "unavailable", "provider": "ollama", "model": model_name,
                "error": "Ollama Python package is not installed."}
    except Exception:
        return {"status": "unavailable", "provider": "ollama", "model": model_name,
                "error": "Ollama is unreachable or the configured model is unavailable."}


@app.post("/tasks", response_model=TaskOut, status_code=202)
def submit_task(request: TaskSubmit, background: BackgroundTasks):
    task_id = str(uuid4())
    session_id = request.session_id or str(uuid4())
    now = datetime.now(timezone.utc)
    stored_task = redact(request.task)
    try:
        create_task(task_id, session_id, stored_task, now)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="task could not be persisted") from exc
    background.add_task(_execute_task, task_id, session_id, request.task)
    return TaskOut(task_id=task_id, session_id=session_id, task=stored_task, status="queued",
                   created_at=now, updated_at=now)


@app.get("/tasks/{task_id}", response_model=TaskDetail)
def get_task(task_id: str, db: Session = Depends(get_db)):
    row = db.get(TaskRecord, task_id)
    if row is None:
        raise HTTPException(status_code=404, detail="task not found")
    try:
        return _task_detail(db, row)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="task history unavailable") from exc


@app.get("/tasks/{task_id}/actions", response_model=ActionsPage)
def task_actions(task_id: str, limit: int = Query(50, ge=1, le=200),
                 offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    if db.get(TaskRecord, task_id) is None:
        raise HTTPException(status_code=404, detail="task not found")
    try:
        query = select(ActionRecord).where(ActionRecord.task_id == task_id,
                                           ActionRecord.status != "authorization_granted")
        total = db.scalar(select(func.count()).select_from(ActionRecord).where(
            ActionRecord.task_id == task_id, ActionRecord.status != "authorization_granted")) or 0
        rows = db.scalars(query.order_by(ActionRecord.timestamp, ActionRecord.action_id).offset(offset).limit(limit)).all()
        items = [ActionOut(action_id=r.action_id, timestamp=r.timestamp, agent_id=r.agent_id,
            session_id=r.session_id, task_id=r.task_id, executed=r.executed, tool=r.tool, arguments=json.loads(r.arguments_json),
            target_resource=r.target_resource, result_summary=r.result_summary, status=r.status,
            decision=r.decision, reason=r.reason, duration_ms=r.duration_ms, risk_score=r.risk_score,
            risk_probability=r.risk_probability, model_version=r.model_version,
            related_action_id=r.related_action_id, approval_id=r.approval_id) for r in rows]
        return ActionsPage(items=items, total=total, limit=limit, offset=offset)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="task actions unavailable") from exc


@app.get("/sessions/{session_id}/tasks", response_model=list[TaskOut])
def session_tasks(session_id: str, limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    try:
        rows = db.scalars(select(TaskRecord).where(TaskRecord.session_id == session_id)
                          .order_by(TaskRecord.created_at.desc()).limit(limit)).all()
        return [_task_out(row) for row in rows]
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="session task history unavailable") from exc


@app.get("/actions", response_model=ActionsPage)
def actions(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
            status: str | None = Query(None, pattern="^(allowed|blocked|failed|review_required|authorization_granted)$"),
            tool: str | None = Query(None, min_length=1, max_length=100),
            task_id: str | None = Query(None, min_length=1, max_length=36),
            db: Session = Depends(get_db)):
    try:
        query = select(ActionRecord).where(ActionRecord.status != "authorization_granted")
        count_query = select(func.count()).select_from(ActionRecord).where(ActionRecord.status != "authorization_granted")
        if status:
            query, count_query = query.where(ActionRecord.status == status), count_query.where(ActionRecord.status == status)
        if tool:
            query, count_query = query.where(ActionRecord.tool == tool), count_query.where(ActionRecord.tool == tool)
        if task_id:
            query, count_query = query.where(ActionRecord.task_id == task_id), count_query.where(ActionRecord.task_id == task_id)
        total = db.scalar(count_query) or 0
        records = db.scalars(query.order_by(ActionRecord.timestamp.desc(), ActionRecord.action_id).offset(offset).limit(limit)).all()
        items = []
        for item in records:
            items.append(ActionOut(action_id=item.action_id, timestamp=item.timestamp, agent_id=item.agent_id,
                                   session_id=item.session_id, task_id=item.task_id, executed=item.executed, tool=item.tool, arguments=json.loads(item.arguments_json),
                                   target_resource=item.target_resource, result_summary=item.result_summary,
                                   status=item.status, decision=item.decision, reason=item.reason, duration_ms=item.duration_ms,
                                   risk_score=item.risk_score, risk_probability=item.risk_probability,
                                   model_version=item.model_version, related_action_id=item.related_action_id,
                                   approval_id=item.approval_id))
        return ActionsPage(items=items, total=total, limit=limit, offset=offset)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="action records unavailable") from exc


@app.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    try:
        counts = dict(db.execute(select(ActionRecord.status, func.count()).where(
            ActionRecord.status != "authorization_granted"
        ).group_by(ActionRecord.status)).all())
        return StatsOut(total_actions=sum(counts.values()), allowed=counts.get("allowed", 0),
                        blocked=counts.get("blocked", 0), failed=counts.get("failed", 0),
                        review_required=counts.get("review_required", 0),
                        security_incidents=counts.get("blocked", 0) + counts.get("failed", 0) + counts.get("review_required", 0))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="statistics unavailable") from exc


@app.get("/events")
def events(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
           event_type: str | None = Query(None, min_length=1, max_length=40), db: Session = Depends(get_db)):
    try:
        query = select(SecurityEvent, ActionRecord).join(ActionRecord, SecurityEvent.action_id == ActionRecord.action_id).where(ActionRecord.status != "authorization_granted")
        count_query = select(func.count()).select_from(SecurityEvent).join(ActionRecord, SecurityEvent.action_id == ActionRecord.action_id).where(ActionRecord.status != "authorization_granted")
        if event_type:
            query, count_query = query.where(SecurityEvent.event_type == event_type), count_query.where(SecurityEvent.event_type == event_type)
        total = db.scalar(count_query) or 0
        rows = db.execute(query.order_by(ActionRecord.timestamp.desc()).offset(offset).limit(limit)).all()
        return {"items": [{"event_id": event.event_id, "action_id": event.action_id, "event_type": event.event_type,
                            "decision": event.decision, "reason": event.reason, "timestamp": action.timestamp,
                            "tool": action.tool, "session_id": action.session_id, "risk_score": action.risk_score,
                            "status": action.status} for event, action in rows], "total": total, "limit": limit, "offset": offset}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="security events unavailable") from exc


@app.get("/sessions")
def sessions(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    try:
        rows = db.execute(select(ActionRecord.session_id, func.count().label("action_count"),
                                 func.max(ActionRecord.timestamp).label("last_seen"))
                          .where(ActionRecord.status != "authorization_granted")
                          .group_by(ActionRecord.session_id).order_by(func.max(ActionRecord.timestamp).desc()).limit(limit)).all()
        return {"items": [{"session_id": row.session_id, "action_count": row.action_count, "last_seen": row.last_seen} for row in rows]}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="sessions unavailable") from exc


@app.get("/sessions/{session_id}/actions", response_model=ActionsPage)
def session_actions(session_id: str, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    try:
        query = select(ActionRecord).where(ActionRecord.session_id == session_id, ActionRecord.status != "authorization_granted")
        total = db.scalar(select(func.count()).select_from(ActionRecord).where(
            ActionRecord.session_id == session_id, ActionRecord.status != "authorization_granted")) or 0
        records = db.scalars(query.order_by(ActionRecord.timestamp, ActionRecord.action_id).offset(offset).limit(limit)).all()
        return ActionsPage(items=[ActionOut(action_id=r.action_id, timestamp=r.timestamp, agent_id=r.agent_id,
            session_id=r.session_id, task_id=r.task_id, executed=r.executed, tool=r.tool, arguments=json.loads(r.arguments_json), target_resource=r.target_resource,
            result_summary=r.result_summary, status=r.status, decision=r.decision, reason=r.reason, duration_ms=r.duration_ms,
            risk_score=r.risk_score, risk_probability=r.risk_probability, model_version=r.model_version,
            related_action_id=r.related_action_id, approval_id=r.approval_id) for r in records], total=total, limit=limit, offset=offset)
    except (SQLAlchemyError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="session actions unavailable") from exc


@app.get("/model")
def model_info():
    from pathlib import Path
    try:
        report = json.loads((Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "evaluation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report = None
    status = runtime_guard.model_status
    return {"status": status["status"], "model_version": status.get("model_version"),
            "selected_model": status.get("selected_model"), "error": status.get("error"),
            "metadata": report.get("metadata") if report else None,
            "metrics": report.get("metrics", {}).get(report.get("selected_model")) if report else None,
            "per_attack_family": report.get("per_attack_family") if report else None,
            "warning": report.get("warning") if report else None}


@app.get("/settings")
def get_settings():
    return {"allow_max": runtime_guard.thresholds.allow_max, "review_max": runtime_guard.thresholds.review_max}


@app.put("/settings")
def update_settings(request: SettingsUpdate, approver_token: str | None = Header(None, alias="X-Approver-Token")):
    if not runtime_guard.authorized(approver_token):
        raise HTTPException(status_code=401, detail="authorized approver credentials required")
    if not request.valid_order:
        raise HTTPException(status_code=422, detail="allow_max must be less than review_max")
    from ml.policy import RiskThresholds
    runtime_guard.thresholds = RiskThresholds(request.allow_max, request.review_max)
    return {"allow_max": runtime_guard.thresholds.allow_max, "review_max": runtime_guard.thresholds.review_max}


@app.get("/approvals/pending")
def pending_approvals(limit: int = Query(50, ge=1, le=200),
                      approver_token: str | None = Header(None, alias="X-Approver-Token"),
                      db: Session = Depends(get_db)):
    if not runtime_guard.authorized(approver_token):
        raise HTTPException(status_code=401, detail="authorized approver credentials required")
    try:
        items = list_pending_approvals(limit)
        for item in items:
            action = db.get(ActionRecord, item["action_id"])
            item["session_id"] = action.session_id if action else None
            item["reason"] = action.reason if action else "Original action record unavailable"
            history = []
            if action:
                prior = db.scalars(select(ActionRecord).where(
                    ActionRecord.session_id == action.session_id,
                    ActionRecord.status != "authorization_granted",
                    ActionRecord.action_id != action.action_id,
                ).order_by(ActionRecord.timestamp.desc()).limit(5)).all()
                history = [{"action_id": row.action_id, "timestamp": row.timestamp, "tool": row.tool,
                            "status": row.status, "reason": row.reason} for row in reversed(prior)]
            item["history"] = history
        return {"items": items}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="pending approvals unavailable") from exc


@app.post("/approvals/{approval_id}", response_model=ApprovalResult)
def resolve_approval(approval_id: str, request: ApprovalRequest,
                     approver_token: str | None = Header(None, alias="X-Approver-Token"),
                     db: Session = Depends(get_db)):
    pending = db.get(PendingApproval, approval_id)
    result = runtime_guard.resolve_approval(approval_id, request.decision, request.approver_id, approver_token)
    if result.get("status") == "allowed" and not result.get("audit_persisted"):
        result["status"] = "failed"
        result["error"] = "Approved action executed, but its completion audit could not be persisted."
    if pending is not None and result["status"] not in {"unauthorized", "not_found", "already_resolved"}:
        original = db.get(ActionRecord, pending.action_id)
        if original and original.task_id:
            if result["status"] == "allowed" and result.get("audit_persisted"):
                update_task(original.task_id, status="approval_resolved", now=datetime.now(timezone.utc),
                            answer="Reviewed action was approved and executed. Submit a follow-up task to continue.",
                            error=None)
            elif result["status"] == "rejected":
                update_task(original.task_id, status="rejected", now=datetime.now(timezone.utc),
                            answer="The reviewer rejected the pending action.", error="Action rejected by reviewer.")
            elif result["status"] in {"blocked", "expired", "failed"}:
                update_task(original.task_id, status=result["status"], now=datetime.now(timezone.utc),
                            error=str(redact(result.get("error") or result["status"])))
    if result["status"] == "unauthorized":
        raise HTTPException(status_code=401, detail=result.get("error"))
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail=result.get("error"))
    if result["status"] in {"already_resolved", "expired", "blocked", "failed"}:
        raise HTTPException(status_code=409, detail=result.get("error") or result["status"])
    return {**result, "approval_id": approval_id}
