"""SQLite persistence. Configure with a new URL before app use for isolated tests."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from sqlalchemy import create_engine, event, inspect, select, update
from sqlalchemy.orm import Session, sessionmaker

from .models import ActionRecord, Base, PendingApproval, SecurityEvent, TaskRecord

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "agentguard.db"
_lock = RLock()
_engine = None
_SessionLocal = None


def _make_engine(url: str):
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, future=True)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _foreign_keys(connection, _record):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


def configure_database(url: str | None = None) -> None:
    global _engine, _SessionLocal
    if url is None:
        url = os.getenv("AGENTGUARD_DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")
    with _lock:
        old = _engine
        _engine = _make_engine(url)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
        if old is not None:
            old.dispose()


def init_db() -> None:
    if _engine is None:
        configure_database()
    Base.metadata.create_all(_engine)
    # Additive SQLite migration for Phase 2 databases; existing actions are kept intact.
    if _engine.dialect.name in {"sqlite", "postgresql"}:
        columns = {item["name"] for item in inspect(_engine).get_columns("actions")}
        additions = {"risk_score": "INTEGER", "risk_probability": "FLOAT", "model_version": "VARCHAR(100)", "assessment_json": "TEXT", "task_id": "VARCHAR(36)",
                     "executed": "BOOLEAN NOT NULL DEFAULT FALSE",
                     "related_action_id": "VARCHAR(36)", "approval_id": "VARCHAR(36)"}
        with _engine.begin() as connection:
            for column, sql_type in additions.items():
                if column not in columns:
                    connection.exec_driver_sql(f"ALTER TABLE actions ADD COLUMN {column} {sql_type}")
            connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_actions_task_id ON actions (task_id)")


def get_session() -> Session:
    if _SessionLocal is None:
        configure_database()
    return _SessionLocal()


def get_db():
    init_db()
    db = get_session()
    try:
        yield db
    finally:
        db.close()


def persist_action(entry: dict[str, Any]) -> None:
    """Store audit data and its security event atomically using the JSONL action id."""
    init_db()
    session = get_session()
    try:
        timestamp = datetime.fromisoformat(entry["timestamp"])
        action = ActionRecord(
            action_id=entry["action_id"], timestamp=timestamp,
            agent_id=entry["agent_id"], session_id=entry["session_id"],
            task_id=entry.get("task_id"),
            tool=entry["tool"], arguments_json=json.dumps(entry["arguments"], ensure_ascii=False),
            executed=bool(entry.get("executed", False)),
            target_resource=str(entry["target_resource"])[:512] if entry.get("target_resource") is not None else None,
            result_summary=str(entry["result_summary"]), status=entry["status"],
            decision=entry["decision"], reason=entry["reason"], duration_ms=entry["duration_ms"],
            risk_score=entry.get("risk_score"), risk_probability=entry.get("risk_probability"),
            model_version=entry.get("model_version"), assessment_json=json.dumps(entry.get("assessment"), ensure_ascii=False) if entry.get("assessment") is not None else None, related_action_id=entry.get("related_action_id"),
            approval_id=entry.get("approval_id"),
        )
        session.add(action)
        session.flush()
        session.add(SecurityEvent(action_id=entry["action_id"], event_type=entry["status"],
                                  decision=entry["decision"], reason=entry["reason"]))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def recent_actions(session_id: str, limit: int = 20) -> list[dict[str, Any]]:
    init_db()
    session = get_session()
    try:
        rows = session.scalars(select(ActionRecord).where(
            ActionRecord.session_id == session_id,
            ActionRecord.status != "authorization_granted",
            ActionRecord.tool != "approval",
        )
                               .order_by(ActionRecord.timestamp.desc()).limit(limit)).all()
        return [{"tool": row.tool, "arguments": json.loads(row.arguments_json),
                 "target_resource": row.target_resource, "status": row.status} for row in reversed(rows)]
    finally:
        session.close()


def get_action_task_id(action_id: str) -> str | None:
    init_db()
    session = get_session()
    try:
        item = session.get(ActionRecord, action_id)
        return item.task_id if item else None
    finally:
        session.close()


def create_pending_approval(entry: dict[str, Any]) -> None:
    init_db()
    session = get_session()
    try:
        session.add(PendingApproval(**entry))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_pending_approval(approval_id: str) -> dict[str, Any] | None:
    init_db()
    session = get_session()
    try:
        item = session.get(PendingApproval, approval_id)
        return _pending_dict(item) if item else None
    finally:
        session.close()


def claim_pending_approval(approval_id: str, now: datetime) -> dict[str, Any] | None:
    """Atomic compare-and-set prevents duplicate concurrent review execution."""
    init_db()
    session = get_session()
    try:
        result = session.execute(update(PendingApproval).where(
            PendingApproval.approval_id == approval_id, PendingApproval.status == "pending",
            PendingApproval.expires_at > now,
        ).values(status="processing"))
        session.commit()
        if result.rowcount != 1:
            return None
        item = session.get(PendingApproval, approval_id)
        return _pending_dict(item) if item else None
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def finish_pending_approval(approval_id: str, status: str, approver_id: str) -> None:
    init_db()
    session = get_session()
    try:
        session.execute(update(PendingApproval).where(
            PendingApproval.approval_id == approval_id, PendingApproval.status == "processing"
        ).values(status=status, approver_id=approver_id, completed_at=datetime.now(timezone.utc)))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def expire_pending_approval(approval_id: str) -> None:
    init_db()
    session = get_session()
    try:
        session.execute(update(PendingApproval).where(
            PendingApproval.approval_id == approval_id, PendingApproval.status == "pending"
        ).values(status="expired", completed_at=datetime.now(timezone.utc)))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def list_pending_approvals(limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    session = get_session()
    try:
        rows = session.scalars(select(PendingApproval).where(PendingApproval.status == "pending")
                               .order_by(PendingApproval.created_at).limit(limit)).all()
        return [_pending_dict(item) for item in rows]
    finally:
        session.close()


def _pending_dict(item: PendingApproval) -> dict[str, Any]:
    created_at = item.created_at.replace(tzinfo=timezone.utc) if item.created_at.tzinfo is None else item.created_at
    expires_at = item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at
    return {"approval_id": item.approval_id, "action_id": item.action_id, "tool": item.tool,
            "arguments": json.loads(item.arguments_json), "argument_hash": item.argument_hash,
            "target_resource": item.target_resource, "risk_score": item.risk_score,
            "risk_probability": item.risk_probability, "model_version": item.model_version,
            "created_at": created_at, "expires_at": expires_at, "status": item.status,
            "approver_id": item.approver_id}


def ping() -> None:
    init_db()
    with _engine.connect() as connection:
        connection.exec_driver_sql("SELECT 1")


def create_task(task_id: str, session_id: str, task_text: str, now: datetime) -> None:
    init_db()
    session = get_session()
    try:
        session.add(TaskRecord(task_id=task_id, session_id=session_id, task_text=task_text,
                               status="queued", created_at=now, updated_at=now))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def update_task(task_id: str, *, status: str, now: datetime, answer: str | None = None,
                error: str | None = None, duration_ms: float | None = None) -> None:
    init_db()
    session = get_session()
    try:
        item = session.get(TaskRecord, task_id)
        if item is None:
            raise LookupError("task not found")
        item.status, item.updated_at = status, now
        if answer is not None:
            item.answer = answer
        if error is not None:
            item.error = error
        if duration_ms is not None:
            item.duration_ms = duration_ms
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
