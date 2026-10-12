from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TaskRecord(Base):
    __tablename__ = "tasks"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    task_text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), index=True)
    answer: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)


class ActionRecord(Base):
    __tablename__ = "actions"

    action_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    agent_id: Mapped[str] = mapped_column(String(100), index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    tool: Mapped[str] = mapped_column(String(100), index=True)
    arguments_json: Mapped[str] = mapped_column(Text)
    target_resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    result_summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), index=True)
    decision: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(Text)
    duration_ms: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    related_action_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.action_id", ondelete="CASCADE"), unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    decision: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(Text)


class PendingApproval(Base):
    __tablename__ = "pending_approvals"

    approval_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.action_id"), unique=True, index=True)
    tool: Mapped[str] = mapped_column(String(100))
    arguments_json: Mapped[str] = mapped_column(Text)
    argument_hash: Mapped[str] = mapped_column(String(64))
    target_resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_probability: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    approver_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
