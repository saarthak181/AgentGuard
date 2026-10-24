from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    action_id: str
    timestamp: datetime
    agent_id: str
    session_id: str
    task_id: str | None = None
    executed: bool = False
    tool: str
    arguments: dict
    target_resource: str | None
    result_summary: str
    status: str
    decision: str
    reason: str
    duration_ms: float
    risk_score: int | None = None
    risk_probability: float | None = None
    model_version: str | None = None
    assessment: dict | None = None
    related_action_id: str | None = None
    approval_id: str | None = None


class TaskSubmit(BaseModel):
    task: str = Field(min_length=1, max_length=4000)
    session_id: str | None = Field(default=None, min_length=1, max_length=100)

    @field_validator("task")
    @classmethod
    def non_blank_task(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("task must not be blank")
        return value


class TaskAnalytics(BaseModel):
    total_actions: int
    allowed: int
    blocked: int
    review_required: int
    failed: int
    highest_risk_score: int | None
    average_risk_score: float | None
    tools_used: list[str]


class TaskSecurityEvent(BaseModel):
    event_id: int
    action_id: str
    event_type: str
    decision: str
    reason: str
    timestamp: datetime
    tool: str
    risk_score: int | None


class TaskOut(BaseModel):
    task_id: str
    session_id: str
    task: str
    status: str
    answer: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
    duration_ms: float | None = None


class TaskDetail(TaskOut):
    analytics: TaskAnalytics
    actions: list[ActionOut]
    security_events: list[TaskSecurityEvent]


class ActionsPage(BaseModel):
    items: list[ActionOut]
    total: int
    limit: int
    offset: int


class StatsOut(BaseModel):
    total_actions: int
    allowed: int
    blocked: int
    failed: int
    review_required: int
    security_incidents: int = 0


class ApprovalRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    approver_id: str = Field(min_length=1, max_length=100)


class ApprovalResult(BaseModel):
    status: str
    executed: bool
    error: str | None = None
    approval_id: str | None = None
    action_id: str | None = None
    execution_action_id: str | None = None
    audit_persisted: bool | None = None


class SettingsUpdate(BaseModel):
    allow_max: int = Field(ge=0, le=99)
    review_max: int = Field(ge=1, le=100)

    @property
    def valid_order(self) -> bool:
        return self.allow_max < self.review_max
