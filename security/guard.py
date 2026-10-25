"""Mandatory deterministic checks, behavioral scoring, and tool execution boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping
from uuid import uuid4

from ml.policy import RiskThresholds
from ml.predictor import RiskPredictor, RiskUnavailable
from .logger import AuditLogError, AuditLogger
from .rules import mandatory_denial
from .risk import POLICY_VERSION, assess


@dataclass
class ExecutionResult:
    action_id: str
    tool: str
    status: str
    decision: str
    reason: str
    result: Any
    duration_ms: float
    audit_persisted: bool
    error: str | None = None
    risk_score: int | None = None
    risk_probability: float | None = None
    model_version: str | None = None
    approval_id: str | None = None
    executed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentGuard:
    """All tool requests cross deterministic policy and model-derived risk checks."""

    def __init__(self, tools: Mapping[str, Any], logger: AuditLogger | None = None,
                 agent_id: str = "agentguard", session_id: str | None = None,
                 predictor: Any | None = None, thresholds: RiskThresholds | None = None,
                 approval_ttl_seconds: int = 900, approver_token: str | None = None,
                 task_id: str | None = None):
        self.tools = dict(tools)
        if logger is None:
            from backend.database import persist_action
            logger = AuditLogger(persist=persist_action)
        self.logger = logger
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid4())
        self.task_id = task_id
        self.predictor = predictor or RiskPredictor(os.getenv("AGENTGUARD_MODEL_PATH") or None)
        self.thresholds = thresholds or RiskThresholds.from_env()
        self.approval_ttl_seconds = max(1, int(approval_ttl_seconds))
        self.approver_token = approver_token
        self._history: list[dict[str, Any]] = []

    @property
    def model_status(self) -> dict[str, Any]:
        return self.predictor.status()

    def authorized(self, approver_token: str | None) -> bool:
        expected = self.approver_token if self.approver_token is not None else os.getenv("AGENTGUARD_APPROVER_TOKEN")
        return bool(expected and approver_token and hmac.compare_digest(expected, approver_token))

    def execute(self, tool: str, arguments: Any, forced_block_reason: str | None = None) -> ExecutionResult:
        action_id = str(uuid4())
        started = time.perf_counter()
        spec, error, reason = self._validate(tool, arguments, forced_block_reason)
        target = self._target(arguments)
        risk = None
        history: list[dict[str, Any]] = []
        if not error:
            try:
                history = self._history_snapshot()
                risk = self.predictor.predict({"tool": tool, "arguments": arguments, "target_resource": target}, history)
            except Exception as exc:
                error = f"risk model unavailable; action blocked by fail-safe policy: {exc}"
                reason = "risk assessment failed; fail-closed block"

        if error:
            return self._finish(action_id, tool, arguments, target, "blocked", "block", reason or error,
                                None, started, error=error, risk=risk)

        assessment = assess(tool, spec, arguments, history, risk)
        assessment.update(raw_ml_probability=risk.get("raw_ml_probability", risk.get("probability")),
                          calibrated_ml_probability=risk.get("calibrated_ml_probability"))
        score = assessment["final_risk_score"]
        # Persist the authoritative hybrid indicator separately. risk_probability
        # remains a deprecated compatibility alias for the ML probability only.
        risk = {**risk, "risk_score": score, "assessment": assessment}
        behavioral_decision = self.thresholds.classify(score)
        inherent_decision = str(spec.get("minimum_decision", "ALLOW")).upper()
        if inherent_decision not in {"ALLOW", "REVIEW", "BLOCK"}:
            return self._finish(action_id, tool, arguments, target, "blocked", "block",
                                "tool policy metadata is invalid", None, started,
                                error="tool policy metadata is invalid", risk=risk)
        decision = max((behavioral_decision, inherent_decision), key=lambda item: {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[item])
        if decision == "BLOCK":
            reason = ("inherent tool policy prohibits this action" if inherent_decision == "BLOCK"
                      else f"hybrid risk score {score}/100 exceeds the block threshold")
            return self._finish(action_id, tool, arguments, target, "blocked", "block", reason,
                                None, started, error=reason, risk=risk)
        if decision == "REVIEW":
            approval_id = str(uuid4())
            expires = datetime.now(timezone.utc) + timedelta(seconds=self.approval_ttl_seconds)
            review_reason = ("inherent side-effect policy requires human approval; "
                             f"hybrid risk score is {score}/100"
                             if inherent_decision == "REVIEW" and behavioral_decision == "ALLOW"
                             else f"hybrid risk score {score}/100 requires human approval")
            logged = self._record(action_id, tool, arguments, target, "review_required", "review",
                                  review_reason, {"approval_id": approval_id, "expires_at": expires.isoformat()},
                                  started, risk=risk)
            if not logged[0]:
                return self._result(action_id, tool, "blocked", "block", "review could not be durably audited",
                                    None, started, logged[1], "approval was not created because audit persistence failed", risk)
            try:
                from backend.database import create_pending_approval
                create_pending_approval({
                    "approval_id": approval_id, "action_id": action_id, "tool": tool,
                    "arguments_json": json.dumps(arguments, ensure_ascii=False, sort_keys=True),
                    "argument_hash": _approval_hash(action_id, tool, arguments, target, expires,
                                                     self._requester_identity(), POLICY_VERSION),
                    "requester_identity": self._requester_identity(), "policy_version": POLICY_VERSION,
                    "target_resource": str(target)[:512] if target is not None else None,
                    "risk_score": score, "risk_probability": risk["probability"],
                    "model_version": risk["model_version"], "created_at": datetime.now(timezone.utc),
                    "expires_at": expires, "status": "pending", "approver_id": None, "completed_at": None,
                })
            except Exception as exc:
                error = f"pending approval could not be stored; action remains unexecuted: {exc}"
                self._record(str(uuid4()), tool, arguments, target, "failed", "block", error, None, started,
                             risk=risk, related_action_id=action_id)
                return self._result(action_id, tool, "blocked", "block", error, None, started, False, error, risk)
            self._remember(tool, arguments, target, "review_required", action_id)
            return self._result(action_id, tool, "review_required", "review", review_reason,
                                {"approval_id": approval_id, "expires_at": expires.isoformat()}, started,
                                True, "human approval required", risk, approval_id)

        authorization_id = str(uuid4())
        authorized = self._record(authorization_id, tool, arguments, target, "authorization_granted", "allow",
                                 "risk policy allowed; execution is about to begin", None, started, risk=risk,
                                 related_action_id=action_id)
        if not authorized[0]:
            error = f"pre-execution audit failed; operation was not run: {authorized[1]}"
            return self._finish(action_id, tool, arguments, target, "blocked", "block", error,
                                None, started, error=error, risk=risk, related_action_id=authorization_id)
        try:
            output = spec["function"](**arguments)
            status, execution_reason, error = "allowed", "risk policy allowed execution", None
        except Exception as exc:
            output, status, execution_reason, error = None, "failed", "tool execution raised an exception", str(exc)
        result = self._finish(action_id, tool, arguments, target, status, "allow", execution_reason,
                              output, started, error=error, risk=risk, related_action_id=authorization_id,
                              executed=True)
        return result

    def resolve_approval(self, approval_id: str, decision: str, approver_id: str,
                         approver_token: str | None) -> dict[str, Any]:
        if decision not in {"approve", "reject"}:
            raise ValueError("decision must be 'approve' or 'reject'")
        from backend.database import (claim_pending_approval, finish_pending_approval,
                                      get_action_task_id, get_pending_approval)
        pending = get_pending_approval(approval_id)
        if not self.authorized(approver_token):
            self._record(str(uuid4()), "approval", {"approval_id": approval_id, "decision": decision},
                         approval_id, "blocked", "block", "unauthorized approval attempt", None, time.perf_counter(),
                         related_action_id=pending["action_id"] if pending else None, approval_id=approval_id,
                         task_id_override=get_action_task_id(pending["action_id"]) if pending else None)
            return {"status": "unauthorized", "executed": False, "error": "authorized approver credentials required"}
        if pending is None:
            return {"status": "not_found", "executed": False, "error": "approval request not found"}

        now = datetime.now(timezone.utc)
        claimed = claim_pending_approval(approval_id, now)
        if claimed is None:
            if pending["status"] == "pending" and pending["expires_at"] <= now:
                from backend.database import expire_pending_approval
                expire_pending_approval(approval_id)
                self._record(str(uuid4()), "approval", {"approval_id": approval_id}, pending["target_resource"],
                             "blocked", "block", "approval expired", None, time.perf_counter(),
                             related_action_id=pending["action_id"], approval_id=approval_id)
                return {"status": "expired", "executed": False, "error": "approval request expired"}
            self._record(str(uuid4()), "approval", {"approval_id": approval_id, "decision": decision},
                         pending["target_resource"], "blocked", "block", "approval is no longer pending",
                         None, time.perf_counter(), related_action_id=pending["action_id"], approval_id=approval_id)
            return {"status": "already_resolved", "executed": False, "error": "approval request is no longer pending"}

        args = claimed["arguments"]
        task_id = get_action_task_id(claimed["action_id"])
        expected_hash = _approval_hash(claimed["action_id"], claimed["tool"], args,
                                       claimed["target_resource"], claimed["expires_at"],
                                       claimed.get("requester_identity"), claimed.get("policy_version"))
        if (not hmac.compare_digest(expected_hash, claimed["argument_hash"]) or
                claimed.get("requester_identity") != self._requester_identity() or
                claimed.get("policy_version") != POLICY_VERSION):
            finish_pending_approval(approval_id, "rejected", approver_id)
            self._record(str(uuid4()), "approval", {"approval_id": approval_id}, claimed["target_resource"],
                         "blocked", "block", "approval payload integrity check failed", None, time.perf_counter(),
                         related_action_id=claimed["action_id"], approval_id=approval_id, task_id_override=task_id)
            return {"status": "rejected", "executed": False, "error": "approval payload integrity check failed"}

        spec, validation_error, validation_reason = self._validate(claimed["tool"], args, None)
        if validation_error or self._target(args) != claimed["target_resource"]:
            finish_pending_approval(approval_id, "rejected", approver_id)
            reason = validation_reason or "approval target changed"
            self._record(str(uuid4()), "approval", {"approval_id": approval_id}, claimed["target_resource"],
                         "blocked", "block", f"revalidation blocked approval: {reason}", None, time.perf_counter(),
                         related_action_id=claimed["action_id"], approval_id=approval_id, task_id_override=task_id)
            return {"status": "blocked", "executed": False, "error": reason}

        try:
            history = self._history_snapshot()
            new_risk = self.predictor.predict({"tool": claimed["tool"], "arguments": args,
                                               "target_resource": claimed["target_resource"]}, history)
            assessment = assess(claimed["tool"], spec, args, history, new_risk)
            assessment.update(raw_ml_probability=new_risk.get("raw_ml_probability", new_risk.get("probability")),
                              calibrated_ml_probability=new_risk.get("calibrated_ml_probability"))
            new_risk = {**new_risk, "risk_score": assessment["final_risk_score"], "assessment": assessment}
            if (self.thresholds.classify(new_risk["risk_score"]) == "BLOCK" or
                    str(spec.get("minimum_decision", "ALLOW")).upper() == "BLOCK"):
                raise RiskUnavailable("risk now exceeds the block threshold")
        except Exception as exc:
            finish_pending_approval(approval_id, "rejected", approver_id)
            self._record(str(uuid4()), "approval", {"approval_id": approval_id}, claimed["target_resource"],
                         "blocked", "block", f"revalidation failed closed: {exc}", None, time.perf_counter(),
                         related_action_id=claimed["action_id"], approval_id=approval_id, task_id_override=task_id)
            return {"status": "blocked", "executed": False, "error": f"risk revalidation failed: {exc}"}

        approval_audit = self._record(str(uuid4()), "approval", {"approval_id": approval_id, "decision": decision,
                                                                  "approver_id": approver_id}, claimed["target_resource"],
                                      "approved" if decision == "approve" else "rejected",
                                      "allow" if decision == "approve" else "block",
                                      f"human {decision} by {approver_id}", None, time.perf_counter(),
                                      risk=new_risk, related_action_id=claimed["action_id"], approval_id=approval_id,
                                      task_id_override=task_id, executed=False)
        if not approval_audit[0]:
            finish_pending_approval(approval_id, "failed", approver_id)
            return {"status": "failed", "executed": False, "error": "approval could not be durably audited"}
        if decision == "reject":
            finish_pending_approval(approval_id, "rejected", approver_id)
            return {"status": "rejected", "executed": False}

        start = time.perf_counter()
        try:
            result = spec["function"](**args)
            status, error = "allowed", None
        except Exception as exc:
            result, status, error = None, "failed", str(exc)
        execution = self._record(str(uuid4()), claimed["tool"], args, claimed["target_resource"], status,
                                 "allow", "human-approved execution" if not error else "approved tool failed",
                                 result, start, error=error, risk=new_risk, related_action_id=claimed["action_id"],
                                 approval_id=approval_id, task_id_override=task_id)
        final_status = "approved" if status == "allowed" else "failed"
        if not execution[0] and status == "allowed":
            # The side effect completed but no durable completion record exists.
            # Keep that uncertainty visible for operator reconciliation.
            final_status = "audit_uncertain"
        finish_pending_approval(approval_id, final_status, approver_id)
        self._remember(claimed["tool"], args, claimed["target_resource"], status, execution[2])
        if final_status == "audit_uncertain":
            return {"status": "audit_uncertain", "executed": True, "result": result,
                    "error": "Tool execution completed but its final audit record was not durable; reconcile before retrying.",
                    "audit_persisted": False, "action_id": claimed["action_id"],
                    "execution_action_id": execution[2], "approval_id": approval_id}
        return {"status": status, "executed": status == "allowed", "result": result,
                "error": error or (None if execution[0] else "execution audit persistence failed"),
                "audit_persisted": execution[0], "action_id": claimed["action_id"],
                "execution_action_id": execution[2], "approval_id": approval_id}

    def _validate(self, tool: str, arguments: Any, forced_block_reason: str | None):
        spec = self.tools.get(tool) if isinstance(tool, str) else None
        if forced_block_reason:
            return None, forced_block_reason, forced_block_reason
        if spec is None:
            error = f"unknown tool: {tool}"
            return None, error, "tool is not allowlisted"
        params = spec.get("parameters", {})
        if not isinstance(arguments, dict) or set(arguments) != set(params):
            error = f"{tool} expects exactly these arguments: {', '.join(params)}"
            return None, error, "arguments do not match the declared schema"
        if any(not isinstance(arguments.get(key), str) for key in params):
            return None, f"{tool} arguments must be strings", "argument type does not match the declared schema"
        function = spec.get("function")
        if not callable(function):
            return None, "tool implementation unavailable", "tool implementation is not callable"
        denial = mandatory_denial(tool, arguments)
        if denial:
            return None, denial, f"mandatory deterministic rule blocked execution: {denial}"
        return spec, None, "validated by deterministic policy"

    @staticmethod
    def _target(arguments: Any) -> Any:
        if isinstance(arguments, dict):
            return arguments.get("filename") or arguments.get("query") or arguments.get("destination")
        return None

    def _history_snapshot(self) -> list[dict[str, Any]]:
        from backend.database import recent_actions
        persisted = recent_actions(self.session_id, 20, agent_id=self.agent_id)
        # Include in-memory events when a test/custom logger has no DB persistence.
        known = {item.get("action_id") for item in persisted}
        history = persisted + [item for item in self._history
                               if item.get("action_id") not in known]
        return history[-20:]

    def _requester_identity(self) -> str:
        """Stable local identity used in approval bindings in this single-tenant app."""
        return f"{self.agent_id}:{self.session_id}"

    def _finish(self, action_id, tool, arguments, target, status, decision, reason, result, started,
                error=None, risk=None, related_action_id=None, approval_id=None, executed=False):
        persisted, log_error, logged_id = self._record(action_id, tool, arguments, target, status, decision,
                                                        reason, result, started, error, risk,
                                                        related_action_id, approval_id, executed=executed)
        if not persisted:
            error = f"{error}; {log_error}" if error else log_error
            reason = f"{reason}; audit persistence failed"
        self._remember(tool, arguments, target, status, action_id)
        return self._result(action_id, tool, status, decision, reason, result, started, persisted,
                            error, risk, approval_id, executed)

    def _record(self, action_id, tool, arguments, target, status, decision, reason, result, started,
                error=None, risk=None, related_action_id=None, approval_id=None, task_id_override=None,
                executed=False):
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        entry = {"timestamp": None, "agent_id": self.agent_id, "session_id": self.session_id,
                 "task_id": task_id_override if task_id_override is not None else self.task_id,
                 "executed": executed,
                 "action_id": action_id, "tool": tool if isinstance(tool, str) else str(tool),
                 "action": tool if isinstance(tool, str) else str(tool), "arguments": arguments,
                 "target_resource": target, "result_summary": error or _summary(result), "status": status,
                 "decision": decision, "reason": reason, "duration_ms": duration_ms,
                 "related_action_id": related_action_id, "approval_id": approval_id}
        if risk:
            entry.update(risk_score=risk.get("risk_score"), risk_probability=risk.get("probability"),
                         raw_ml_probability=risk.get("raw_ml_probability", risk.get("probability")),
                         calibrated_ml_probability=risk.get("calibrated_ml_probability"),
                         model_version=risk.get("model_version"), assessment=risk.get("assessment"))
        try:
            logged = self.logger.record(entry)
            return True, None, logged["action_id"]
        except AuditLogError as exc:
            return False, str(exc), action_id

    def _result(self, action_id, tool, status, decision, reason, result, started, audit_persisted,
                error=None, risk=None, approval_id=None, executed=False):
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        return ExecutionResult(action_id, tool if isinstance(tool, str) else str(tool), status, decision,
                               reason, result, duration_ms, audit_persisted, error,
                               risk.get("risk_score") if risk else None,
                               risk.get("probability") if risk else None,
                               risk.get("model_version") if risk else None, approval_id, executed)

    def _remember(self, tool, arguments, target, status, action_id=None):
        self._history.append({"action_id": action_id or str(uuid4()),
                              "timestamp": datetime.now(timezone.utc).isoformat(), "tool": tool,
                              "arguments": arguments, "target_resource": target, "status": status})
        self._history = self._history[-20:]


def _approval_hash(action_id: str, tool: str, arguments: Any, target: Any, expires_at: datetime,
                   requester_identity: str | None = None, policy_version: str | None = None) -> str:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expiry = expires_at.astimezone(timezone.utc).isoformat()
    payload = json.dumps({"action_id": action_id, "tool": tool, "arguments": arguments,
                          "target": target, "expires_at": expiry,
                          "requester_identity": requester_identity, "policy_version": policy_version},
                         ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _summary(value: Any, limit: int = 240) -> str:
    if isinstance(value, dict) and isinstance(value.get("content"), str):
        value = {**value, "content": f"[document content omitted; {len(value['content'])} characters]"}
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"
