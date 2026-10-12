import json

from sqlalchemy import select

from agent import Agent
from agent.tools import TOOL_REGISTRY
from backend.database import get_session, persist_action
from backend.models import ActionRecord
from security.guard import AgentGuard
from security.logger import AuditLogger


def msg(name, arguments):
    return json.dumps({"action": "tool", "name": name, "arguments": arguments})


def test_agent_tool_requests_pass_through_guard_and_are_logged(tmp_path):
    llm_answers = iter([msg("calculator", {"expression": "5*5"}), json.dumps({"action": "final", "answer": "25"})])
    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(tmp_path / "actions.jsonl", persist=persist_action))
    result = Agent(llm=lambda _: next(llm_answers), guard=guard).run("calculate")
    execution = result.tool_calls[0]["execution"]
    assert result.answer == "25" and execution["status"] == "allowed" and execution["audit_persisted"]
    db = get_session()
    try:
        assert db.scalar(select(ActionRecord).where(ActionRecord.action_id == execution["action_id"])) is not None
    finally:
        db.close()


def test_agent_blocked_action_is_not_executed_and_is_logged(tmp_path):
    calls = []
    tools = dict(TOOL_REGISTRY)
    tools["calculator"] = {**TOOL_REGISTRY["calculator"], "function": lambda **kw: calls.append(kw)}
    llm_answers = iter([msg("calculator", {"expression": 7}), json.dumps({"action": "final", "answer": "blocked"})])
    guard = AgentGuard(tools, AuditLogger(tmp_path / "actions.jsonl", persist=persist_action))
    result = Agent(llm=lambda _: next(llm_answers), guard=guard).run("calculate")
    execution = result.tool_calls[0]["execution"]
    assert calls == [] and execution["status"] == "blocked" and execution["audit_persisted"]


def test_agent_stops_after_audit_persistence_failure(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    llm_calls = []

    def llm(_):
        llm_calls.append(True)
        return msg("calculator", {"expression": "1+1"})

    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(blocker / "actions.jsonl"))
    result = Agent(llm=llm, guard=guard).run("calculate")
    assert len(llm_calls) == 1 and result.steps == 1
    assert result.tool_calls[0]["execution"]["audit_persisted"] is False
    assert "could not be audited" in result.answer


def test_sales_report_acceptance_regression(tmp_path, documents):
    replies = iter([
        msg("search_files", {"query": "sales"}),
        msg("read_file", {"filename": "sales_report.txt"}),
        msg("calculator", {"expression": "12000+15000+18000+21000"}),
        json.dumps({"action": "final", "answer": "Total sales: 66000. Best region: North India."}),
    ])
    guard = AgentGuard(TOOL_REGISTRY, AuditLogger(tmp_path / "actions.jsonl", persist=persist_action))
    result = Agent(llm=lambda _: next(replies), guard=guard).run("Find the sales report, read it, calculate the total sales, and tell me the best region.")
    assert result.answer == "Total sales: 66000. Best region: North India."
    assert [item["execution"]["status"] for item in result.tool_calls] == ["allowed"] * 3
    assert "January: 12000" not in result.answer
