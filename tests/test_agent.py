import json

import pytest

from agent.agent import Agent, AgentError


def scripted(*items):
    values = iter(items)
    return lambda _messages: next(values)


def response(action):
    return json.dumps(action)


def test_valid_tool_selection(documents):
    result = Agent(llm=scripted(response({"action": "tool", "name": "calculator", "arguments": {"expression": "2+2"}}), response({"action": "final", "answer": "4"}))).run("calculate")
    assert result.answer == "4" and result.tool_calls[0]["result"]["result"] == 4


def test_malformed_json_retries():
    result = Agent(llm=scripted("{bad", response({"action": "final", "answer": "ok"}))).run("go")
    assert result.answer == "ok"


def test_unknown_tool_and_invalid_arguments_recover():
    llm = scripted(response({"action": "tool", "name": "python", "arguments": {}}), response({"action": "tool", "name": "calculator", "arguments": {"expression": "2+2", "extra": True}}), response({"action": "final", "answer": "recovered"}))
    result = Agent(llm=llm).run("go")
    assert "unknown tool" in result.tool_calls[0]["result"]["error"]
    assert "expects exactly" in result.tool_calls[1]["result"]["error"]


def test_repeated_call_stopped():
    decision = response({"action": "tool", "name": "calculator", "arguments": {"expression": "1+1"}})
    result = Agent(max_steps=3, llm=scripted(decision, decision, response({"action": "final", "answer": "done"}))).run("go")
    assert "Repeated" in result.tool_calls[1]["result"]["error"]


def test_max_step_enforcement():
    decision = response({"action": "tool", "name": "calculator", "arguments": {"expression": "1+1"}})
    result = Agent(max_steps=2, llm=scripted(decision, decision, decision)).run("go")
    assert result.steps == 2 and "allowed number" in result.answer


def test_tool_error_recovery():
    result = Agent(llm=scripted(response({"action": "tool", "name": "read_file", "arguments": {"filename": "../secret"}}), response({"action": "final", "answer": "could not read"}))).run("read")
    assert "traversal" in result.tool_calls[0]["result"]["error"]


@pytest.mark.parametrize("failure,expected", [(ConnectionError("connection refused"), "Cannot reach Ollama"), (RuntimeError("model not found; pull it"), "unavailable"), (TimeoutError("request timeout"), "timed out")])
def test_ollama_errors_reported(failure, expected):
    agent = Agent()
    agent._request = lambda _messages: (_ for _ in ()).throw(failure)
    with pytest.raises(AgentError, match=expected):
        agent.run("hello")


def test_mocked_multi_step_acceptance_workflow():
    answers = [
        {"action": "tool", "name": "search_files", "arguments": {"query": "sales"}},
        {"action": "tool", "name": "read_file", "arguments": {"filename": "sales_report.txt"}},
        {"action": "tool", "name": "calculator", "arguments": {"expression": "12000+15000+18000+21000"}},
        {"action": "final", "answer": "Total sales were 66000; North India was the best region."},
    ]
    result = Agent(llm=scripted(*(response(a) for a in answers))).run("Find the sales report, read it, calculate the total sales, and tell me the best region.")
    assert [c["name"] for c in result.tool_calls] == ["search_files", "read_file", "calculator"]
    assert "66000" in result.answer and "North India" in result.answer
    assert result.tool_calls[1]["result"]["content"].count("January") == 1
