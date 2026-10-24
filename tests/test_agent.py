import json
import sys
import types

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
    remaining = iter((decision, decision, response({"action": "final", "answer": "done"})))
    requests = []

    def llm(_messages):
        requests.append(True)
        return next(remaining)

    result = Agent(max_steps=3, llm=llm).run("go")
    assert "Repeated" in result.tool_calls[1]["result"]["error"]
    assert result.completed is False
    assert "new task" in result.answer
    assert len(requests) == 2


def test_max_step_enforcement():
    first = response({"action": "tool", "name": "calculator", "arguments": {"expression": "1+1"}})
    second = response({"action": "tool", "name": "calculator", "arguments": {"expression": "2+2"}})
    result = Agent(max_steps=2, llm=scripted(first, second, second)).run("go")
    assert result.steps == 2 and "allowed number" in result.answer


def test_missing_arguments_are_corrected_and_retried():
    prompts = []
    responses = iter([
        response({"action": "tool", "name": "calculator"}),
        response({"action": "tool", "name": "calculator", "arguments": {"expression": "44*55"}}),
        response({"action": "final", "answer": "2420"}),
    ])

    def llm(messages):
        prompts.append(list(messages))
        return next(responses)

    result = Agent(llm=llm).run("Calculate 44 times 55.")
    assert [call["execution"]["status"] for call in result.tool_calls] == ["blocked", "allowed"]
    assert result.answer == "2420"
    assert prompts[1][-1]["role"] == "user"
    assert "did not execute it" in prompts[1][-1]["content"]
    assert '"expression":"44*55"' in prompts[1][-1]["content"]


def test_ollama_receives_tool_specific_json_schema(monkeypatch):
    captured = {}

    class Client:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        def chat(self, **kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(message=types.SimpleNamespace(content='{"action":"final","answer":"ok"}'))

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(Client=Client))
    assert Agent(timeout=12)._request([{"role": "user", "content": "test"}]).endswith('"answer":"ok"}')
    schema = captured["format"]
    calculator = next(item for item in schema["anyOf"]
                      if item["properties"].get("name", {}).get("enum") == ["calculator"])
    assert calculator["required"] == ["action", "name", "arguments"]
    assert calculator["properties"]["arguments"]["required"] == ["expression"]
    assert calculator["properties"]["arguments"]["additionalProperties"] is False


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
