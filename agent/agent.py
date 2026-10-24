"""Ollama-backed, explicit-tool agent loop."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .tools import TOOL_REGISTRY
from security.guard import AgentGuard


class AgentError(RuntimeError):
    pass


@dataclass
class AgentResult:
    answer: str
    steps: int
    tool_calls: list[dict[str, Any]]
    completed: bool = True


class Agent:
    def __init__(self, model: str = "llama3.2:3b", max_steps: int = 8, timeout: float = 60,
                 llm: Callable[[list[dict[str, str]]], str] | None = None,
                 guard: AgentGuard | None = None):
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self.model, self.max_steps, self.timeout, self.llm = model, max_steps, timeout, llm
        self.guard = guard or AgentGuard(TOOL_REGISTRY)

    def _decision_schema(self) -> dict[str, Any]:
        """Bind each model tool decision to the exact argument schema the guard accepts."""
        variants = []
        for name, spec in self.guard.tools.items():
            parameters = spec.get("parameters", {})
            variants.append({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["tool"]},
                    "name": {"type": "string", "enum": [name]},
                    "arguments": {
                        "type": "object",
                        "properties": {key: {"type": "string"} for key in parameters},
                        "required": list(parameters),
                        "additionalProperties": False,
                    },
                },
                "required": ["action", "name", "arguments"],
                "additionalProperties": False,
            })
        variants.append({
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["final"]},
                "answer": {"type": "string"},
            },
            "required": ["action", "answer"],
            "additionalProperties": False,
        })
        return {"type": "object", "anyOf": variants}

    def _request(self, messages: list[dict[str, str]]) -> str:
        if self.llm:
            return self.llm(messages)
        try:
            import ollama
        except ImportError as exc:
            raise AgentError("Ollama Python package is missing. Install requirements.txt.") from exc
        try:
            client = ollama.Client(timeout=self.timeout)
            response = client.chat(model=self.model, messages=messages, format=self._decision_schema(),
                                   options={"num_predict": 512})
        except Exception as exc:
            text = str(exc)
            if "timeout" in text.lower() or isinstance(exc, TimeoutError):
                raise AgentError(f"Ollama request timed out after {self.timeout:g} seconds.") from exc
            if "not found" in text.lower() or "model" in text.lower() and "pull" in text.lower():
                raise AgentError(f"Ollama model '{self.model}' is unavailable. Run: ollama pull {self.model}") from exc
            raise AgentError(f"Cannot reach Ollama. Start Ollama and verify the model '{self.model}' is installed. Details: {exc}") from exc
        if isinstance(response, dict):
            return response.get("message", {}).get("content", "")
        return response.message.content

    def run(self, task: str) -> AgentResult:
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task must be a non-empty string")
        tool_list = [{"name": name, "description": spec["description"], "parameters": spec["parameters"]}
                     for name, spec in self.guard.tools.items()]
        schema = self._decision_schema()
        messages = [{"role": "system", "content": (
            "You are AgentGuard, a local assistant. Choose only listed tools. Never invent tools. "
            "Reply with JSON exactly: {\"action\":\"tool\",\"name\":...,\"arguments\":{...}} "
            "or {\"action\":\"final\",\"answer\":...}. Every tool call MUST include a non-null arguments object "
            "with exactly the listed keys and string values. For calculator, use "
            "{\"action\":\"tool\",\"name\":\"calculator\",\"arguments\":{\"expression\":\"44*55\"}}. "
            "Never omit arguments, use null, or put arguments beside the arguments object. Do not repeat completed calls. "
            f"Available tools: {json.dumps(tool_list)}. Required output schema: {json.dumps(schema)}")},
                    {"role": "user", "content": task}]
        calls: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        seen = set()
        for step in range(1, self.max_steps + 1):
            try:
                raw = self._request(messages)
                decision = json.loads(raw)
            except json.JSONDecodeError as exc:
                messages.append({"role": "assistant", "content": str(raw)})
                messages.append({"role": "user", "content": f"Malformed JSON ({exc}). Return one valid decision JSON object."})
                continue
            except AgentError:
                raise
            except TimeoutError as exc:
                raise AgentError(f"Ollama request timed out after {self.timeout:g} seconds.") from exc
            except Exception as exc:
                detail = str(exc)
                lowered = detail.lower()
                if isinstance(exc, (ConnectionError, OSError)) or "connection refused" in lowered or "connecterror" in lowered:
                    message = f"Cannot reach Ollama. Start Ollama and verify the model '{self.model}' is installed. Details: {detail}"
                elif "not found" in lowered or "pull it" in lowered:
                    message = f"Ollama model '{self.model}' is unavailable. Run: ollama pull {self.model}"
                elif "timeout" in lowered:
                    message = f"Ollama request timed out after {self.timeout:g} seconds."
                else:
                    message = f"LLM request failed: {detail}"
                raise AgentError(message) from exc
            if not isinstance(decision, dict):
                messages.append({"role": "user", "content": "Response must be a JSON object. Try again."})
                continue
            if decision.get("action") == "final" and isinstance(decision.get("answer"), str):
                return AgentResult(decision["answer"], step, calls, True)
            name, args = decision.get("name"), decision.get("arguments")
            if decision.get("action") != "tool":
                messages.append({"role": "user", "content": "Use action 'tool' or 'final' and provide a valid response."})
                continue
            key = json.dumps([name, args], sort_keys=True, default=str)
            tool_key = name if isinstance(name, str) else str(name)
            counts[tool_key] = counts.get(tool_key, 0) + 1
            if key in seen or counts[tool_key] > 3:
                execution = self.guard.execute(name, args, forced_block_reason="Repeated tool call stopped to prevent a loop.")
            else:
                seen.add(key)
                execution = self.guard.execute(name, args)
            result = execution.result if execution.status == "allowed" else {"error": execution.error or execution.reason}
            if not execution.audit_persisted:
                result = {"error": "Action execution stopped because audit persistence failed.", "details": execution.error}
            call = {"name": name, "arguments": args, "result": result,
                    "execution": execution.to_dict()}
            calls.append(call)
            if not execution.audit_persisted:
                messages.extend([{"role": "assistant", "content": json.dumps(decision)},
                                 {"role": "user", "content": "The action could not be audited, so it was not run. Stop and report this."}])
                return AgentResult("The action could not be audited, so I stopped the task.", step, calls)
            if execution.status == "blocked":
                if execution.reason == "Repeated tool call stopped to prevent a loop.":
                    return AgentResult(
                        "I stopped because the model repeated a tool call. No calculator action was run for that repeated call. "
                        "Please submit the calculation again as a new task.", step, calls, False)
                feedback = (
                    f"AgentGuard blocked the {name} call and did not execute it. Reason: {execution.error or execution.reason}. "
                    "Correct the call using the exact required argument names and string values. "
                    "For calculator, send arguments as {\"expression\":\"44*55\"}. "
                    "Do not repeat the rejected call; if you cannot form a valid call, return a final explanation."
                )
            else:
                feedback = (f"AgentGuard {execution.status} the {name} call. "
                            f"Result: {json.dumps(result, ensure_ascii=False)}. "
                            "Use this result to answer or continue only if another distinct tool call is needed.")
            messages.extend([{"role": "assistant", "content": json.dumps(decision)},
                             {"role": "user", "content": feedback}])
        return AgentResult("I couldn't complete the task within the allowed number of steps.", self.max_steps, calls, False)
