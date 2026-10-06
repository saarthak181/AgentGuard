import json
import uuid
import ollama

from agent.tools import TOOLS
from security.guard import AgentGuard


MODEL_NAME = "llama3.2:3b"


class Agent:

    def __init__(self):

        self.agent_id = "agent-001"
        self.session_id = str(uuid.uuid4())
        self.guard = AgentGuard()
        self.messages = []

    # =========================================================
    # SYSTEM PROMPT
    # =========================================================

    def _system_prompt(self):

        return """
You are AgentGuard's AI agent.

You have ONLY these tools:

1. calculator
   Use for mathematical calculations.

2. search_files
   Use to search for files.

3. read_file
   Use to read a file.

IMPORTANT RULES:

- Never invent tools.
- Never use Wikipedia.
- Never use web search.
- Never use browser tools.
- Only use calculator, search_files, and read_file.

If a tool is needed, return ONLY JSON.

Tool format:

{
    "action": "tool",
    "tool": "tool_name",
    "arguments": {}
}

For calculator:

{
    "action": "tool",
    "tool": "calculator",
    "arguments": {
        "expression": "33*44"
    }
}

For search_files:

{
    "action": "tool",
    "tool": "search_files",
    "arguments": {
        "query": "sales"
    }
}

For read_file:

{
    "action": "tool",
    "tool": "read_file",
    "arguments": {
        "filename": "sales_report.txt"
    }
}

When you have enough information, return ONLY:

{
    "action": "final",
    "answer": "your answer"
}

Do not repeatedly call the same tool.
Do not search for a file after successfully reading it.
"""

    # =========================================================
    # CALL LLM
    # =========================================================

    def _call_llm(self):

        response = ollama.chat(
            model=MODEL_NAME,
            messages=self.messages,
            options={
                "temperature": 0
            }
        )

        return response["message"]["content"]

    # =========================================================
    # PARSE RESPONSE
    # =========================================================

    def _parse_response(self, response):

        response = response.strip()

        # Remove markdown code fences.
        if response.startswith("```"):

            lines = response.splitlines()

            if lines and lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            response = "\n".join(lines).strip()

        try:

            data = json.loads(response)

        except json.JSONDecodeError:

            return {
                "action": "error",
                "message": "The AI returned invalid JSON.",
                "raw_response": response
            }

        # -----------------------------------------------------
        # NORMAL TOOL FORMAT
        # -----------------------------------------------------

        if data.get("action") == "tool":

            tool_name = data.get("tool")

            if tool_name not in TOOLS:

                return {
                    "action": "error",
                    "message": (
                        f"Invalid tool '{tool_name}'. "
                        f"Available tools: "
                        f"{', '.join(TOOLS.keys())}"
                    )
                }

            return {
                "action": "tool",
                "tool": tool_name,
                "arguments": data.get(
                    "arguments",
                    {}
                )
            }

        # -----------------------------------------------------
        # HANDLE:
        #
        # {
        #     "action": "calculator",
        #     ...
        # }
        # -----------------------------------------------------

        if data.get("action") in TOOLS:

            return {
                "action": "tool",
                "tool": data["action"],
                "arguments": data.get(
                    "arguments",
                    {}
                )
            }

        # -----------------------------------------------------
        # FINAL ANSWER
        # -----------------------------------------------------

        if data.get("action") == "final":

            return {
                "action": "final",
                "answer": data.get(
                    "answer",
                    "No answer available."
                )
            }

        return {
            "action": "error",
            "message": (
                f"Unknown agent action: "
                f"{data.get('action')}"
            )
        }

    # =========================================================
    # RUN AGENT
    # =========================================================

    def run(self, user_input):

        self.session_id = str(uuid.uuid4())

        self.messages = [
            {
                "role": "system",
                "content": self._system_prompt()
            },
            {
                "role": "user",
                "content": user_input
            }
        ]

        max_steps = 10

        previous_tool = None
        previous_arguments = None

        for step in range(max_steps):

            print(
                f"\n[Agent Step {step + 1}]"
            )

            response = self._call_llm()

            print(response)

            decision = self._parse_response(
                response
            )

            # =================================================
            # ERROR
            # =================================================

            if decision["action"] == "error":

                return decision["message"]

            # =================================================
            # FINAL ANSWER
            # =================================================

            if decision["action"] == "final":

                return decision.get(
                    "answer",
                    "No answer available."
                )

            # =================================================
            # TOOL ACTION
            # =================================================

            if decision["action"] == "tool":

                tool_name = decision["tool"]

                arguments = decision.get(
                    "arguments",
                    {}
                )

                # -------------------------------------------------
                # DETECT EXACT REPEATED TOOL CALL
                # -------------------------------------------------

                if (
                    previous_tool == tool_name
                    and previous_arguments == arguments
                ):

                    return (
                        "The agent attempted to repeat "
                        f"the same '{tool_name}' action "
                        "multiple times."
                    )

                previous_tool = tool_name
                previous_arguments = arguments

                # -------------------------------------------------
                # AGENTGUARD
                # -------------------------------------------------

                allowed, result = self.guard.execute(
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    tool=tool_name,
                    arguments=arguments
                )

                # -------------------------------------------------
                # BLOCKED / FAILED
                # -------------------------------------------------

                if not allowed:

                    return (
                        f"AgentGuard blocked the action "
                        f"'{tool_name}'. "
                        f"Reason: {result}"
                    )

                # =================================================
                # IMPORTANT:
                # SUCCESSFUL FILE READ
                # =================================================

                if tool_name == "read_file":

                    return result

                # =================================================
                # CALCULATOR RESULT
                # =================================================

                if tool_name == "calculator":

                    self.messages.append(
                        {
                            "role": "assistant",
                            "content": response
                        }
                    )

                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                "The calculator returned:\n\n"
                                f"{result}\n\n"
                                "Return the final answer now. "
                                "Do not call another tool."
                            )
                        }
                    )

                    continue

                # =================================================
                # SEARCH RESULT
                # =================================================

                if tool_name == "search_files":

                    self.messages.append(
                        {
                            "role": "assistant",
                            "content": response
                        }
                    )

                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                "The file search returned:\n\n"
                                f"{result}\n\n"
                                "If a relevant file was found, "
                                "use read_file to read it. "
                                "Do not search again using "
                                "the same query."
                            )
                        }
                    )

                    continue

        return (
            "Maximum agent steps reached "
            "without a final answer."
        )