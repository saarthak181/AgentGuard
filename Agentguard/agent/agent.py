import json
import ollama

from agent.tools import TOOLS


MODEL_NAME = "llama3.2:3b"


SYSTEM_PROMPT = """
You are AgentGuard's AI agent.

You are a helpful multi-step AI agent.

You have access to these tools:

1. calculator
   - Use this for mathematical calculations.
   - Argument:
     expression

2. search_files
   - Search documents for a keyword.
   - Argument:
     keyword

3. read_file
   - Read a document.
   - Argument:
     filename

When you need a tool, respond ONLY with valid JSON:

{
    "action": "tool",
    "tool": "tool_name",
    "arguments": {
        "argument_name": "value"
    }
}

When you have enough information to answer the user, respond ONLY with:

{
    "action": "final",
    "answer": "your answer"
}

Do not invent tool results.
Use tools when necessary.
You may use multiple tools to complete a task.
"""


class Agent:

    def __init__(self):
        self.messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            }
        ]

    def _call_llm(self):

        response = ollama.chat(
            model=MODEL_NAME,
            messages=self.messages,
            options={
                "temperature": 0
            }
        )

        return response["message"]["content"]

    def _execute_tool(self, tool_name, arguments):

        if tool_name not in TOOLS:
            return f"Unknown tool: {tool_name}"

        try:
            tool = TOOLS[tool_name]

            result = tool(**arguments)

            return result

        except Exception as e:
            return f"Tool execution error: {str(e)}"

    def run(self, user_input):

        self.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )

        for step in range(10):

            response = self._call_llm()

            print(f"\n[Agent reasoning step {step + 1}]")
            print(response)

            try:

                decision = json.loads(response)

            except json.JSONDecodeError:

                return (
                    "The model returned an invalid response:\n"
                    + response
                )

            action = decision.get("action")

            # ------------------------------------------------
            # FINAL ANSWER
            # ------------------------------------------------

            if action == "final":

                answer = decision.get(
                    "answer",
                    "No answer provided."
                )

                return answer

            # ------------------------------------------------
            # TOOL CALL
            # ------------------------------------------------

            if action == "tool":

                tool_name = decision.get("tool")

                arguments = decision.get(
                    "arguments",
                    {}
                )

                print(
                    f"\n[Tool Call] "
                    f"{tool_name}({arguments})"
                )

                result = self._execute_tool(
                    tool_name,
                    arguments
                )

                print("\n[Tool Result]")
                print(result)

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
                            f"Tool '{tool_name}' returned:\n"
                            f"{result}\n\n"
                            "Continue the task. "
                            "Use another tool if necessary, "
                            "otherwise provide the final answer."
                        )
                    }
                )

                continue

            return "Unknown agent action."

        return "Agent reached the maximum number of steps."

    