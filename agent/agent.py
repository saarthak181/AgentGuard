import json
import uuid
import ollama

from agent.tools import TOOLS
from security.guard import AgentGuard


# ============================================================
# MODEL CONFIGURATION
# ============================================================

MODEL_NAME = "llama3.2:3b"


# ============================================================
# SYSTEM PROMPT
# ============================================================

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


# ============================================================
# AGENT CLASS
# ============================================================

class Agent:

    def __init__(self):

        self.agent_id = "agent-001"

        self.session_id = str(
            uuid.uuid4()
        )

        self.guard = AgentGuard()

        self.messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            }
        ]

    # ========================================================
    # CALL OLLAMA
    # ========================================================

    def _call_llm(self):

        response = ollama.chat(
            model=MODEL_NAME,
            messages=self.messages,
            options={
                "temperature": 0
            }
        )

        return response["message"]["content"]

    # ========================================================
    # EXECUTE TOOL THROUGH AGENTGUARD
    # ========================================================

    def _execute_tool(
        self,
        tool_name,
        arguments,
    ):

        if tool_name not in TOOLS:

            return {
                "success": False,
                "blocked": False,
                "result": f"Unknown tool: {tool_name}",
                "risk_level": "unknown",
                "decision": "deny",
                "reasons": [
                    "Unknown tool requested."
                ],
            }

        tool = TOOLS[tool_name]

        return self.guard.execute(
            tool_function=tool,
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=tool_name,
            arguments=arguments,
        )

    # ========================================================
    # RUN AGENT
    # ========================================================

    def run(self, user_input):

        self.messages.append(
            {
                "role": "user",
                "content": user_input
            }
        )

        # Maximum number of actions for one task
        MAX_STEPS = 10

        for step in range(MAX_STEPS):

            response = self._call_llm()

            print(
                f"\n[Agent Step {step + 1}]"
            )

            print(response)

            # ------------------------------------------------
            # Parse model response
            # ------------------------------------------------

            try:

                decision = json.loads(response)

            except json.JSONDecodeError:

                return (
                    "The model returned an invalid "
                    "JSON response:\n"
                    + response
                )

            action = decision.get("action")

            # ------------------------------------------------
            # FINAL ANSWER
            # ------------------------------------------------

            if action == "final":

                return decision.get(
                    "answer",
                    "No answer provided."
                )

            # ------------------------------------------------
            # TOOL ACTION
            # ------------------------------------------------

            if action == "tool":

                tool_name = decision.get(
                    "tool"
                )

                arguments = decision.get(
                    "arguments",
                    {}
                )

                print(
                    "\n[Tool Call]"
                )

                print(
                    f"{tool_name}({arguments})"
                )

                # --------------------------------------------
                # AgentGuard
                # --------------------------------------------

                tool_response = self._execute_tool(
                    tool_name,
                    arguments
                )

                print(
                    "\n[AgentGuard]"
                )

                print(
                    f"Risk: "
                    f"{tool_response['risk_level']}"
                )

                print(
                    f"Decision: "
                    f"{tool_response['decision']}"
                )

                if tool_response["reasons"]:

                    print("Reasons:")

                    for reason in tool_response["reasons"]:

                        print(
                            f"- {reason}"
                        )

                print(
                    "\n[Tool Result]"
                )

                print(
                    tool_response["result"]
                )

                # --------------------------------------------
                # Add assistant decision to history
                # --------------------------------------------

                self.messages.append(
                    {
                        "role": "assistant",
                        "content": response
                    }
                )

                # --------------------------------------------
                # Send AgentGuard result back to LLM
                # --------------------------------------------

                self.messages.append(
                    {
                        "role": "user",
                        "content": (
                            "AgentGuard processed your "
                            "tool request.\n\n"
                            f"Security result:\n"
                            f"{json.dumps(tool_response)}\n\n"
                            "Continue the task. "
                            "If more tools are needed, "
                            "request another tool. "
                            "Otherwise provide the final answer."
                        )
                    }
                )

                continue

            # ------------------------------------------------
            # UNKNOWN ACTION
            # ------------------------------------------------

            return (
                "Unknown agent action: "
                f"{action}"
            )

        return (
            "Agent reached the maximum number "
            "of allowed steps."
        )