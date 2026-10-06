import json
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# LOG CONFIGURATION
# ============================================================

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "agent_actions.jsonl"


# ============================================================
# ACTION LOGGER
# ============================================================

def log_action(
    agent_id,
    session_id,
    tool_name,
    arguments,
    result,
    status,
    risk_level="unknown",
):
    """
    Store one agent action as a JSON Lines record.
    """

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "session_id": session_id,
        "tool": tool_name,
        "arguments": arguments,
        "result": result,
        "status": status,
        "risk_level": risk_level,
    }

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(event) + "\n"
        )

    return event