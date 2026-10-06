import json
from pathlib import Path
from datetime import datetime


LOG_FOLDER = Path("logs")
LOG_FILE = LOG_FOLDER / "agent_actions.jsonl"


def log_action(
    agent_id,
    session_id,
    action,
    arguments,
    result,
    status,
    risk_level
):
    """
    Record one AgentGuard action in JSONL format.
    """

    LOG_FOLDER.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "agent_id": agent_id,
        "session_id": session_id,
        "action": action,
        "arguments": arguments,
        "result": result,
        "status": status,
        "risk_level": risk_level
    }

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(
            json.dumps(log_entry, ensure_ascii=False) + "\n"
        )