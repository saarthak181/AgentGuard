from fastapi import FastAPI
from pathlib import Path
import json


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AgentGuard API",
    description="Security backend for AI agents",
    version="0.1.0",
)


# ============================================================
# LOG FILE
# ============================================================

LOG_FILE = Path(
    "logs/agent_actions.jsonl"
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "name": "AgentGuard",
        "status": "running",
        "version": "0.1.0",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# READ ACTION LOGS
# ============================================================

@app.get("/actions")
def get_actions():

    if not LOG_FILE.exists():

        return []

    actions = []

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            try:

                actions.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                continue

    return actions


# ============================================================
# SECURITY STATISTICS
# ============================================================

@app.get("/stats")
def get_stats():

    actions = get_actions()

    total = len(actions)

    blocked = sum(
        1
        for action in actions
        if action.get("status") == "blocked"
    )

    high_risk = sum(
        1
        for action in actions
        if action.get("risk_level") == "high"
    )

    medium_risk = sum(
        1
        for action in actions
        if action.get("risk_level") == "medium"
    )

    low_risk = sum(
        1
        for action in actions
        if action.get("risk_level") == "low"
    )

    return {
        "total_actions": total,
        "blocked_actions": blocked,
        "high_risk_actions": high_risk,
        "medium_risk_actions": medium_risk,
        "low_risk_actions": low_risk,
    }