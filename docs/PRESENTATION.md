# Presentation runbook

Use this repository at `C:\Users\ssaar\Documents\ChatGPT\AgentGuard`. The older `Desktop\Agentguard` folder is a different checkout and does not contain this completed application.

## First-time setup

Open PowerShell in the repository root and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1
```

The setup script creates `.venv`, installs backend and frontend packages, creates the SQLite database, and creates the synthetic-model artifact only if it is missing.

For agent chat, install and start Ollama once, then pull the configured local model:

```powershell
ollama pull llama3.2:3b
```

## Start the presentation

```powershell
.\scripts\start.ps1
```

The script starts FastAPI in one PowerShell window and Next.js in another, waits until FastAPI health is available, and prints the dashboard and API documentation URLs. The dashboard is available at `http://127.0.0.1:3000`; API documentation is at `http://127.0.0.1:8000/docs`.

Keep both service windows open while presenting. Press `Ctrl+C` in each window when you are finished.

Run the following first if you only want to validate the local install:

```powershell
.\scripts\start.ps1 -CheckOnly
```

## Suggested live flow

1. Open **Overview** to show persisted action counts, model state, and the audit timeline.
2. Open **Chat** and submit `Calculate 44 * 55.`. The expected answer is **2420** and the action timeline records the guarded calculator execution.
3. Submit `Find the sales report, read it, and calculate total sales.`. The permitted report is read from `data\document`; the expected total is **66000**.
4. Submit a traversal request such as `Read ../secret.txt`. AgentGuard blocks it before a file function can run, and the action appears in **Security events**.
5. Use **Approvals** only after configuring `AGENTGUARD_APPROVER_TOKEN` before backend startup. Review actions remain unexecuted until FastAPI revalidates an authorized approval.

Each tool decision is stored in SQLite and append-only JSONL at `logs\agent_actions.jsonl`. The dashboard reads those persisted records; it cannot bypass backend enforcement.

## Troubleshooting

- **“Cannot reach AgentGuard API”**: run `.\scripts\start.ps1`, then confirm the configured Backend URL in **Settings** is `http://127.0.0.1:8000`.
- **Chat shows Ollama unavailable**: start Ollama and run `ollama pull llama3.2:3b`.
- **A port is already in use**: close the existing backend/frontend PowerShell windows, or pass another port, for example `.\scripts\start.ps1 -BackendPort 8010 -FrontendPort 3010` and update the dashboard Backend URL.
- **PowerShell blocks scripts**: run `Set-ExecutionPolicy -Scope Process Bypass` in the current PowerShell session, then rerun the command.
