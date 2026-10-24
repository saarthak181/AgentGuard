[CmdletBinding()]
param(
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 3000,
    [switch]$SkipFrontend,
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$python = Join-Path $projectRoot ".venv\\Scripts\\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Virtual environment is missing. Run .\\scripts\\setup.ps1 from $projectRoot first."
}
if (-not $SkipFrontend -and -not (Test-Path -LiteralPath "frontend\\node_modules")) {
    throw "Dashboard dependencies are missing. Run .\\scripts\\setup.ps1 from $projectRoot first."
}
if ($BackendPort -lt 1 -or $BackendPort -gt 65535 -or $FrontendPort -lt 1 -or $FrontendPort -gt 65535) {
    throw "Ports must be between 1 and 65535."
}

$env:AGENTGUARD_DATABASE_URL = "sqlite:///./data/agentguard.db"
& $python -c "from backend.database import init_db; init_db(); print('SQLite database initialized.')"

if ($CheckOnly) {
    Write-Host "Preflight passed. Python environment, SQLite initialization, and dashboard dependencies are ready."
    exit 0
}

$ports = @($BackendPort)
if (-not $SkipFrontend) { $ports += $FrontendPort }
foreach ($port in $ports) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Stop the existing service or choose another port."
    }
}

$backendCommand = "Set-Location -LiteralPath '$projectRoot'; `$env:AGENTGUARD_DATABASE_URL='sqlite:///./data/agentguard.db'; & '$python' -m uvicorn backend.main:app --host 127.0.0.1 --port $BackendPort"
Start-Process -FilePath powershell.exe -ArgumentList @("-NoExit", "-Command", $backendCommand) -WorkingDirectory $projectRoot | Out-Null

$backendReady = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    Start-Sleep -Seconds 1
    try {
        Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$BackendPort/health" -TimeoutSec 2 | Out-Null
        $backendReady = $true
        break
    } catch {}
}
if (-not $backendReady) { throw "FastAPI did not become ready. Check the backend PowerShell window for details." }

if (-not $SkipFrontend) {
    $frontendPath = Join-Path $projectRoot "frontend"
    $frontendCommand = "Set-Location -LiteralPath '$frontendPath'; npm run dev -- --hostname 127.0.0.1 --port $FrontendPort"
    Start-Process -FilePath powershell.exe -ArgumentList @("-NoExit", "-Command", $frontendCommand) -WorkingDirectory $frontendPath | Out-Null
    $frontendReady = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$FrontendPort/" -TimeoutSec 2 | Out-Null
            $frontendReady = $true
            break
        } catch {}
    }
    if (-not $frontendReady) { throw "Next.js did not become ready. Check the dashboard PowerShell window for details." }
    Write-Host "AgentGuard started. Dashboard: http://127.0.0.1:$FrontendPort  API docs: http://127.0.0.1:$BackendPort/docs"
} else {
    Write-Host "AgentGuard API started. Docs: http://127.0.0.1:$BackendPort/docs"
}

try {
    $agent = Invoke-RestMethod "http://127.0.0.1:$BackendPort/agent/status" -TimeoutSec 5
    if ($agent.status -ne "ready") { Write-Warning "Ollama/model is unavailable. The dashboard works, but Chat tasks need: ollama pull $($agent.model)" }
} catch { Write-Warning "Could not verify Ollama status. Check http://127.0.0.1:$BackendPort/agent/status" }
