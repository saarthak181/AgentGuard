[CmdletBinding()]
param(
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath ".venv\\Scripts\\python.exe")) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    Write-Host "Creating Python virtual environment..."
    if ($py) {
        & $py.Source -3.12 -m venv .venv
    } elseif ($pythonCommand) {
        & $pythonCommand.Source -m venv .venv
    } else {
        throw "Python 3.12 or later is required. Install it, then run this script again."
    }
}

$python = Join-Path $projectRoot ".venv\\Scripts\\python.exe"
Write-Host "Installing backend dependencies..."
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt

New-Item -ItemType Directory -Force data | Out-Null
$env:AGENTGUARD_DATABASE_URL = "sqlite:///./data/agentguard.db"
& $python -c "from backend.database import init_db; init_db(); print('SQLite database initialized.')"

if (-not (Test-Path -LiteralPath "ml\\artifacts\\model_bundle.joblib")) {
    Write-Host "Training the included reproducible synthetic model..."
    & $python -m ml.dataset --seed 2026 --output ml/data/synthetic_traces.jsonl
    & $python -m ml.pipeline train --dataset ml/data/synthetic_traces.jsonl --artifact-dir ml/artifacts --seed 2026 --test-size 0.25
    & $python -m ml.pipeline evaluate --artifact-dir ml/artifacts
}

if (-not $SkipFrontend) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npm) { throw "Node.js 20.9+ and npm are required for the dashboard." }
    Write-Host "Installing dashboard dependencies..."
    Push-Location frontend
    try { & $npm.Source ci } finally { Pop-Location }
}

Write-Host "Setup complete. Start the app with: .\\scripts\\start.ps1"
