$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (!(Test-Path ".env")) { Copy-Item ".env.example" ".env" }
if (!(Test-Path ".venv")) { py -3.12 -m venv .venv }
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Write-Host "Starting Cyber X OSINT at http://127.0.0.1:8000" -ForegroundColor Cyan
uvicorn app.main:app --host 127.0.0.1 --port 8000
