# Create/activate the venv, install deps, then download and unzip the datasets. Usage: . .\setup.ps1
Set-Location $PSScriptRoot

Write-Host "Setting up the development environment..."
if (-not (Test-Path .venv\pyvenv.cfg)) { python -m venv .venv }
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt