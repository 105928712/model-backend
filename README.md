# model-backend
Backend for the model for COS30049 Computing Technology Innovation Project. Input processing, santitisation, handling, processing, visually

## Requirements
- Python 3.14

## Install
macOS / Linux: `source setup.sh`. 

Windows: `setup.bat` (Command Prompt) or `. .\setup.ps1` (PowerShell).

## Run
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
