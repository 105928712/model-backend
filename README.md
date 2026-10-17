# model-backend
Backend for the model for COS30049 Computing Technology Innovation Project. Input processing, santitisation, handling, processing, visually

## Requirements
- Python 3.14

## Install
macOS / Linux: `source setup.sh`.

Windows: `setup.bat` (Command Prompt) or `. .\setup.ps1` (PowerShell).

## Running
Needs Docker running

Then:

```bash
cp .env.example .env      # customise the .env
docker compose up -d      # Postgres on 127.0.0.1 only, tables created on first start
python -m scripts.seed    # admin and user accounts
```

## Run
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Auto API docs generated at http://127.0.0.1:8000/docs. Sign in with `POST /api/login`, then send `Authorization: Bearer <token>` in every request