@echo off
cd /d "%~dp0"

if not exist ".env" (
    echo You must have a .env file to run this script!
    echo See .env.example for an example.
    echo Use copy .env.example .env to create a .env file.
    exit /b 1
)

docker compose up -d --wait && echo Postgres running on 127.0.0.1:5432
python -m scripts.seed && echo Admin and user accounts created
uvicorn app.main:app --host 127.0.0.1 --port 8000
echo Backend running on http://127.0.0.1:8000
echo Ctrl+C to stop.