#!/bin/bash

if [ ! -f .env ]; then
    echo "You must have a .env file to run this script!"
    echo "See .env.example for an example."
    echo "Use cp .env.example .env to create a .env file."
    exit 1
fi

docker compose up -d && echo "Postgres running on 127.0.0.1:5432"
python -m scripts.seed && echo "Admin and user accounts created"
uvicorn app.main:app --host 127.0.0.1 --port 8000
echo "Backend running on http://127.0.0.1:8000"
echo "Ctrl+C to stop."
