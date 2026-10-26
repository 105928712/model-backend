# common.py
# 2026 Joey Manani & Anchorfish Team
# Shared bits for the red-team scripts: tiny HTTP client, login, verdict printer

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DEFAULT_BASE = "http://127.0.0.1:8000" # default server to attack (set in main.py)


def base_url() -> str:
    """Server to attack. --base <url> wins, else REDTEAM_BASE env, else default."""
    if "--base" in sys.argv:
        return sys.argv[sys.argv.index("--base") + 1].rstrip("/") # any child can use --base <url> to override
    return os.environ.get("REDTEAM_BASE", DEFAULT_BASE).rstrip("/")


def request(method: str, path: str, body: dict | None = None, token: str | None = None) -> tuple[int, object]:
    """One HTTP call. Returns (status_code, parsed_json_or_raw_text). Never raises on 4xx/5xx."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base_url() + path, data=data, headers=headers, method=method)
    
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, _parse(response.read(), response.headers)
    except urllib.error.HTTPError as error: # don't care, want response anyways
        return error.code, _parse(error.read(), error.headers)


def _parse(raw: bytes, headers) -> object:
    text = raw.decode(errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


# shortcuts for common methods
def get(path, token=None):            return request("GET", path, token=token)
def post(path, body, token=None):     return request("POST", path, body=body, token=token)
def delete(path, token=None):         return request("DELETE", path, token=token)


def login(username: str, password: str) -> str | None:
    """Returns a bearer token, or None if the login was rejected."""
    status, body = post("/api/login", {"username": username, "password": password})
    return body["access_token"] if status == 200 and isinstance(body, dict) else None


def seed_password(username: str) -> str:
    """The seeded password for a demo account, from .env (e.g. SEED_JOEY_PASSWORD)."""
    key = f"SEED_{username.upper()}_PASSWORD"
    password = os.environ.get(key)
    if not password:
        sys.exit(f"{key} is not set in .env - seed the database first (python -m scripts.seed)")
    return password


def verdict(attack: str, vulnerable: bool, evidence: str) -> None:
    """Print the one line that matters for the report, then the evidence."""
    tag = "ATTACK SUCCEEDED - vulnerable" if vulnerable else "ATTACK BLOCKED - defended"
    print(f"\n[{tag}]  {attack}\n  {evidence}\n")
