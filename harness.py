# harness.py
# 2026 Joey Manani & Anchorfish Team
#
# Project utility for the security evaluation notebooks (and anything else that wants to
# drive a live server): start and stop the API on a spare port (8001) with chosen defence
# flags, bring up the database, and a tiny HTTP client


import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PORT = 8001
BASE = f"http://127.0.0.1:{PORT}"
BACKEND = Path(__file__).resolve().parent           # model-backend/
PYTHON = sys.executable                             # the venv running the caller


def request(method: str, path: str, body: dict | None = None, token: str | None = None) -> tuple[int, object, float]:
    """One HTTP call to the test server. Returns (status, parsed_body, elapsed_ms). Never raises on 4xx/5xx"""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    except (urllib.error.URLError, http.client.IncompleteRead, ConnectionError, TimeoutError) as error:
        # the server dropped or truncated the reply, which under a flood is itself a symptom
        return 0, f"<request failed: {type(error).__name__}>", (time.perf_counter() - start) * 1000
    elapsed_ms = (time.perf_counter() - start) * 1000
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")
    return status, parsed, elapsed_ms

#########################################

def get(path: str, token: str | None = None) -> tuple[int, object, float]:
    return request("GET", path, token=token)

def post(path: str, body: dict, token: str | None = None) -> tuple[int, object, float]:
    return request("POST", path, body=body, token=token)

def delete(path: str, token: str | None = None) -> tuple[int, object, float]:
    return request("DELETE", path, token=token)

#########################################

def login(username: str, password: str) -> str | None:
    """A bearer token, or None if the login was rejected."""
    status, body, _ = post("/api/login", {"username": username, "password": password})
    return body["access_token"] if status == 200 and isinstance(body, dict) else None


def wait_health(timeout: float = 45) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(BASE + "/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError):
            time.sleep(0.3)
    return False

def start_server(**flags: object) -> subprocess.Popen:
    """Start uvicorn on PORT with the given settings flags (e.g. ACCESS_CONTROL=False). Waits until healthy."""
    env = {**os.environ, "RATE_LIMIT_ENABLED": "false"}   # no 429s to pollute the runs
    env.update({k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in flags.items()})
    log = tempfile.NamedTemporaryFile("w+", suffix="-uvicorn.log", delete=False)
    proc = subprocess.Popen(
        [PYTHON, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(PORT), "--log-level", "warning"],
        cwd=BACKEND, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    if not wait_health():
        proc.terminate()
        raise RuntimeError(f"server did not come up on :{PORT}\n--- server log ---\n{Path(log.name).read_text()[-2000:]}")
    return proc

def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

def ensure_db() -> None:
    """Bring up Postgres and seed, idempotently. Call once at the top of a notebook."""
    subprocess.run(["docker", "compose", "up", "-d"], cwd=BACKEND, check=True)
    for _ in range(10):
        if subprocess.run([PYTHON, "-m", "scripts.seed"], cwd=BACKEND, check=False).returncode == 0:
            return
        time.sleep(1.5)
    raise RuntimeError("seed never succeeded - is Docker running?")

