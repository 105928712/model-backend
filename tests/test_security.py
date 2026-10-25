# test_security.py
# 2026 Joey Manani & Anchorfish Team
# Each defence stops its attack (the defence is on, as shipped)

import jwt
import pytest
from datetime import UTC, datetime, timedelta
from app import model as model_module, settings
from app.model import load_model
from app.security import limiter
from conftest import bearer

GOOD_ORIGIN = "http://localhost:5173"


def test_cors_only_answers_the_front_end(client):
    assert client.get("/api/health", headers={"Origin": GOOD_ORIGIN}).headers["Access-Control-Allow-Origin"] == GOOD_ORIGIN
    assert "Access-Control-Allow-Origin" not in client.get("/api/health", headers={"Origin": "https://evil.example"}).headers
    preflight = client.options("/api/check", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert preflight.status_code == 400


def test_sql_injection_login_fails(client):
    response = client.post("/api/login", json={"username": "' OR '1'='1", "password": "anything"})
    assert response.status_code == 401


def test_login_does_not_reveal_which_usernames_exist(client):
    unknown = client.post("/api/login", json={"username": "ahdbfsljiknas", "password": "wrong password!"})
    wrong_password = client.post("/api/login", json={"username": "admin", "password": "wrong password!"})
    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()


def token(secret: str, minutes: int = 30) -> str:
    now = datetime.now(UTC)
    return jwt.encode({"sub": "1", "role": "admin", "iat": now, "exp": now + timedelta(minutes=minutes)}, secret, algorithm="HS256")


def test_forged_token_is_401(client):
    forged = token("a different secret that is long enough to use (faked by a user)")
    assert client.get("/api/me", headers=bearer(forged)).status_code == 401


def test_expired_real_token_is_401(client):
    assert client.get("/api/me", headers=bearer(token(settings.JWT_SECRET, minutes=-1))).status_code == 401


def test_role_comes_from_the_database_not_the_token(client, users):
    """Ensure the user's role is fetched from the database (i.e user 1 is admin, database knows. API shouldn't assume admin must mean the ID is admin by default)"""
    me = client.get("/api/me", headers=users[0]).json()
    claims = {"sub": str(me["id"]), "role": "admin", "exp": datetime.now(UTC) + timedelta(minutes=5)}
    promoted = bearer(jwt.encode(claims, settings.JWT_SECRET, algorithm="HS256"))
    assert client.get("/api/models", headers=promoted).status_code == 403

1
def test_login_rate_limit(client):
    limiter.enabled = True
    limiter.reset()
    try:
        statuses = [client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code for _ in range(6)]
        assert statuses == [401] * 5 + [429]
        # 5 bad password logins should cause a 429
        blocked = client.post("/api/login", json={"username": "admin", "password": "wrong"})
        assert int(blocked.headers["Retry-After"]) > 0
        assert blocked.json()["error"]["status"] == 429
    finally:
        limiter.enabled = False
        limiter.reset()


def test_tampered_model_file_is_refused(monkeypatch, tmp_path):
    """Monkey patch in a new fake model file"""
    for file in model_module.MODELS_DIRECTORY.glob("*.joblib"):
        (tmp_path / file.name).write_bytes(file.read_bytes() + b"tampered")
    monkeypatch.setattr(model_module, "MODELS_DIRECTORY", tmp_path)
    with pytest.raises(ValueError, match="Hash mismatch"):
        load_model()


