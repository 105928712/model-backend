# conftest.py
# 2026 Joey Manani & Anchorfish Team

import os
import secrets
from collections.abc import Iterator

os.environ["RATE_LIMIT_ENABLED"] = "false"  # required here

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.database import engine
from app.main import app

PASSWORD = "sienna is my favourite person"

@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    with TestClient(app) as client:  # context manager lifecycle to hold model
        yield client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return bearer(response.json()["access_token"])


@pytest.fixture(scope="session")
def users(client: TestClient) -> Iterator[tuple[dict[str, str], dict[str, str]]]:
    """Create two throwaway accounts and delete them afterwards"""
    names = [f"test_{secrets.token_hex(4)}" for _ in range(2)]

    for name in names:
        assert client.post("/api/register", json={"username": name, "password": PASSWORD}).status_code == 201
    yield tuple(login(client, name, PASSWORD) for name in names)
    with engine.begin() as db:
        db.execute(text("DELETE FROM users WHERE username = ANY(:names)"), {"names": names})


@pytest.fixture(scope="session")
def admin(client: TestClient) -> dict[str, str]: 
    return login(client, "admin", os.environ["SEED_ADMIN_PASSWORD"]) # relies on seeding to db

#