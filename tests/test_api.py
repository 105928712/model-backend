# test_api.py
# 2026 Joey Manani & Anchorfish Team
# Endpoints, status codes




import pytest
from fastapi.testclient import TestClient
from app import main
from app.main import app


def assert_error(response, status: int) -> dict:
    """Every error is {"error": {"status", "message", "details"}} and nothing else"""
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"status", "message", "details"}
    assert body["error"]["status"] == status
    return body["error"]


def test_health_and_model(client):
    """Default model"""
    assert client.get("/api/health").json() == {"status": "ok", "model": "final_hgb"}
    assert client.get("/api/model").json() == {"name": "final_hgb", "threshold": 0.35}


def test_check_scores_a_url(client):
    """Does the model even score?"""
    result = client.post("/api/check", json={"url": "paypal-account-verify.top/login"}).json()
    assert result["label"] == "phishing" and result["risk_band"] == "high"
    assert result["probability"] > result["threshold"]
    assert result["features"]["tld"] == "top"


def test_check_flags_urls_outside_training(client):
    """Too long string"""
    result = client.post("/api/check", json={"url": "example.notarealtld/" + "a" * 1000}).json()
    assert result["outside_training_domain"] is True
    assert set(result["warnings"]) == {"unknown_suffix", "longer_than_training_urls"}


@pytest.mark.parametrize("body", [
    {"url": "   "},
    {"url": "http://"},                           # no host
    {"url": "a.com/" + "pineapple" * 228},        # over MAX_URL_LENGTH
    {"url": "google.com", "extra": 1},            # unknown fields are refused
])
def test_bad_check_input_is_422_naming_the_field(client, body):
    error = assert_error(client.post("/api/check", json=body), 422)
    assert error["details"] and all(detail["field"].startswith("body") for detail in error["details"])


def test_not_json_is_422(client):
    assert_error(client.post("/api/check", content="url=google.com", headers={"Content-Type": "application/json"}), 422)


def test_unknown_route_and_wrong_method_use_the_error_shape(client):
    """Validate error shape for unknown routes and wrong methods"""
    assert_error(client.get("/api/nope"), 404)
    assert_error(client.delete("/api/health"), 405)


def test_body_over_the_cap_is_413(client):
    """Force a really long body"""
    assert client.post("/api/check", content=b'{"url": "' + b"a" * 20_000 + b'"}', headers={"Content-Type": "application/json"}).status_code == 413


def test_failing_model_is_a_clean_500(client, monkeypatch):
    class BrokenModel:
        name, threshold = "broken", 0.5

        def predict_many(self, urls):
            raise RuntimeError("don't tell the user but (secret): sometimes i eat an entire pack of tim tams myself")

    monkeypatch.setattr(app.state, "model", BrokenModel())
    response = TestClient(app, raise_server_exceptions=False).post("/api/check", json={"url": "google.com"})
    error = assert_error(response, 500)
    assert error["message"] == "Something went wrong"
    assert "secret" not in response.text and "Traceback" not in response.text # 500 errors only visible to us, NEVER the client


def test_batch_keeps_order_and_names_the_bad_url(client):
    urls = ["google.com", "paypal-account-verify.top/login", "en.wikipedia.org/wiki/Phishing"]
    results = client.post("/api/check/batch", json={"urls": urls}).json()
    assert [r["url"] for r in results] == urls

    error = assert_error(client.post("/api/check/batch", json={"urls": ["google.com", "http://"]}), 422)
    assert error["details"][0]["field"] == "body.urls.1"


def test_batch_size_limits(client):
    assert_error(client.post("/api/check/batch", json={"urls": []}), 422)
    assert_error(client.post("/api/check/batch", json={"urls": ["google.com"] * (main.BATCH_MAX_URLS + 1)}), 422)


def test_full_batch_of_long_urls_fits_the_batch_body_cap(client):
    urls = [f"example{i}.com/" + "a" * 200 for i in range(main.BATCH_MAX_URLS)]  # about 21 KB, over the single-URL cap
    response = client.post("/api/check/batch", json={"urls": urls})
    assert response.status_code == 200, response.text
    assert len(response.json()) == main.BATCH_MAX_URLS


def test_batch_is_503_when_every_slot_is_busy(client, monkeypatch):
    class Full: # mock a semaphore that's always full
        def acquire(self, blocking): return False

    monkeypatch.setattr(main, "batch_slots", Full())
    response = client.post("/api/check/batch", json={"urls": ["google.com"]})
    assert_error(response, 503)
    assert response.headers["Retry-After"] == "5"


def test_signed_in_checks_go_to_history_and_only_the_owner_sees_them(client, users):
    owner, other = users
    client.post("/api/check", json={"url": "secure-update-bank.xyz/signin.php"}, headers=owner)
    latest = client.get("/api/history", headers=owner).json()[0]
    assert latest["url"] == "secure-update-bank.xyz/signin.php"
    # history shows yes

    path = f"/api/history/{latest['id']}"
    assert client.get(path, headers=owner).json() == latest
    assert_error(client.get(path, headers=other), 404)      # someone else's record looks the same as no record (security !)
    assert_error(client.delete(path, headers=other), 404)   # we cannot delete something that "doesn't exist..."
    assert client.delete(path, headers=owner).status_code == 204 # but the owner can!
    assert_error(client.get(path, headers=owner), 404)



def test_anonymous_checks_are_not_saved_and_history_needs_sign_in(client):
    assert client.post("/api/check", json={"url": "google.com"}).status_code == 200
    assert_error(client.get("/api/history"), 401)





def test_admin_routes(client, users, admin):
    assert_error(client.get("/api/models"), 401)
    assert_error(client.get("/api/models", headers=users[0]), 403)
    models = client.get("/api/models", headers=admin).json()
    assert {"name": "final_hgb", "threshold": 0.35, "active": True} in models
    assert_error(client.put("/api/model", json={"name": "no_such_model"}, headers=admin), 404)
    assert_error(client.put("/api/model", json={"name": "final_hgb"}, headers=users[0]), 403)

