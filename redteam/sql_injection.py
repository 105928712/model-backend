# sql_injection.py
# 2026 Joey Manani & Anchorfish Team

# Attack: classic auth bypass - paste ' OR '1'='1 into the username
# Toggle for before/after evidence: SQLI_DEFENCE=false in .env
# Usage: python -m redteam.sql_injection

from redteam.common import post, verdict


PAYLOAD = "' OR '1'='1"


def run() -> None:
    status, body = post("/api/login", {"username": PAYLOAD, "password": "not their password"})
    got_token = status == 200 and isinstance(body, dict) and "access_token" in body
    verdict(
        f"SQL injection login bypass with username {PAYLOAD!r}",
        vulnerable=got_token,
        evidence=f"HTTP {status} - {'logged in without a valid password (token issued)' if got_token else 'rejected! secure!'}",
    )


if __name__ == "__main__":
    run()