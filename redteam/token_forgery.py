# token_forgery.py
# 2026 Joey Manani & Anchorfish Team
#
# Attack: forge a JWT to become admin. Two angles, both always defended
#
#   1. Sign a token with a guessed secret claiming role=admin -> rejected, signature is checked.
#   2. Log in as a normal user, mint a VALIDLY signed token claiming role=admin -> still blocked,
#      because the server reads the role from the database. Token alone is not enough
#
# 2 should be impossible in the real world unless the token is stolen or compromised
#
# Usage: python -m redteam.token_forgery

from datetime import UTC, datetime, timedelta

import jwt

from app.auth import create_token          # the server's real token (same secret)
from redteam.common import get, login, seed_password, verdict

WRONG_SECRET = "attacker-guess-that-is-at-least-thirty-two-chars-long" # 32 chars is the minimum length for a JWT secret for server to validate

def forged_with_wrong_secret() -> None:
    claims = {"sub": "1", "role": "admin", "iat": datetime.now(UTC), "exp": datetime.now(UTC) + timedelta(minutes=30)}
    forged = jwt.encode(claims, WRONG_SECRET, algorithm="HS256")
    status, _ = get("/api/me", token=forged)
    verdict(
        "Forged JWT signed with a guessed secret",
        vulnerable=status == 200,
        evidence=f"HTTP {status} on /api/me - {'accepted the forgery' if status == 200 else 'rejected, signature was trusted'}",
    )

def valid_signature_but_lying_role() -> None:
    token = login("joey", seed_password("joey"))
    if token is None: return print("  (skipped role test: could not log in as joey - seed the database first)")
    
    me = get("/api/me", token=token)[1]
    promoted = create_token(me["id"], "admin")       # correctly signed, but claims admin for a normal user
    status, _ = get("/api/models", token=promoted)   # admin-only endpoint
    verdict(
        "Privilege escalation via a real signed token claiming role=admin",
        vulnerable=status == 200,
        evidence=f"HTTP {status} on admin-only /api/models - {'trusted the token role' if status == 200 else 'blocked, role read from the database'}",
    )

def run() -> None:
    forged_with_wrong_secret()
    valid_signature_but_lying_role()

if __name__ == "__main__":
    run()
