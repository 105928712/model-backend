# auth.py
# 2026 Joey Manani & Anchorfish Team

import jwt
from datetime import UTC, datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from .database import engine
from .schemas import UserInfo
from .settings import JWT_MINUTES, JWT_SECRET, LOGIN_TIMING_DEFENCE

hasher     = PasswordHasher()               # argon2id using defaults
bearer     = HTTPBearer(auto_error=False)   # reads "Authorization: Bearer <token>" else none
DUMMY_HASH = hasher.hash("ilovesienna")     # verified against when the username doesn't exist


def hash_password(password: str) -> str:
    return hasher.hash(password)


def password_matches(password_hash: str | None, password: str) -> bool:
    """Returns True if the password matches the hash, False otherwise. Runs argon2 on the dummy hash if the user doesn't exist to prevent timing attacks"""
    if password_hash is None:
        if LOGIN_TIMING_DEFENCE:
            password_matches(DUMMY_HASH, password)
        return False
    try:
        return hasher.verify(password_hash, password)
    except VerificationError:
        return False


#########################################


def create_token(user_id: int, role: str) -> str:
    """Returns JWT token for the given user"""
    now = datetime.now(UTC)
    # sub = Subject, iat = Issued at, exp = Expiry - Standard JWT claims
    claims = {"sub": str(user_id), "role": role, "iat": now, "exp": now + timedelta(minutes=JWT_MINUTES)}
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256") # HMAC SHA256 - Arguably the best one here


def unauthorised(message: str) -> HTTPException:
    return HTTPException(401, message, headers={"WWW-Authenticate": "Bearer"})


def optional_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> UserInfo | None:
    """The signed-in user, or None if no token was sent - bad token rejected"""
    if credentials is None:
        return None
    try:
        # Force HMAC SHA256 decode (user cannot modify the token) and need decode subject and expiry
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"], options={"require": ["sub", "exp"]})
    except jwt.InvalidTokenError as e:
        raise unauthorised("Token invalid") from e

    with engine.connect() as db:
        # mappings to out to a keyable array
        user = db.execute(text("SELECT id, username, role, created_at FROM users WHERE id = :id"), {"id": int(claims["sub"])}).mappings().first()
    if user is None:
        raise unauthorised("Account does not exist")
    return UserInfo(**user)


def required_user(user: UserInfo | None = Depends(optional_user)) -> UserInfo:
    if user is None:
        raise unauthorised("Sign in to access this resource")
    return user


def admin_user(user: UserInfo = Depends(required_user)) -> UserInfo:
    """Role is read from the database (optional_user), not trusted from the token"""
    if user.role != "admin":
        raise HTTPException(403, "Admins only")
    return user
