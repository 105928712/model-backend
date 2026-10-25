# settings.py
# 2026 Joey Manani & Anchorfish Team
# load settings from .env

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DATABASE_URL: str = os.environ["DATABASE_URL"]
JWT_SECRET: str   = os.environ["JWT_SECRET"]
JWT_MINUTES: int  = int(os.environ.get("JWT_MINUTES", "30"))

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET in .env must be at least 32 characters")

# comma separated exact origins of the front end, e.g. http://localhost:5173
CORS_ORIGINS: list[str] = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

if "*" in CORS_ORIGINS:
    raise RuntimeError("CORS_ORIGINS must list exact origins, not *")

# requests per IP per minute; the off switches are for the before/after evidence runs
RATE_LIMIT: int            = int(os.environ.get("RATE_LIMIT", "60"))
LOGIN_RATE_LIMIT: int      = int(os.environ.get("LOGIN_RATE_LIMIT", "5"))


# security flags
RATE_LIMIT_ENABLED: bool   = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
LOGIN_TIMING_DEFENCE: bool = os.environ.get("LOGIN_TIMING_DEFENCE", "true").lower() == "true"
MODEL_HASH_CHECK: bool     = os.environ.get("MODEL_HASH_CHECK", "true").lower() == "true"
SQLI_DEFENCE: bool         = os.environ.get("SQLI_DEFENCE", "true").lower() == "true"


# For mass checking (logged in users): set BATCH_CONCURRENCY very high to switch the cap off for the DoS before/after runs
BATCH_MAX_URLS: int        = int(os.environ.get("BATCH_MAX_URLS", "100"))
BATCH_CONCURRENCY: int     = int(os.environ.get("BATCH_CONCURRENCY", "4"))
