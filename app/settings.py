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
