# database.py
# 2026 Joey Manani & Anchorfish Team
# Connection to Postgres

from sqlalchemy import create_engine
from .settings import DATABASE_URL

engine = create_engine(DATABASE_URL)
