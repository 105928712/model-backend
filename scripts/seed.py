# seed.py
# 2026 Joey Manani & Anchorfish Team
# Seed db with users and an admin account and fake history
# Usage: python -m scripts.seed

import os
import secrets
from dotenv import set_key
from psycopg.types.json import Jsonb
from sqlalchemy import text
from app.auth import hash_password
from app.database import engine
from app.model import PhishingModel, load_model
from app.preprocessing import url_features
from app.settings import ENV_FILE

SAMPLE_URLS: list[str] = ["google.com", "en.wikipedia.org/wiki/Phishing", "paypal-account-verify.top/login", "secure-update-bank.xyz/signin.php?id=123123"]


MODELS = [("final_hgb", "final_hgb.joblib", "f38ef340afd563da93bbcdd04ec71c0e1abd7c3ca40067e969923048b134f4ca", 0.35),
          ("final_nb_3to5", "final_nb_3to5.joblib", "c8e7aae59b6b1448fb877796509f76b5c4e52bf56b85b546c414da1fa33c4cec", 0.5)]

with engine.begin() as db:
    for name, file, sha256, threshold in MODELS:
        db.execute(text("INSERT INTO models (name, file, sha256, threshold, active) VALUES (:name, :file, :sha256, :threshold, :active) ON CONFLICT (name) DO NOTHING"),
                   {"name": name, "file": file, "sha256": sha256, "threshold": threshold, "active": name == MODELS[0][0]})

model: PhishingModel = load_model()

# username, role. Each password comes from SEED_<USERNAME>_PASSWORD in .env
accounts = [("admin", "admin"), ("user", "user"), ("joey", "user"), ("sienna", "user"), ("luke", "user")]


with engine.begin() as db:
    for username, role in accounts:
        key = f"SEED_{username.upper()}_PASSWORD"
        given = os.environ.get(key)
        password = given or secrets.token_urlsafe(12) # random if none given

        user_id = db.execute(text("INSERT INTO users (username, role, password_hash) VALUES (:username, :role, :password_hash) ON CONFLICT (username) DO NOTHING RETURNING id"), {"username": username, "role": role, "password_hash": hash_password(password)}).scalar()
        if user_id is None:
            print(f"{username} already exists! Skipping...")
            continue

        if given:
            print(f"Created {username} - {role}")
        else:
            set_key(ENV_FILE, key, password, quote_mode="never")
            print(f"Created {username} - {role}, password {password} (saved to .env as {key})")

        # fake history
        if role == "user":
            for url in SAMPLE_URLS:
                prediction = model.predict(url)
                db.execute(text("INSERT INTO checks (user_id, url, probability, label, model_name, features) VALUES (:user_id, :url, :probability, :label, :model_name, :features)"), {"user_id": user_id, "url": url, "probability": prediction.probability, "label": prediction.label, "model_name": model.name, "features": Jsonb(url_features(url))})


