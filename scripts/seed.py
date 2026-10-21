# seed.py
# 2026 Joey Manani & Anchorfish Team
# Seed db with users and an admin account and fake history
# Usage: python -m scripts.seed

import os
from sqlalchemy import text
from app.auth import hash_password
from app.database import engine
from app.model import PhishingModel, load_model

SAMPLE_URLS: list[str] = ["google.com", "en.wikipedia.org/wiki/Phishing", "paypal-account-verify.top/login", "secure-update-bank.xyz/signin.php?id=123123"]


MODELS = [("final_hgb", "final_hgb.joblib", "3b61eeded36c3f6f6dc05655426aaf4db43ccb17feb255b58ef5900630de3929", 0.35),
          ("final_nb_3to5", "final_nb_3to5.joblib", "c8e7aae59b6b1448fb877796509f76b5c4e52bf56b85b546c414da1fa33c4cec", 0.5)]

with engine.begin() as db:
    for name, file, sha256, threshold in MODELS:
        db.execute(text("INSERT INTO models (name, file, sha256, threshold, active) VALUES (:name, :file, :sha256, :threshold, :active) ON CONFLICT (name) DO NOTHING"),
                   {"name": name, "file": file, "sha256": sha256, "threshold": threshold, "active": name == MODELS[0][0]})

model: PhishingModel = load_model()

# username, role, password
accounts = [("admin", "admin", os.environ["SEED_ADMIN_PASSWORD"]),
            ("user", "user", os.environ["SEED_USER_PASSWORD"]),
            ("joey", "user", os.environ["SEED_JOEY_PASSWORD"]),
            ("sienna", "user", os.environ["SEED_SIENNA_PASSWORD"]),
            ("luke", "user", os.environ["SEED_LUKE_PASSWORD"])]



with engine.begin() as db:
    for username, role, password in accounts:
        user_id = db.execute(text("INSERT INTO users (username, role, password_hash) VALUES (:username, :role, :password_hash) ON CONFLICT (username) DO NOTHING RETURNING id"), {"username": username, "role": role, "password_hash": hash_password(password)}).scalar()
        if user_id is None:
            print(f"{username} already exists! Skipping...")
            continue

        print(f"Created {username} - {role}")

        # fake history
        if role == "user":
            for url in SAMPLE_URLS:
                prediction = model.predict(url)
                db.execute(text("INSERT INTO checks (user_id, url, probability, label, model_name) VALUES (:user_id, :url, :probability, :label, :model_name)"), {"user_id": user_id, "url": url, "probability": prediction.probability, "label": prediction.label, "model_name": model.name})


