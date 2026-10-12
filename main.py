# Joey Manani & Anchorfish Team 2026
# main.py


"""
Provide an API to the frontend to interact with the model and the database.

FastAPI will be used along with Pydantic and a SQLite database.

I will probably also make a docker container for this too and make this publicly available.

We will be doing every security method outlined by Assignment 3.

API Contacts are still to be decided.

This API will follow REST and OOP practices, taking data in as JSON and returning JSON.

We will be using real HTTP methods, status codes and headers.

Authentication will be done using JWT tokens.

User accounts will be stored in the database. 

We will need to also design the database schema too to handle these things.

Security comes first, speed second.
"""

import fastapi
# import pydantic
# import sqlite3
# import jwt
import dotenv
import uvicorn
import joblib
from pathlib import Path
import pandas as pd
import os
import sys


HERE = Path(__file__).parent
sys.path.append(str(HERE.parent / "feature-extraction"))

import features
from features.utils import canonical_url

dotenv.load_dotenv()

THRESHOLD = 0.35  # chosen for HGB on its own in classification_final.ipynb section 4

hgb = joblib.load(HERE / "models" / "final_hgb.joblib")  # HistogramGradientBoosting


def phishing_probability(url: str) -> float:
    """Return probability of phishing from a given URL in the form of a float"""

    clean = canonical_url(url) # cleans out www, scheme, trailing slash
    row = pd.DataFrame([features.extract_features(clean)])[hgb.feature_names_in_] # unpack what the feature extraction function returns into a dataframe, also removes features model wasn't trained on: tld and root_domain (text features)

    return hgb.predict_proba(row)[0, 1] # P(phishing) from HGB


if __name__ == "__main__":
    app = fastapi.FastAPI(
        title="Anchorfish Model Backend",
        description="API for the Anchorfish model",
        version="0.1.0",
        contact={
            "name": "Joey Manani",
            "email": "joeymanani@theflyingrat.com",
        },
    )

    @app.get("/")
    def index():
        return "It works!"
    
    @app.get("/predict")
    def predict(url: str):
        prob = phishing_probability(url)
        classification = "Phishing" if prob > THRESHOLD else "Legitimate"
        return {"url": url, "phishing_probability": prob, "classification": classification}

    uvicorn.run(app, host="0.0.0.0", port=8000)
    print("Server is running on http://0.0.0.0:8000")