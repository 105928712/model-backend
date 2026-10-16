# Joey Manani & Anchorfish Team 2026
# main.py


"""
Provide an API to the frontend to interact with the model and the database.

FastAPI will be used along with Pydantic and a PostgreSQL database in Docker.

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

from fastapi import FastAPI, Request
from .model import PhishingModel, load_model

model: PhishingModel = load_model()


app = FastAPI(
    title="Anchorfish Model Backend",
    description="API for the Anchorfish model",
    version="0.1.0",
    contact={"name": "Joey Manani", "email": "joeymanani@theflyingrat.com"}
)


@app.get("/api/health")
def health(request: Request) -> dict[str, str]:
    return {"status": "ok", "model": model.name}


@app.get("/api/predict")
def predict(url: str, request: Request) -> dict[str, str | float]:
    prediction = model.predict(url)
    return {"url": url, "probability": prediction.probability, "label": prediction.label}
