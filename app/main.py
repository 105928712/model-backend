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

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from .auth import admin_user, create_token, hash_password, optional_user, password_matches, required_user, unauthorised
from .database import engine
from .errors import add_error_handlers, error_responses
from .globals import BATCH_RETRY_AFTER, MAX_BODY_BYTES
from .model import PhishingModel, load_model
from .preprocessing import url_features
from .security import add_security, login_limit
from .schemas import BatchRequest, CheckRequest, CheckResult, Credentials, Health, HistoryItem, LoginCredentials, ModelChoice, ModelInfo, ModelOption, Token, UserInfo
from .settings import BATCH_CONCURRENCY, BATCH_MAX_URLS, SQLI_DEFENCE
from .utils import training_domain_warnings, risk_band

logger = logging.getLogger("uvicorn.error")  # uvicorn's logger, so the startup line shows in the console


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Load the model once at startup (hash checked), not per request"""
    app.state.model = load_model()
    logger.info(f"Model {app.state.model.name} loaded")
    yield # yield model to caller as context manager
    # Implied destruction here


def current_model(request: Request) -> PhishingModel:
    return request.app.state.model


def score(urls: list[str], model: PhishingModel) -> list[CheckResult]:
    """Score URLs in one model call and build the full result for each
    Also works with a single URL since zip will take a single URL as an iterable"""
    results = []
    for url, prediction in zip(urls, model.predict_many(urls), strict=True):
        warnings = training_domain_warnings(url)
        results.append(CheckResult(
            url=url,
            model=model.name,
            probability=prediction.probability,
            threshold=model.threshold,
            label=prediction.label,
            risk_band=risk_band(prediction.probability, model.threshold),
            outside_training_domain=bool(warnings),
            warnings=warnings,
            features=url_features(url),
        ))
    return results


def save_checks(user: UserInfo | None, results: list[CheckResult]) -> None:
    """A signed-in user's checks go to their history, anonymous checks are not stored"""
    if user is None:
        return
    with engine.begin() as db:
        db.execute(
            text("INSERT INTO checks (user_id, url, probability, label, model_name) VALUES (:user_id, :url, :probability, :label, :model_name)"),
            [{"user_id": user.id, "url": r.url, "probability": r.probability, "label": r.label, "model_name": r.model} for r in results],
        )


# how many batches may be scored at once or the rest get a 503 OVERLOADED instead of queueing
batch_slots = threading.BoundedSemaphore(BATCH_CONCURRENCY)

# set range of check ids to be valid to 2^31 which is the database max value
CheckId = Path(ge=1, le=2**31 - 1, description="The id of a saved check, from GET /api/history")


app = FastAPI(
    lifespan=lifespan, # lifespan ctxmanager to load model once at startup and destroy it at shutdown
    title="Anchorfish Model Backend",
    description="API for the Anchorfish model",
    version="0.1.0",
    contact={"name": "Joey Manani", "email": "joeymanani@theflyingrat.com"},
    responses=error_responses(429, 500), # any route can be rate limited or fail
)
add_error_handlers(app)
add_security(app)


@app.get("/api/health")
def health(model: PhishingModel = Depends(current_model)) -> Health:
    """Is the server up, and which model did it load"""
    return Health(status="ok", model=model.name)


@app.get("/api/model")
def model_info(model: PhishingModel = Depends(current_model)) -> ModelInfo:
    """The model answering checks and its threshold: above the threshold is labelled phishing"""
    return ModelInfo(name=model.name, threshold=model.threshold)


@app.get("/api/models", responses=error_responses(401, 403))
def models(admin: UserInfo = Depends(admin_user)) -> list[ModelOption]:
    """Admin: the predefined models the server may switch to, and which one is answering"""
    with engine.connect() as db:
        rows = db.execute(text("SELECT name, threshold, active FROM models ORDER BY name")).mappings()
        return [ModelOption(**row) for row in rows]


@app.put("/api/model", responses=error_responses(401, 403, 404, 422))
def switch_model(request: Request, choice: ModelChoice, admin: UserInfo = Depends(admin_user)) -> ModelInfo:
    """Admin: switch the model answering checks to one from GET /api/models"""
    try:
        new_model = load_model(choice.name)
    except KeyError as e:
        raise HTTPException(404, "No such model in the registry") from e
    with engine.begin() as db:  # atomic
        db.execute(text("UPDATE models SET active = false WHERE active"))
        db.execute(text("UPDATE models SET active = true WHERE name = :name"), {"name": new_model.name})

    request.app.state.model = new_model 
    logger.info(f"Admin {admin.username} switched the model to {new_model.name}")
    return ModelInfo(name=new_model.name, threshold=new_model.threshold)


@app.post("/api/check", responses=error_responses(401, 413, 422))
def check(request: CheckRequest, user: UserInfo | None = Depends(optional_user), model: PhishingModel = Depends(current_model)) -> CheckResult:
    """Score a URL. Anyone can check, a signed-in user's checks are also saved to their history."""
    results = score([request.url], model)
    save_checks(user, results)
    return results[0]


# Uses a semaphore to limit the number of batches that can be scored at once (DoS protection)
@app.post("/api/check/batch", responses=error_responses(401, 413, 422, 503), description=(
    f"Score up to {BATCH_MAX_URLS} URLs at once, results in the same order as sent. Signed-in users get every check saved. "
    f"Only {BATCH_CONCURRENCY} batches run at a time; when every slot is busy the server answers 503 with Retry-After..."))
def check_batch(request: BatchRequest, user: UserInfo | None = Depends(optional_user), model: PhishingModel = Depends(current_model)) -> list[CheckResult]:
    if not batch_slots.acquire(blocking=False):
        raise HTTPException(503, "Server is busy with other batches, try again shortly", headers={"Retry-After": str(BATCH_RETRY_AFTER)})
    try:
        results = score(list(request.urls), model)
    finally:
        batch_slots.release()
    save_checks(user, results)
    return results


@app.post("/api/register", status_code=201, responses=error_responses(409, 422))
@login_limit
def register(request: Request, credentials: Credentials) -> UserInfo:
    """Create an account. Username is 3 to 32 letters, numbers or underscores (stored lowercase), password 12 to 128 characters"""
    try:
        with engine.begin() as db:
            user = db.execute(
                text("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash) RETURNING id, username, role, created_at"),
                {"username": credentials.username, "password_hash": hash_password(credentials.password)},
            ).mappings().one()
    except IntegrityError as e:   # the UNIQUE on username
        raise HTTPException(409, "Username is taken") from e
    return UserInfo(**user) # unpack user obj --> new UserInfo obj


@app.post("/api/login", responses=error_responses(401, 422))
@login_limit
def login(request: Request, credentials: LoginCredentials) -> Token:
    """Login with username/password. Client shall now send Authorization: Bearer <token>"""
    if not SQLI_DEFENCE:
        # SQL injection demo. The username is pasted straight into the SQL and any returned row is treated as 
        # authenticated (no password check), so  ' OR '1'='1' logs in as the first user. 
        with engine.connect() as db:
            user = db.execute(text(f"SELECT id, role, password_hash FROM users WHERE username = '{credentials.username}'")).mappings().first()
        if user is None:
            raise unauthorised("Wrong username or password - (SQL injection demo - I never checked the password!)")
        return Token(access_token=create_token(user["id"], user["role"]))

    with engine.connect() as db:
        user = db.execute(text("SELECT id, role, password_hash FROM users WHERE username = :username"), {"username": credentials.username}).mappings().first()

    # Cyber 101: Same message for both, so the response doesn't reveal which usernames exist
    # unknown users still get a full hash check (dummy hash) so timing matches too
    if not password_matches(user["password_hash"] if user else None, credentials.password) or user is None:
        raise unauthorised("Wrong username or password")

    # Create a new token for the user
    return Token(access_token=create_token(user["id"], user["role"]))


@app.get("/api/me", responses=error_responses(401))
def me(user: UserInfo = Depends(required_user)) -> UserInfo:
    """The signed-in account"""
    return user


@app.get("/api/history", responses=error_responses(401, 422))
def history(user: UserInfo = Depends(required_user), limit: int = Query(20, ge=1, le=100)) -> list[HistoryItem]:
    """The signed-in user's history, ordered by latest to oldest"""
    with engine.connect() as db:
        rows = db.execute(text("SELECT id, url, probability, label, model_name, created_at FROM checks WHERE user_id = :user_id ORDER BY created_at DESC, id DESC LIMIT :limit"), {"user_id": user.id, "limit": limit}).mappings()
        return [HistoryItem(**row) for row in rows]


@app.get("/api/history/{check_id}", responses=error_responses(401, 404, 422))
def history_item(check_id: int = CheckId, user: UserInfo = Depends(required_user)) -> HistoryItem:
    """One saved check"""
    with engine.connect() as db:
        row = db.execute(text("SELECT id, url, probability, label, model_name, created_at FROM checks WHERE id = :id AND user_id = :user_id"), {"id": check_id, "user_id": user.id}).mappings().first()
    if row is None:
        raise HTTPException(404, "Check not found")
    return HistoryItem(**row)


@app.delete("/api/history/{check_id}", status_code=204, responses=error_responses(401, 404, 422))
def delete_history_item(check_id: int = CheckId, user: UserInfo = Depends(required_user)) -> None:
    """Delete one saved check"""
    with engine.begin() as db:
        deleted = db.execute(text("DELETE FROM checks WHERE id = :id AND user_id = :user_id"), {"id": check_id, "user_id": user.id}).rowcount
    if not deleted:
        raise HTTPException(404, "Check not found")
