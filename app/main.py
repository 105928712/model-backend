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

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from .auth import create_token, hash_password, optional_user, password_matches, required_user, unauthorised
from .database import engine
from .errors import add_error_handlers
from .model import PhishingModel, load_model
from .preprocessing import url_features
from .security import add_security, login_limit
from .schemas import CheckRequest, CheckResult, Credentials, HistoryItem, ModelInfo, Token, UserInfo
from .utils import training_domain_warnings, risk_band

model: PhishingModel = load_model()


app = FastAPI(
    title="Anchorfish Model Backend",
    description="API for the Anchorfish model",
    version="0.1.0",
    contact={"name": "Joey Manani", "email": "joeymanani@theflyingrat.com"}
)
add_error_handlers(app)
add_security(app)


@app.get("/api/health")
def health(request: Request) -> dict[str, str]:
    return {"status": "ok", "model": model.name}


@app.get("/api/model")
def model_info() -> ModelInfo:
    return ModelInfo(name=model.name, threshold=model.threshold)


@app.post("/api/check", responses={422: {"description": "The URL cannot be formatted correctly"}})
def check(request: CheckRequest, user: UserInfo | None = Depends(optional_user)) -> CheckResult:
    """Score a URL. Anyone can check, a signed-in user's checks are also saved to their history."""
    prediction = model.predict(request.url)
    warnings   = training_domain_warnings(request.url)

    # if user is logged in, log it to their history
    if user is not None:
        with engine.begin() as db:
            db.execute(text("INSERT INTO checks (user_id, url, probability, label, model_name) VALUES (:user_id, :url, :probability, :label, :model_name)"), {"user_id": user.id, "url": request.url, "probability": prediction.probability, "label": prediction.label, "model_name": model.name})

    # both user types get a model return
    return CheckResult(
        url=request.url,
        model=model.name,
        probability=prediction.probability,
        threshold=model.threshold,
        label=prediction.label,
        risk_band=risk_band(prediction.probability, model.threshold),
        outside_training_domain=bool(warnings),
        warnings=warnings,
        features=url_features(request.url),
    )


@app.post("/api/register", status_code=201, responses={409: {"description": "Username is taken"}})
@login_limit
def register(request: Request, credentials: Credentials) -> UserInfo:
    try:
        with engine.begin() as db:
            user = db.execute(
                text("INSERT INTO users (username, password_hash) VALUES (:username, :password_hash) RETURNING id, username, role, created_at"),
                {"username": credentials.username, "password_hash": hash_password(credentials.password)},
            ).mappings().one()
    except IntegrityError as e:   # the UNIQUE on username
        raise HTTPException(409, "Username is taken") from e
    return UserInfo(**user) # unpack user obj --> new UserInfo obj


@app.post("/api/login", responses={401: {"description": "Wrong username or password"}})
@login_limit
def login(request: Request, credentials: Credentials) -> Token:
    """Login with username/password. Client shall now send Authorization: Bearer <token>"""
    with engine.connect() as db:
        user = db.execute(text("SELECT id, role, password_hash FROM users WHERE username = :username"), {"username": credentials.username}).mappings().first()

    # Cyber 101: Same message for both, so the response doesn't reveal which usernames exist
    # unknown users still get a full hash check (dummy hash) so timing matches too
    if not password_matches(user["password_hash"] if user else None, credentials.password) or user is None:
        raise unauthorised("Wrong username or password")

    # Create a new token for the user
    return Token(access_token=create_token(user["id"], user["role"]))


@app.get("/api/me")
def me(user: UserInfo = Depends(required_user)) -> UserInfo:
    return user


@app.get("/api/history")
def history(user: UserInfo = Depends(required_user), limit: int = Query(20, ge=1, le=100)) -> list[HistoryItem]:
    """The signed-in user's history, ordered by latest to oldest"""
    with engine.connect() as db:
        rows = db.execute(text("SELECT id, url, probability, label, model_name, created_at FROM checks WHERE user_id = :user_id ORDER BY created_at DESC, id DESC LIMIT :limit"), {"user_id": user.id, "limit": limit}).mappings()
        return [HistoryItem(**row) for row in rows]
