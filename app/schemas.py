# schemas.py
# 2026 Joey Manani & Anchorfish Team
# Request and response shapes for the API

from datetime import datetime
from typing import Annotated
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator
from features.utils import get_host, normalise_url
from .globals import MAX_URL_LENGTH, RISK_BAND, FEATURE_VALUE, LABEL
from .settings import BATCH_MAX_URLS


def must_look_like_a_url(url: str) -> str:
    """Identical to training data cleaning"""
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    if not url.isprintable() or "�" in url:
        raise ValueError("URL contains unreadable characters")
    if any(character.isspace() for character in url):
        raise ValueError("URL contains whitespace")
    if not get_host(normalise_url(url)):
        raise ValueError("URL has no host")
    return url

# Annotated to validate the URL and limit the length
Url = Annotated[str, Field(min_length=1, max_length=MAX_URL_LENGTH), AfterValidator(must_look_like_a_url)]


class CheckRequest(BaseModel):
    """A URL to check return HTTP 422 if bad"""
    model_config = ConfigDict(extra="forbid", frozen=True, json_schema_extra={"examples": [{"url": "paypal-account-verify.top/login"}]})

    url: Url


class BatchRequest(BaseModel):
    """Several URLs to check at once. One bad URL rejects the whole batch with HTTP 422 naming its position"""
    model_config = ConfigDict(extra="forbid", frozen=True, json_schema_extra={"examples": [{"urls": ["google.com", "paypal-account-verify.top/login"]}]})

    urls: tuple[Url, ...] = Field(min_length=1, max_length=BATCH_MAX_URLS)


class CheckResult(BaseModel):
    """Everything known about one scored URL - return DTO for the front end"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{
        "url": "paypal-account-verify.top/login",
        "model": "final_hgb",
        "probability": 0.9999650084942906,
        "threshold": 0.35,
        "label": "phishing",
        "risk_band": "high",
        "outside_training_domain": False,
        "warnings": [],
        "features": {"path_level": 1, "path_length": 6, "query_length": 0, "entropy": 4.13569955274647, "subdomain_count": 0, "...": "every extracted feature"},
    }]})

    url: str
    model: str
    probability: float
    threshold: float
    label: LABEL
    risk_band: RISK_BAND
    outside_training_domain: bool
    warnings: list[str]
    features: dict[str, FEATURE_VALUE]

class Health(BaseModel):
    """The server is up and which model it loaded"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"status": "ok", "model": "final_hgb"}]})

    status: str
    model: str


class ModelInfo(BaseModel):
    """The model currently answering"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"name": "final_hgb", "threshold": 0.35}]})

    name: str
    threshold: float


class Credentials(BaseModel):
    """A username and password, for both registering and signing  in"""
    model_config = ConfigDict(extra="forbid", frozen=True, json_schema_extra={"examples": [{"username": "joey", "password": "i love cybersecurity!"}]})

    username: str = Field(pattern=r"^[A-Za-z0-9_]{3,32}$") # Username must be 3-32 characters and contain only letters, numbers, and underscores
    password: str = Field(min_length=12, max_length=128)   # Password must be 12-128 characters

    @field_validator("username")
    @classmethod
    def lowercase(cls, username: str) -> str:
        return username.lower()


class UserInfo(BaseModel):
    """A signed-in account, never includes the password hash"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"id": 3, "username": "joey", "role": "user", "created_at": "2026-10-21T07:25:00Z"}]})

    id: int
    username: str
    role: str
    created_at: datetime


class Token(BaseModel):
    """Send as Authorization: Bearer <access_token>"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "token_type": "bearer"}]})

    access_token: str
    token_type: str = "bearer"


class HistoryItem(BaseModel):
    """One saved check from the signed-in user's history"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"id": 42, "url": "paypal-account-verify.top/login", "probability": 0.9999650084942906, "label": "phishing", "model_name": "final_hgb", "created_at": "2026-10-21T07:25:00Z"}]})

    id: int
    url: str
    probability: float
    label: LABEL
    model_name: str
    created_at: datetime


class ErrorBody(BaseModel):
    status: int
    message: str
    details: list[dict[str, str]]


class ErrorResponse(BaseModel):
    """Every error the API sends has this shape"""
    model_config = ConfigDict(frozen=True, json_schema_extra={"examples": [{"error": {"status": 422, "message": "Request is not valid", "details": [{"field": "body.url", "message": "Value error, URL has no host"}]}}]})

    error: ErrorBody
