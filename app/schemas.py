# schemas.py
# 2026 Joey Manani & Anchorfish Team
# Request and response shapes for the API

from pydantic import BaseModel, ConfigDict, Field, field_validator
from features.utils import get_host, normalise_url
from .globals import MAX_URL_LENGTH, RISK_BAND, FEATURE_VALUE, LABEL


class CheckRequest(BaseModel):
    """A URL to check return HTTP 422 if bad"""
    model_config = ConfigDict(extra="forbid", frozen=True, json_schema_extra={"examples": [{"url": "paypal-account-verify.top/login"}]})

    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def must_look_like_a_url(cls, url: str) -> str | None:
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

class CheckResult(BaseModel):
    """Everything known about one scored URL - return DTO for the front end"""
    model_config = ConfigDict(frozen=True)

    url: str
    model: str
    probability: float
    threshold: float
    label: LABEL
    risk_band: RISK_BAND
    outside_training_domain: bool
    warnings: list[str]
    features: dict[str, FEATURE_VALUE]

class ModelInfo(BaseModel):
    """The model currently answering"""
    model_config = ConfigDict(frozen=True)

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


