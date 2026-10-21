# security.py
# 2026 Joey Manani & Anchorfish Team
# CORS, security headers and rate limiting

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
from .errors import error_response
from .globals import MAX_BODY_BYTES
from .settings import CORS_ORIGINS, LOGIN_RATE_LIMIT, RATE_LIMIT, RATE_LIMIT_ENABLED

DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")  # swagger needs its CDN scripts, so no content security policy there


# security headers
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-site",
}

# CSP for the API
API_CSP = "default-src 'none'; frame-ancestors 'none'"



# https://deepwiki.com/laurentS/slowapi/4.2-fastapi-integration
# remote address not proxy X-Forwarded-For because a client can write anything in that header and get a fresh limit 
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{RATE_LIMIT}/minute"], enabled=RATE_LIMIT_ENABLED)

# login and register share
login_limit = limiter.shared_limit(f"{LOGIN_RATE_LIMIT}/minute", scope="login")


async def too_many_requests(request: Request, error: RateLimitExceeded) -> JSONResponse:
    """Declare a rate limit exceeded error, takes a Request and RateLimitExceeded instance"""
    return error_response(429, "Too many requests!!", headers={"Retry-After": str(error.limit.limit.get_expiry())})


async def security_headers(request: Request, call_next: callable) -> JSONResponse:
    """Middleware: Add security headers to all responses"""
    response = await call_next(request) # Call the next middleware
    response.headers.update(HEADERS) # Update the response headers with security headers
    if not request.url.path.startswith(DOCS_PATHS): # if the request is not documentation, amend the CSP headers
        response.headers["Content-Security-Policy"] = API_CSP
    return response


def add_security(app: FastAPI) -> None:
    # Top down!!

    # Body size cap
    app.add_middleware(RequestBodyLimitMiddleware, max_body_size=MAX_BODY_BYTES)

    # Add rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, too_many_requests)
    app.add_middleware(SlowAPIMiddleware)

    # Add security headers middleware
    app.middleware("http")(security_headers)
    
    # Add CORS middleware - might need revising later
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )
