# errors.py
# 2026 Joey Manani & Anchorfish Team
# declare egress shapes {"error": {"status", "message", "details"}} 

import logging
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

logger = logging.getLogger(__name__)


def error_response(status: int, message: str, details: list[dict[str, str]] | None = None, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"status": status, "message": message, "details": details or []}}, headers=headers)

##

async def http_error(request: Request, error: HTTPException) -> JSONResponse:
    return error_response(error.status_code, str(error.detail), headers=error.headers)


async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    details = [{"field": ".".join(str(part) for part in problem["loc"]), "message": problem["msg"]} for problem in error.errors()]
    return error_response(422, "Request is not valid", details)


async def unexpected_error(request: Request, error: Exception) -> JSONResponse:
    logger.exception(f"Unhandled error on {request.method} {request.url.path}")
    return error_response(500, "Something went wrong")


def add_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(Exception, unexpected_error)
