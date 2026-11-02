"""Uniform error model and exception handlers."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import correlation_id_var
from app.core.logging import get_logger, redact

log = get_logger(__name__)


class AppError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status: int = 400,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}
        self.headers = headers or {}


def not_found(code: str, message: str) -> AppError:
    return AppError(code, message, 404)


def conflict(code: str, message: str, details: dict | None = None) -> AppError:
    return AppError(code, message, 409, details)


def error_body(code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": correlation_id_var.get(),
            "details": redact(details or {}),
        }
    }


def error_response(code: str, message: str, status: int, details: dict | None = None, headers=None) -> JSONResponse:
    return JSONResponse(error_body(code, message, details), status_code=status, headers=headers)


async def _app_error(_: Request, exc: AppError) -> JSONResponse:
    return error_response(exc.code, exc.message, exc.status, exc.details, exc.headers)


async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # never echo submitted input (may contain secrets)
    errors = [
        {"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    return error_response("VALIDATION_ERROR", "Request validation failed", 422, {"errors": errors})


_HTTP_CODES = {
    400: "BAD_REQUEST", 401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED", 409: "CONFLICT", 413: "PAYLOAD_TOO_LARGE", 415: "UNSUPPORTED_MEDIA_TYPE",
    429: "RATE_LIMITED",
}


async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _HTTP_CODES.get(exc.status_code, "HTTP_ERROR")
    msg = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return error_response(code, msg, exc.status_code, headers=getattr(exc, "headers", None))


async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled_exception", exc_info=exc)
    return error_response("INTERNAL_ERROR", "An internal error occurred", 500)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled)
