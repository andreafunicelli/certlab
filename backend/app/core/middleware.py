"""Pure-ASGI middleware: correlation id, secure headers, rate limiting, crash safety."""
from __future__ import annotations

import json
import re
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_settings
from app.core.context import client_ip_var, correlation_id_var, user_agent_var
from app.core.errors import error_body
from app.core.logging import get_logger
from app.core.ratelimit import get_rate_limiter

log = get_logger(__name__)
_CID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def _client_ip(scope: Scope, headers: Headers) -> str | None:
    if get_settings().trust_proxy_headers:
        xff = headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()[:64]
    client = scope.get("client")
    return client[0] if client else None


async def _send_json(send: Send, status: int, body: dict, headers: dict[str, str]) -> None:
    raw = json.dumps(body).encode()
    hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]
    hdrs += [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    await send({"type": "http.response.start", "status": status, "headers": hdrs})
    await send({"type": "http.response.body", "body": raw})


class CorrelationIdMiddleware:
    """Outermost: sets contextvars, echoes X-Correlation-ID, converts crashes into a safe 500."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        incoming = headers.get("x-correlation-id")
        cid = incoming if incoming and _CID_RE.match(incoming) else uuid.uuid4().hex
        t1 = correlation_id_var.set(cid)
        t2 = client_ip_var.set(_client_ip(scope, headers))
        t3 = user_agent_var.set((headers.get("user-agent") or "")[:300] or None)
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                MutableHeaders(scope=message)["X-Correlation-ID"] = cid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            log.error("unhandled_exception", exc_info=exc, path=scope.get("path"))
            if not started:
                await _send_json(
                    send, 500, error_body("INTERNAL_ERROR", "An internal error occurred"),
                    {"X-Correlation-ID": cid, "Cache-Control": "no-store"},
                )
        finally:
            correlation_id_var.reset(t1)
            client_ip_var.reset(t2)
            user_agent_var.reset(t3)


_DOC_PREFIXES = ("/api/docs", "/api/redoc")
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_DOC_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)


class SecureHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        secure = get_settings().cookie_secure

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h["Content-Security-Policy"] = _DOC_CSP if path.startswith(_DOC_PREFIXES) else _API_CSP
                h["X-Content-Type-Options"] = "nosniff"
                h["X-Frame-Options"] = "DENY"
                h["Referrer-Policy"] = "no-referrer"
                h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                if path.startswith("/api/") and not path.startswith(_DOC_PREFIXES):
                    h.setdefault("Cache-Control", "no-store")
                if secure:
                    h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RateLimitMiddleware:
    """General per-IP API limiter. (Login has a stricter limiter inside the auth service.)"""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/api/") or path.startswith("/api/v1/healthz"):
            await self.app(scope, receive, send)
            return
        ip = client_ip_var.get() or "unknown"
        limit = get_settings().rate_limit_api_per_minute
        allowed, retry = get_rate_limiter().hit(f"api:{ip}", limit, 60)
        if not allowed:
            await _send_json(
                send, 429, error_body("RATE_LIMITED", "Too many requests", {"retry_after": retry}),
                {"Retry-After": str(retry)},
            )
            return
        await self.app(scope, receive, send)
