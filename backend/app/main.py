"""Cert Deploy Pro API application factory."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.crypto import get_vault
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import CorrelationIdMiddleware, RateLimitMiddleware, SecureHeadersMiddleware

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    get_vault()  # refuses to start without a valid master key
    try:
        from app.services.bootstrap import bootstrap_admin_if_needed

        bootstrap_admin_if_needed(settings)
    except Exception as exc:  # noqa: BLE001 - DB may be migrating; do not crash the API
        log.error("bootstrap_failed", error=type(exc).__name__)
    log.info("startup_complete", env=settings.env)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="Cert Deploy Pro API", version="0.1.0", lifespan=lifespan,
        openapi_url="/api/v1/openapi.json", docs_url="/api/docs", redoc_url=None,
    )
    register_exception_handlers(app)
    # added innermost -> outermost
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Correlation-ID", "Idempotency-Key"],
        expose_headers=["X-Correlation-ID"], max_age=600,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
