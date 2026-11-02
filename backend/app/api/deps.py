"""FastAPI dependencies: DB session, authentication, CSRF, RBAC, re-auth."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core import security
from app.core.db import get_db
from app.core.errors import AppError
from app.core.permissions import authorize
from app.services import audit
from app.services import auth as auth_service
from app.services.auth import AuthContext


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    token = request.cookies.get(security.SESSION_COOKIE)
    if not token:
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    ctx = auth_service.resolve_session(db, token)
    if request.method in security.UNSAFE_METHODS and not security.csrf_valid(
        token, request.cookies.get(security.CSRF_COOKIE), request.headers.get(security.CSRF_HEADER)
    ):
        raise AppError("CSRF_FAILED", "Missing or invalid CSRF token", 403)
    return ctx


def require_permission(permission: str, *, reauth: bool = False) -> Callable[..., AuthContext]:
    """Dependency factory: authenticated + CSRF-checked + authorized (+ recent re-auth if requested)."""

    def dependency(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> AuthContext:
        try:
            authorize(ctx.user, permission)
        except AppError:
            audit.record_independent(action="ACCESS_DENIED", resource_type="permission", resource_id=permission,
                                     actor=ctx.user, outcome="denied")
            raise
        if reauth:
            auth_service.require_recent_reauth(db, ctx)
        return ctx

    return dependency
