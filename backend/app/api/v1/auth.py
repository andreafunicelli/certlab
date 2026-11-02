from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_auth_context
from app.core import security
from app.core.config import get_settings
from app.core.db import get_db
from app.schemas.user import (
    LoginRequest,
    MeResponse,
    MfaDisableRequest,
    MfaEnableRequest,
    PasswordChange,
    ReauthRequest,
    UserOut,
)
from app.services import auth as auth_service
from app.services import oidc as oidc_service
from app.services.auth import AuthContext

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookies(response: Response, token: str, max_age: int) -> str:
    s = get_settings()
    csrf = security.csrf_token_for(token)
    common = {"secure": s.cookie_secure, "samesite": "lax", "path": "/", "domain": s.cookie_domain, "max_age": max_age}
    response.set_cookie(security.SESSION_COOKIE, token, httponly=True, **common)
    response.set_cookie(security.CSRF_COOKIE, csrf, httponly=False, **common)
    return csrf


def _me(ctx: AuthContext, csrf: str) -> MeResponse:
    return MeResponse(user=UserOut.model_validate(ctx.user), roles=ctx.roles,
                      permissions=sorted(ctx.permissions), csrf_token=csrf)


def _ttl(ctx: AuthContext) -> int:
    return max(60, int((ctx.session.expires_at - ctx.session.created_at).total_seconds()))


@router.post("/login", response_model=MeResponse)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)) -> MeResponse:
    ctx, token = auth_service.login(db, body.username, body.password, body.totp)
    return _me(ctx, _set_cookies(response, token, _ttl(ctx)))


@router.post("/logout", status_code=204)
def logout(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> Response:
    auth_service.logout(db, ctx)
    resp = Response(status_code=204)
    resp.delete_cookie(security.SESSION_COOKIE, path="/", domain=get_settings().cookie_domain)
    resp.delete_cookie(security.CSRF_COOKIE, path="/", domain=get_settings().cookie_domain)
    return resp


@router.get("/me", response_model=MeResponse)
def me(response: Response, ctx: AuthContext = Depends(get_auth_context)) -> MeResponse:
    return _me(ctx, _set_cookies(response, ctx.token, _ttl(ctx)))


@router.post("/reauth", status_code=204)
def reauth(body: ReauthRequest, ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> Response:
    auth_service.reauth(db, ctx, body.password, body.totp)
    return Response(status_code=204)


@router.post("/password", status_code=204)
def change_password(body: PasswordChange, ctx: AuthContext = Depends(get_auth_context),
                    db: Session = Depends(get_db)) -> Response:
    auth_service.change_password(db, ctx, body.current_password, body.new_password)
    return Response(status_code=204)


@router.post("/mfa/setup")
def mfa_setup(ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    return auth_service.mfa_setup(db, ctx)


@router.post("/mfa/enable", status_code=204)
def mfa_enable(body: MfaEnableRequest, ctx: AuthContext = Depends(get_auth_context),
               db: Session = Depends(get_db)) -> Response:
    auth_service.mfa_enable(db, ctx, body.code)
    return Response(status_code=204)


@router.post("/mfa/disable", status_code=204)
def mfa_disable(body: MfaDisableRequest, ctx: AuthContext = Depends(get_auth_context),
                db: Session = Depends(get_db)) -> Response:
    auth_service.mfa_disable(db, ctx, body.password)
    return Response(status_code=204)


@router.get("/oidc/login", include_in_schema=True)
def oidc_login() -> RedirectResponse:
    url, cookie = oidc_service.begin_login()
    resp = RedirectResponse(url, status_code=302)
    s = get_settings()
    resp.set_cookie(oidc_service.STATE_COOKIE, cookie, max_age=600, httponly=True, secure=s.cookie_secure,
                    samesite="lax", path="/api/v1/auth/oidc")
    return resp


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str, state: str, db: Session = Depends(get_db)) -> RedirectResponse:
    user = oidc_service.complete_login(db, code, state, request.cookies.get(oidc_service.STATE_COOKIE))
    ctx, token = auth_service.create_session_for(db, user)
    resp = RedirectResponse("/", status_code=302)
    _set_cookies(resp, token, _ttl(ctx))
    resp.delete_cookie(oidc_service.STATE_COOKIE, path="/api/v1/auth/oidc")
    return resp
