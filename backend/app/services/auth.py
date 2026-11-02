from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.context import client_ip_var, user_agent_var
from app.core.crypto import get_vault
from app.core.errors import AppError
from app.core.permissions import permissions_for_roles
from app.core.ratelimit import get_rate_limiter
from app.models import User, UserSession
from app.models.base import utcnow
from app.repositories import users as users_repo
from app.services import audit
from app.services import settings as settings_service

MAX_FAILED = 5
LOCK_MINUTES = 15


@dataclass
class AuthContext:
    user: User
    session: UserSession
    roles: list[str]
    permissions: frozenset[str]
    token: str


def _session_ttl_minutes(db: Session) -> int:
    sec = settings_service.get_section_data(db, "security")
    return max(1, min(sec["session_minutes"], get_settings().session_ttl // 60))


def _check_rate(ip: str, username: str) -> None:
    limit = get_settings().rate_limit_login_per_minute
    rl = get_rate_limiter()
    ok_ip, retry = rl.hit(f"login:ip:{ip}", limit, 60)
    ok_user, retry_u = rl.hit(f"login:user:{username.lower()}", max(3, limit // 2), 60)
    if not (ok_ip and ok_user):
        raise AppError("RATE_LIMITED", "Too many login attempts, try again later", 429,
                       {"retry_after": max(retry, retry_u)}, {"Retry-After": str(max(retry, retry_u))})


def _fail(db: Session, username: str, user: User | None, reason: str) -> AppError:
    audit.record(db, action="LOGIN_FAILED", resource_type="user", resource_id=user.id if user else None,
                 actor=user, actor_name=None if user else username[:64], outcome="failure", error=reason)
    db.commit()
    return AppError("INVALID_CREDENTIALS", "Invalid username or password", 401)


def login(db: Session, username: str, password: str, totp: str | None) -> tuple[AuthContext, str]:
    ip = client_ip_var.get() or "unknown"
    _check_rate(ip, username)
    user = users_repo.by_username(db, username)
    now = utcnow()
    if user is not None and user.locked_until and user.locked_until > now:
        raise _fail(db, username, user, "account_locked")
    pw_ok = security.verify_password(user.password_hash if user and user.auth_provider == "local" else None, password)
    if user is None or not pw_ok or not user.enabled:
        if user is not None and not pw_ok:
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_FAILED:
                user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                user.failed_login_count = 0
        raise _fail(db, username, user, "bad_credentials" if user is None or not pw_ok else "disabled")
    if user.mfa_enabled:
        if not totp:
            raise AppError("MFA_REQUIRED", "A one-time code is required", 401)
        secret = get_vault().decrypt_value(user.mfa_secret_encrypted or "")
        if not security.verify_totp(secret, totp):
            user.failed_login_count += 1
            raise _fail(db, username, user, "bad_totp")
    if security.needs_rehash(user.password_hash or ""):
        user.password_hash = security.hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    ctx, token = _create_session(db, user)
    audit.record(db, action="LOGIN", resource_type="user", resource_id=user.id, actor=user)
    db.commit()
    return ctx, token


def _create_session(db: Session, user: User) -> tuple[AuthContext, str]:
    now = utcnow()
    token = security.new_session_token()
    sess = UserSession(
        user_id=user.id, token_hash=security.hash_token(token), created_at=now, last_seen_at=now, reauth_at=now,
        expires_at=now + timedelta(minutes=_session_ttl_minutes(db)),
        ip=client_ip_var.get(), user_agent=user_agent_var.get(),
    )
    db.add(sess)
    db.flush()
    roles = user.role_names
    return AuthContext(user, sess, roles, permissions_for_roles(roles), token), token


def create_session_for(db: Session, user: User) -> tuple[AuthContext, str]:
    """Used by OIDC after the identity provider authenticated the user."""
    user.last_login_at = utcnow()
    ctx, token = _create_session(db, user)
    audit.record(db, action="LOGIN", resource_type="user", resource_id=user.id, actor=user,
                 after={"provider": user.auth_provider})
    db.commit()
    return ctx, token


def resolve_session(db: Session, token: str) -> AuthContext:
    sess = users_repo.get_session_by_hash(db, security.hash_token(token))
    now = utcnow()
    if sess is None or sess.revoked_at is not None or sess.expires_at <= now:
        raise AppError("SESSION_INVALID", "Session expired or invalid", 401)
    user = sess.user
    if not user.enabled:
        raise AppError("SESSION_INVALID", "Account disabled", 401)
    if (now - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = now
        db.commit()
    roles = user.role_names
    return AuthContext(user, sess, roles, permissions_for_roles(roles), token)


def logout(db: Session, ctx: AuthContext) -> None:
    ctx.session.revoked_at = utcnow()
    audit.record(db, action="LOGOUT", resource_type="user", resource_id=ctx.user.id, actor=ctx.user)
    db.commit()


def reauth(db: Session, ctx: AuthContext, password: str, totp: str | None) -> None:
    user = ctx.user
    ok = user.auth_provider == "local" and security.verify_password(user.password_hash, password)
    if ok and user.mfa_enabled:
        ok = bool(totp) and security.verify_totp(get_vault().decrypt_value(user.mfa_secret_encrypted or ""), totp or "")
    if not ok:
        audit.record(db, action="REAUTH_FAILED", resource_type="user", resource_id=user.id, actor=user,
                     outcome="failure")
        db.commit()
        raise AppError("INVALID_CREDENTIALS", "Re-authentication failed", 401)
    ctx.session.reauth_at = utcnow()
    audit.record(db, action="REAUTH", resource_type="user", resource_id=user.id, actor=user)
    db.commit()


def require_recent_reauth(db: Session, ctx: AuthContext) -> None:
    minutes = settings_service.get_section_data(db, "security")["reauth_minutes"]
    at = ctx.session.reauth_at
    if at is None or utcnow() - at > timedelta(minutes=minutes):
        raise AppError("REAUTH_REQUIRED", "Recent re-authentication is required for this action", 403,
                       {"reauth_minutes": minutes})


def change_password(db: Session, ctx: AuthContext, current: str, new: str) -> None:
    user = ctx.user
    if user.auth_provider != "local" or not security.verify_password(user.password_hash, current):
        raise AppError("INVALID_CREDENTIALS", "Current password is incorrect", 401)
    user.password_hash = security.hash_password(new)
    user.password_changed_at = utcnow()
    users_repo.revoke_user_sessions(db, user.id, utcnow(), except_id=ctx.session.id)
    audit.record(db, action="PASSWORD_CHANGED", resource_type="user", resource_id=user.id, actor=user)
    db.commit()


def mfa_setup(db: Session, ctx: AuthContext) -> dict:
    user = ctx.user
    if user.mfa_enabled:
        raise AppError("MFA_ALREADY_ENABLED", "MFA is already enabled", 409)
    secret = security.new_totp_secret()
    user.mfa_secret_encrypted = get_vault().encrypt_value(secret)
    db.commit()
    return {"secret": secret, "otpauth_uri": security.totp_uri(secret, user.username)}


def mfa_enable(db: Session, ctx: AuthContext, code: str) -> None:
    user = ctx.user
    if not user.mfa_secret_encrypted:
        raise AppError("MFA_NOT_INITIALIZED", "Run MFA setup first", 409)
    if not security.verify_totp(get_vault().decrypt_value(user.mfa_secret_encrypted), code):
        raise AppError("INVALID_TOTP", "Invalid one-time code", 400)
    user.mfa_enabled = True
    audit.record(db, action="MFA_ENABLED", resource_type="user", resource_id=user.id, actor=user)
    db.commit()


def mfa_disable(db: Session, ctx: AuthContext, password: str) -> None:
    user = ctx.user
    if not security.verify_password(user.password_hash, password):
        raise AppError("INVALID_CREDENTIALS", "Password is incorrect", 401)
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    audit.record(db, action="MFA_DISABLED", resource_type="user", resource_id=user.id, actor=user)
    db.commit()


_ = uuid
