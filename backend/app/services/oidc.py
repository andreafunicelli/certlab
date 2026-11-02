"""OIDC authorization-code + PKCE login (Authlib JOSE for ID-token validation)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.crypto import get_vault
from app.core.errors import AppError
from app.models import User
from app.repositories import users as users_repo
from app.services import audit

STATE_COOKIE = "cdp_oidc"
_disc_cache: dict[str, tuple[float, dict]] = {}


def _require_enabled() -> None:
    if not get_settings().oidc_enabled:
        raise AppError("OIDC_NOT_CONFIGURED", "OIDC login is not configured", 404)


def _redirect_uri() -> str:
    s = get_settings()
    base = (s.public_base_url or "").rstrip("/")
    return f"{base}/api/v1/auth/oidc/callback"


def _discovery() -> dict[str, Any]:
    issuer = get_settings().oidc_issuer.rstrip("/")  # type: ignore[union-attr]
    cached = _disc_cache.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]
    try:
        r = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
        r.raise_for_status()
        doc = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AppError("OIDC_UNAVAILABLE", "The identity provider is unreachable", 502) from exc
    _disc_cache[issuer] = (time.time() + 600, doc)
    return doc


def _sign(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    mac = hmac.new(get_vault().derive_key("oidc-state"), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def _unsign(value: str | None) -> dict:
    try:
        raw, mac = (value or "").rsplit(".", 1)
        good = hmac.new(get_vault().derive_key("oidc-state"), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, good):
            raise ValueError
        data = json.loads(base64.urlsafe_b64decode(raw))
        if data["exp"] < time.time():
            raise ValueError
        return data
    except (ValueError, KeyError):
        raise AppError("OIDC_STATE_INVALID", "Login state is invalid or expired", 400) from None


def begin_login() -> tuple[str, str]:
    """Returns (authorization_url, signed_state_cookie_value)."""
    _require_enabled()
    s = get_settings()
    doc = _discovery()
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {
        "response_type": "code", "client_id": s.oidc_client_id, "redirect_uri": _redirect_uri(),
        "scope": s.oidc_scopes, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    cookie = _sign({"state": state, "nonce": nonce, "verifier": verifier, "exp": time.time() + 600})
    return f"{doc['authorization_endpoint']}?{urlencode(params)}", cookie


def _role_names(claims: dict[str, Any]) -> list[str]:
    s = get_settings()
    groups = claims.get(s.oidc_groups_claim) or []
    groups = {groups} if isinstance(groups, str) else set(groups)
    if groups & set(s.oidc_admin_groups):
        return ["admin"]
    if groups & set(s.oidc_operator_groups):
        return ["operator"]
    return ["viewer"]


def complete_login(db: Session, code: str, state: str, cookie_value: str | None) -> User:
    _require_enabled()
    s = get_settings()
    saved = _unsign(cookie_value)
    if not hmac.compare_digest(saved["state"], state):
        raise AppError("OIDC_STATE_INVALID", "Login state mismatch", 400)
    doc = _discovery()
    try:
        tok = httpx.post(
            doc["token_endpoint"],
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": _redirect_uri(),
                  "code_verifier": saved["verifier"], "client_id": s.oidc_client_id},
            auth=(s.oidc_client_id or "", s.oidc_client_secret.get_secret_value() if s.oidc_client_secret else ""),
            timeout=10,
        )
        tok.raise_for_status()
        id_token = tok.json()["id_token"]
        jwks = httpx.get(doc["jwks_uri"], timeout=10).json()
        claims = jwt.decode(id_token, JsonWebKey.import_key_set(jwks))
        claims.validate()
    except (httpx.HTTPError, KeyError, ValueError, JoseError) as exc:
        audit.record_independent(action="OIDC_LOGIN_FAILED", resource_type="user", outcome="failure",
                                 actor_name="oidc", error=type(exc).__name__)
        raise AppError("OIDC_LOGIN_FAILED", "Single sign-on failed", 401) from exc
    if claims.get("iss") != doc.get("issuer") or s.oidc_client_id not in (
        claims["aud"] if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    ) or claims.get("nonce") != saved["nonce"]:
        raise AppError("OIDC_LOGIN_FAILED", "Single sign-on failed", 401)

    subject, email = str(claims["sub"]), claims.get("email")
    user = users_repo.by_oidc_subject(db, subject)
    roles = users_repo.roles_by_names(db, _role_names(claims))
    if user is None:
        if not s.oidc_auto_provision or not email:
            raise AppError("OIDC_USER_NOT_PROVISIONED", "No account is provisioned for this identity", 403)
        if users_repo.by_email(db, email):
            raise AppError("OIDC_EMAIL_CONFLICT", "A local account with this email already exists", 409)
        username = str(claims.get("preferred_username") or email)[:64]
        if users_repo.by_username(db, username):
            username = f"{username[:50]}-{secrets.token_hex(3)}"
        user = User(username=username, email=email, display_name=str(claims.get("name") or username)[:128],
                    auth_provider="oidc", oidc_subject=subject)
        db.add(user)
        audit.record(db, action="USER_PROVISIONED_OIDC", resource_type="user", actor=user,
                     after={"username": username})
    if not user.enabled:
        raise AppError("OIDC_LOGIN_FAILED", "Account disabled", 403)
    user.roles = roles
    db.flush()
    return user
