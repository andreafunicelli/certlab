"""Password hashing, opaque session tokens, CSRF, TOTP helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

SESSION_COOKIE = "cdp_session"
CSRF_COOKIE = "cdp_csrf"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_hasher = PasswordHasher()  # argon2id defaults (RFC 9106 low-memory profile)
_DUMMY_HASH = _hasher.hash("cdp-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Constant-ish time: verifies against a dummy hash when the user has no hash."""
    try:
        _hasher.verify(password_hash or _DUMMY_HASH, password)
        return password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token_for(session_token: str) -> str:
    """Stateless CSRF token bound to the session (HMAC keyed from the master key)."""
    from app.core.crypto import get_vault

    key = get_vault().derive_key("csrf-v1")
    return hmac.new(key, session_token.encode(), hashlib.sha256).hexdigest()


def csrf_valid(session_token: str, cookie_value: str | None, header_value: str | None) -> bool:
    if not cookie_value or not header_value:
        return False
    if not hmac.compare_digest(cookie_value, header_value):
        return False
    return hmac.compare_digest(header_value, csrf_token_for(session_token))


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


def totp_uri(secret: str, account: str, issuer: str = "Cert Deploy Pro") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)
