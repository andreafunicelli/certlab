from __future__ import annotations

import time
from unittest.mock import MagicMock

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt

from app.core.config import Settings
from app.core.errors import AppError
from app.models import Role, User
from app.services import oidc


@pytest.fixture
def complete_oidc_login(monkeypatch):
    settings = Settings(oidc_issuer="https://idp.example", oidc_client_id="certlab",
                        oidc_client_secret="test-client-secret", oidc_operator_groups=["operators"])
    monkeypatch.setattr(oidc, "get_settings", lambda: settings)
    monkeypatch.setattr(oidc, "_unsign", lambda _: {"state": "state", "nonce": "nonce", "verifier": "verifier"})
    monkeypatch.setattr(oidc, "_discovery", lambda: {
        "issuer": "https://idp.example", "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    })
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    token = jwt.encode({"alg": "RS256"}, {
        "iss": "https://idp.example", "aud": "certlab", "sub": "first-user", "nonce": "nonce",
        "exp": int(time.time()) + 300, "iat": int(time.time()), "email": "first@example.com",
        "preferred_username": "first", "groups": ["operators"],
    }, key).decode()
    monkeypatch.setattr(oidc.httpx, "post", lambda *args, **kwargs: httpx.Response(
        200, json={"id_token": token}, request=httpx.Request("POST", "https://idp.example/token")))
    monkeypatch.setattr(oidc.httpx, "get", lambda *args, **kwargs: httpx.Response(
        200, json={"keys": [key.as_dict()]}, request=httpx.Request("GET", "https://idp.example/jwks")))
    monkeypatch.setattr(oidc.users_repo, "by_oidc_subject", lambda *args: None)
    monkeypatch.setattr(oidc.users_repo, "by_email", lambda *args: None)
    monkeypatch.setattr(oidc.users_repo, "by_username", lambda *args: None)
    monkeypatch.setattr(oidc.users_repo, "roles_by_names", lambda *args: [Role(name="operator")])
    return lambda: oidc.complete_login(MagicMock(), "code", "state", "cookie")


def test_first_oidc_login_provisions_an_enabled_user(complete_oidc_login):
    user = complete_oidc_login()

    assert user.enabled is True
    assert user.username == "first"
    assert user.email == "first@example.com"
    assert user.auth_provider == "oidc"
    assert user.oidc_subject == "first-user"
    assert user.role_names == ["operator"]


def test_oidc_login_rejects_an_existing_disabled_user(complete_oidc_login, monkeypatch):
    user = User(username="first", email="first@example.com", display_name="First",
                auth_provider="oidc", oidc_subject="first-user", enabled=False)
    monkeypatch.setattr(oidc.users_repo, "by_oidc_subject", lambda *args: user)

    with pytest.raises(AppError) as exc:
        complete_oidc_login()

    assert exc.value.code == "OIDC_LOGIN_FAILED"
    assert exc.value.status == 403
