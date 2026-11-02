from __future__ import annotations

import base64
import os
import shutil
import tempfile
import uuid
from pathlib import Path

# --- environment must be configured before any app import -------------------------------------------
_ARTIFACTS = tempfile.mkdtemp(prefix="cdp-test-artifacts-")
TEST_MASTER_KEY = base64.b64encode(bytes(range(32))).decode()
os.environ.update({
    "CDP_ENV": "test",
    "CDP_DATABASE_URL": os.environ.get("CDP_TEST_DATABASE_URL",
                                       "postgresql+psycopg://cdp:cdp-dev-only@127.0.0.1:5432/cdp_test"),
    "CDP_MASTER_KEY": TEST_MASTER_KEY,
    "CDP_ARTIFACT_DIR": _ARTIFACTS,
    "CDP_COOKIE_SECURE": "false",
    "CDP_RATE_LIMIT_BACKEND": "memory",
    "CDP_RATE_LIMIT_API_PER_MINUTE": "100000",
    "CDP_RATE_LIMIT_LOGIN_PER_MINUTE": "1000",
})

import pytest
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from alembic import command
from app.core import crypto
from app.core.config import get_settings
from app.core.db import SessionLocal
from app.core.ratelimit import get_rate_limiter
from app.main import create_app
from app.schemas.user import UserCreate
from app.services import users as users_service

BACKEND_DIR = Path(__file__).resolve().parents[1]
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(scope="session")
def _schema():
    url = get_settings().database_url
    assert url.endswith("/cdp_test") or "test" in url, "refusing to run tests against a non-test database"
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")
    yield
    shutil.rmtree(_ARTIFACTS, ignore_errors=True)


_TRUNCATE = (
    "users, credentials, encrypted_artifacts, servers, certificates, audit_events, notification_channels, "
    "deployment_jobs, backups, discovery_jobs, certificate_versions"
)


@pytest.fixture
def _clean(_schema):
    with SessionLocal() as db:
        db.execute(text(f"TRUNCATE {_TRUNCATE} RESTART IDENTITY CASCADE"))
        db.execute(text("DELETE FROM environments WHERE name NOT IN ('Production','Staging','Test','Development')"))
        db.execute(text("DELETE FROM app_settings"))
        db.commit()
    get_rate_limiter().reset()
    crypto.reset_vault()
    for f in Path(_ARTIFACTS).glob("*"):
        f.unlink()
    yield


@pytest.fixture
def db(_clean):
    with SessionLocal() as session:
        yield session


@pytest.fixture(scope="session")
def app(_schema):
    return create_app()


@pytest.fixture
def anon(app):
    with TestClient(app) as c:
        yield c


def make_user(db, username: str, role: str, password: str = PASSWORD):
    return users_service.create(db, None, UserCreate(
        username=username, email=f"{username}@example.com", display_name=username.title(),
        password=password, roles=[role]))


class AuthedClient:
    """TestClient wrapper that sends the CSRF header on unsafe methods unless told otherwise."""

    def __init__(self, client: TestClient, csrf: str):
        self.c, self.csrf = client, csrf

    def _h(self, kw):
        headers = dict(kw.pop("headers", None) or {})
        if self.csrf is not None:
            headers.setdefault("X-CSRF-Token", self.csrf)
        return headers

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, **kw):
        return self.c.post(url, headers=self._h(kw), **kw)

    def patch(self, url, **kw):
        return self.c.patch(url, headers=self._h(kw), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(kw), **kw)

    def without_csrf(self) -> AuthedClient:
        return AuthedClient(self.c, None)  # type: ignore[arg-type]


@pytest.fixture
def login(app, db):
    clients: list[TestClient] = []

    def _login(role: str, username: str | None = None) -> AuthedClient:
        username = username or f"{role}-{uuid.uuid4().hex[:6]}"
        make_user(db, username, role)
        client = TestClient(app)
        clients.append(client)
        r = client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        return AuthedClient(client, r.json()["csrf_token"])

    yield _login
    for c in clients:
        c.close()


@pytest.fixture
def admin(login):
    return login("admin")
