from __future__ import annotations

import pytest
from sqlalchemy import text

from app.core.db import SessionLocal
from app.integrations.tls import probe as tls_probe
from app.services import deployment_engine as engine
from app.services import deployments as deployments_service
from tests.conftest import make_user
from tests.unit.deploy.helpers import FakeNetwork

FAST = {"verify_retries": 2, "verify_delay_seconds": 0}


@pytest.fixture(autouse=True)
def _clean_locks(db):
    with SessionLocal() as s:
        s.execute(text("DELETE FROM deployment_locks"))
        s.commit()
    yield
    with SessionLocal() as s:
        s.execute(text("DELETE FROM deployment_locks"))
        s.commit()


@pytest.fixture(autouse=True)
def _relax_chain_enforcement(db):
    """Migration 0004 turns strict chain enforcement on for 'Production'; the throwaway test PKI is not trusted, so the
    generic deploy tests run with it off (tests that exercise K8 switch it on for their own environment)."""
    with SessionLocal() as s:
        s.execute(text("UPDATE environments SET require_trusted_chain = false"))
        s.commit()
    yield
    with SessionLocal() as s:
        s.execute(text("UPDATE environments SET require_trusted_chain = (name = 'Production')"))
        s.commit()


@pytest.fixture
def net(monkeypatch):
    n = FakeNetwork()
    monkeypatch.setattr(engine, "HOST_FACTORY", n.factory)
    monkeypatch.setattr(tls_probe, "probe_endpoint", n.probe_endpoint)
    return n


@pytest.fixture
def dispatched(monkeypatch):
    sent: list = []
    monkeypatch.setattr(deployments_service, "dispatch", lambda job_id: sent.append(job_id))
    return sent


@pytest.fixture
def operator(db):
    return make_user(db, "oper1", "operator")


@pytest.fixture
def admin_user(db):
    return make_user(db, "admin1", "admin")


@pytest.fixture(scope="module")
def pkis():
    from tests.fixtures.pki import make_pki

    names = ["site.test.local"]
    return {"old": make_pki(names), "new": make_pki(names)}
