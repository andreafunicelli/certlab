from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.core.db import SessionLocal
from app.models import DeploymentLock
from app.models.base import utcnow
from app.services import locks


def _expire(key: str) -> None:
    with SessionLocal() as s:
        s.execute(text("UPDATE deployment_locks SET expires_at = :t WHERE resource_key = :k"),
                  {"t": utcnow() - timedelta(seconds=5), "k": key})
        s.commit()


def test_acquire_is_exclusive_and_release_requires_owner(db):
    key = locks.file_key(uuid.uuid4(), "/etc/ssl/a.pem")
    assert locks.acquire(key, owner="w1")
    assert not locks.acquire(key, owner="w2")
    assert not locks.release(key, owner="w2")            # not the owner
    assert locks.holder(key).owner == "w1"
    assert locks.release(key, owner="w1")
    assert locks.acquire(key, owner="w2")


def test_expired_lock_is_recovered_by_another_worker(db):
    key = "srv:/etc/ssl/b.pem"
    assert locks.acquire(key, owner="dead-worker", ttl_seconds=60)
    assert not locks.acquire(key, owner="w2")
    _expire(key)                                          # the holder crashed and stopped renewing
    assert locks.acquire(key, owner="w2")
    assert locks.holder(key).owner == "w2"


def test_same_job_may_reenter_its_own_lock(db):
    job = uuid.uuid4()
    from app.models import CertificateVersion, DeploymentJob

    v = CertificateVersion()
    db.add(v)
    db.commit()
    j = DeploymentJob(id=job, version_id=v.id, status="pending")
    db.add(j)
    db.commit()
    key = "srv:/etc/ssl/c.pem"
    assert locks.acquire(key, owner="old-run", job_id=job)
    assert locks.acquire(key, owner="new-run", job_id=job)        # resumed worker of the same job
    assert not locks.acquire(key, owner="other", job_id=None)


def test_renew_extends_expiry_only_for_owner(db):
    key = "srv:/etc/ssl/d.pem"
    locks.acquire(key, owner="w1", ttl_seconds=5)
    before = locks.holder(key).expires_at
    assert locks.renew(key, owner="w1", ttl_seconds=300)
    assert locks.holder(key).expires_at > before + timedelta(seconds=100)
    assert not locks.renew(key, owner="w2")


async def test_lockset_is_all_or_nothing_and_releases(db):
    locks.acquire("k:b", owner="someone-else")
    with pytest.raises(locks.LockHeld) as ei:
        async with locks.LockSet(["k:a", "k:b", "k:c"], owner="me", job_id=None, target_id=None):
            pytest.fail("must not enter")
    assert ei.value.resource_key == "k:b"
    assert locks.holder("k:a") is None and locks.holder("k:c") is None      # partial acquisitions rolled back
    async with locks.LockSet(["k:a", "k:c"], owner="me", job_id=None, target_id=None):
        assert locks.holder("k:a").owner == "me"
    assert locks.holder("k:a") is None                                       # released in finally


async def test_heartbeat_keeps_lock_alive(db):
    ls = locks.LockSet(["k:hb"], owner="me", job_id=None, target_id=None, ttl_seconds=2, heartbeat_seconds=0.2)
    async with ls:
        first = locks.holder("k:hb").heartbeat_at
        await asyncio.sleep(0.7)
        assert locks.holder("k:hb").heartbeat_at > first
        assert not ls.lost


def test_purge_expired(db):
    locks.acquire("k:old", owner="x")
    _expire("k:old")
    locks.acquire("k:new", owner="y")
    assert locks.purge_expired() == 1
    with SessionLocal() as s:
        assert [r.resource_key for r in s.query(DeploymentLock)] == ["k:new"]
