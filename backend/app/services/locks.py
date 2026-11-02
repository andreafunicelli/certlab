"""Durable deployment locks (``deployment_locks`` table).

A lock is identified by ``resource_key`` (``<server_id>:<realpath>`` for files, ``<server_id>:service:<type>`` for a
service, ``job:<job_id>`` for a worker run). Each lock has an owner string, an expiry and a heartbeat.

* ``acquire`` is a single atomic INSERT .. ON CONFLICT DO UPDATE .. WHERE statement: an existing row is taken over only
  when it has expired (stale lock recovery after a crashed worker) or when it already belongs to the same job (the
  resumed worker of the same job re-acquires its own locks).
* ``renew`` extends the expiry while the holder is alive (``Heartbeat`` does this periodically).
* ``release`` removes the row only when the owner matches.

Every function uses its own short transaction so lock state is immediately visible to other workers.
"""
from __future__ import annotations

import asyncio
import contextlib
import posixpath
import uuid
from collections.abc import Iterable
from datetime import timedelta
from typing import Self

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.db import SessionLocal
from app.core.logging import get_logger
from app.models import DeploymentLock
from app.models.base import utcnow

log = get_logger(__name__)

DEFAULT_TTL_SECONDS = 120
HEARTBEAT_SECONDS = 20


def file_key(server_id: uuid.UUID | str, realpath: str) -> str:
    return f"{server_id}:{posixpath.normpath(realpath)}"


def service_key(server_id: uuid.UUID | str, service_type: str) -> str:
    return f"{server_id}:service:{service_type}"


def job_key(job_id: uuid.UUID | str) -> str:
    return f"job:{job_id}"


class LockHeld(Exception):
    def __init__(self, resource_key: str, holder: str | None, expires_at):
        super().__init__(f"lock {resource_key} is held by {holder} until {expires_at}")
        self.resource_key = resource_key
        self.holder = holder
        self.expires_at = expires_at


def acquire(resource_key: str, *, owner: str, job_id: uuid.UUID | None = None, target_id: uuid.UUID | None = None,
            ttl_seconds: float = DEFAULT_TTL_SECONDS) -> bool:
    """Try to take ``resource_key``. Returns True on success (new, recovered-after-expiry or same-job re-entry)."""
    now = utcnow()
    expires = now + timedelta(seconds=ttl_seconds)
    stmt = pg_insert(DeploymentLock).values(
        id=uuid.uuid4(), resource_key=resource_key, job_id=job_id, target_id=target_id, owner=owner,
        acquired_at=now, expires_at=expires, heartbeat_at=now,
    )
    cond = DeploymentLock.expires_at < now
    if job_id is not None:
        cond = cond | (DeploymentLock.job_id == job_id)
    stmt = stmt.on_conflict_do_update(
        index_elements=[DeploymentLock.resource_key],
        set_={"job_id": job_id, "target_id": target_id, "owner": owner, "acquired_at": now,
              "expires_at": expires, "heartbeat_at": now},
        where=cond,
    ).returning(DeploymentLock.id)
    with SessionLocal() as db:
        got = db.execute(stmt).first()
        db.commit()
    return got is not None


def holder(resource_key: str) -> DeploymentLock | None:
    with SessionLocal() as db:
        row = db.scalar(select(DeploymentLock).where(DeploymentLock.resource_key == resource_key))
        if row is not None:
            db.expunge(row)
        return row


def renew(resource_key: str, *, owner: str, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> bool:
    now = utcnow()
    with SessionLocal() as db:
        res = db.execute(
            update(DeploymentLock)
            .where(DeploymentLock.resource_key == resource_key, DeploymentLock.owner == owner)
            .values(expires_at=now + timedelta(seconds=ttl_seconds), heartbeat_at=now)
        )
        db.commit()
        return res.rowcount == 1


def release(resource_key: str, *, owner: str) -> bool:
    with SessionLocal() as db:
        res = db.execute(delete(DeploymentLock).where(DeploymentLock.resource_key == resource_key,
                                                      DeploymentLock.owner == owner))
        db.commit()
        return res.rowcount == 1


def release_owner(owner: str) -> int:
    with SessionLocal() as db:
        res = db.execute(delete(DeploymentLock).where(DeploymentLock.owner == owner))
        db.commit()
        return res.rowcount or 0


def purge_expired() -> int:
    with SessionLocal() as db:
        res = db.execute(delete(DeploymentLock).where(DeploymentLock.expires_at < utcnow()))
        db.commit()
        return res.rowcount or 0


def active_locks(resource_keys: Iterable[str], *, exclude_job: uuid.UUID | None = None) -> list[DeploymentLock]:
    """Unexpired locks on the given keys, optionally ignoring those held by ``exclude_job``."""
    keys = list(resource_keys)
    if not keys:
        return []
    with SessionLocal() as db:
        rows = db.scalars(select(DeploymentLock).where(DeploymentLock.resource_key.in_(keys),
                                                       DeploymentLock.expires_at >= utcnow())).all()
        out = [r for r in rows if exclude_job is None or r.job_id != exclude_job]
        for r in out:
            db.expunge(r)
        return out


class LockSet:
    """Acquire several locks atomically-ish (all-or-nothing, sorted order) and keep them alive with a heartbeat.

    Use as ``async with LockSet(...) as ls``; raises :class:`LockHeld` if any lock is unavailable (the ones already
    taken are released again). Locks are always released in ``__aexit__``.
    """

    def __init__(self, keys: Iterable[str], *, owner: str, job_id: uuid.UUID | None, target_id: uuid.UUID | None,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS, heartbeat_seconds: float = HEARTBEAT_SECONDS):
        self.keys = sorted(set(keys))
        self.owner, self.job_id, self.target_id = owner, job_id, target_id
        self.ttl, self.beat = ttl_seconds, heartbeat_seconds
        self._held: list[str] = []
        self._task: asyncio.Task | None = None
        self.lost = False

    def acquire_all(self) -> None:
        for k in self.keys:
            if acquire(k, owner=self.owner, job_id=self.job_id, target_id=self.target_id, ttl_seconds=self.ttl):
                self._held.append(k)
                continue
            row = holder(k)
            self.release_all()
            raise LockHeld(k, row.owner if row else None, row.expires_at if row else None)

    def release_all(self) -> None:
        for k in reversed(self._held):
            with contextlib.suppress(Exception):
                release(k, owner=self.owner)
        self._held = []

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(self.beat)
            for k in list(self._held):
                try:
                    if not renew(k, owner=self.owner, ttl_seconds=self.ttl):
                        self.lost = True
                        log.error("deployment_lock_lost", resource_key=k)
                except Exception as exc:  # noqa: BLE001
                    log.warning("deployment_lock_renew_failed", error=type(exc).__name__)

    async def __aenter__(self) -> Self:
        self.acquire_all()
        self._task = asyncio.ensure_future(self._heartbeat())
        return self

    async def __aexit__(self, *exc) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(BaseException):
                await self._task
        self.release_all()
