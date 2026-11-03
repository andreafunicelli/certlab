"""Job progress events: Redis pub/sub (one channel per job) with the database as the source of truth.

Publishers call :func:`publish_job_event` (best effort: Redis outages never break a job). Consumers use
:func:`sse_stream`, a *synchronous* generator of Server-Sent-Events text frames (Starlette runs sync
iterators in a thread pool), which

1. emits a ``snapshot`` event built from the DB (so late subscribers and Redis outages are harmless),
2. forwards every pub/sub message as ``event: progress`` (the JSON message is the ``data``),
3. re-reads the DB snapshot periodically and emits a new ``snapshot`` whenever it changed,
4. emits ``event: end`` and returns once the DB says the job is in a terminal state.

Frame format::

    event: snapshot|progress|end
    data: {"kind": "discovery", "job_id": "...", "type": "...", "ts": "...", ...payload}

``kind`` is ``"discovery"`` or ``"deployment"``; other kinds can be added with :func:`register_kind`.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import redis as redis_lib

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.base import utcnow

log = get_logger(__name__)

SnapshotFn = Callable[[Any, uuid.UUID], "dict[str, Any] | None"]


@dataclass(frozen=True)
class KindSpec:
    snapshot: SnapshotFn            # (db, job_id) -> JSON-able dict (must contain "status") or None if unknown
    terminal_statuses: frozenset[str]


_KINDS: dict[str, KindSpec] = {}


def register_kind(kind: str, snapshot: SnapshotFn, terminal_statuses: set[str] | frozenset[str]) -> None:
    _KINDS[kind] = KindSpec(snapshot, frozenset(terminal_statuses))


def channel_name(kind: str, job_id: Any) -> str:
    return f"cdp:job:{kind}:{job_id}"


_redis: redis_lib.Redis | None = None


def _client() -> redis_lib.Redis:
    global _redis
    if _redis is None:
        _redis = redis_lib.Redis.from_url(get_settings().redis_url, socket_timeout=5, socket_connect_timeout=3,
                                          decode_responses=True)
    return _redis


def reset_client() -> None:
    global _redis
    _redis = None


def publish_job_event(kind: str, job_id: Any, payload: dict[str, Any]) -> bool:
    """Publish ``payload`` to the job's channel. Returns False (never raises) when Redis is unavailable.

    ``payload`` should contain a ``type`` ("progress" | "step" | "status" | "done" ...); ``kind``, ``job_id`` and
    ``ts`` are added. Payloads must not contain secrets.
    """
    from app.core.logging import redact

    msg = {"type": "progress", **redact(payload), "kind": kind, "job_id": str(job_id), "ts": utcnow().isoformat()}
    try:
        _client().publish(channel_name(kind, job_id), json.dumps(msg, default=str))
        return True
    except Exception as exc:  # noqa: BLE001 - progress is advisory; the DB is the source of truth
        log.warning("job_event_publish_failed", kind=kind, error=type(exc).__name__)
        return False


def _frame(event: str, data: dict[str, Any] | str) -> str:
    body = data if isinstance(data, str) else json.dumps(data, default=str)
    return f"event: {event}\ndata: {body}\n\n"


# ---------------------------------------------------------------------------- default snapshot builders
def _discovery_snapshot(db, job_id: uuid.UUID) -> dict[str, Any] | None:
    from sqlalchemy import func, select

    from app.models import DiscoveryFinding, DiscoveryJob

    job = db.get(DiscoveryJob, job_id)
    if job is None:
        return None
    n = db.scalar(select(func.count()).select_from(DiscoveryFinding).where(DiscoveryFinding.job_id == job_id)) or 0
    return {
        "type": "snapshot", "kind": "discovery", "job_id": str(job.id), "server_id": str(job.server_id),
        "status": job.status, "started_at": job.started_at, "finished_at": job.finished_at,
        "stats": job.stats, "error": job.error, "error_code": job.error_code, "finding_count": n,
        "steps": job.steps or [],
    }


def _deployment_snapshot(db, job_id: uuid.UUID) -> dict[str, Any] | None:
    from sqlalchemy import select

    from app.models import DeploymentJob, DeploymentTarget

    job = db.get(DeploymentJob, job_id)
    if job is None:
        return None
    targets = db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job_id)
                         .order_by(DeploymentTarget.batch_index, DeploymentTarget.created_at)).all()
    return {
        "type": "snapshot", "kind": "deployment", "job_id": str(job.id), "status": job.status,
        "rollback_status": job.rollback_status, "started_at": job.started_at, "finished_at": job.finished_at,
        "error_summary": job.error_summary,
        "targets": [
            {"id": str(t.id), "server_id": str(t.server_id), "installation_id": str(t.installation_id)
             if t.installation_id else None, "status": t.status, "current_step": t.current_step,
             "is_canary": t.is_canary, "batch_index": t.batch_index, "steps": t.steps,
             "error_code": t.error_code, "error_message": t.error_message}
            for t in targets
        ],
    }


register_kind("discovery", _discovery_snapshot, {"completed", "failed", "partial", "cancelled"})
register_kind("deployment", _deployment_snapshot,
              {"completed", "failed", "rolled_back", "cancelled", "partially_failed", "manual_intervention_required"})


def snapshot(kind: str, job_id: uuid.UUID) -> dict[str, Any] | None:
    from app.core.db import SessionLocal

    spec = _KINDS[kind]
    with SessionLocal() as db:
        return spec.snapshot(db, job_id)


def sse_stream(kind: str, job_id: uuid.UUID | str, *, poll_seconds: float = 1.0, resnapshot_seconds: float = 5.0,
               heartbeat_seconds: float = 15.0, max_seconds: float = 3600.0) -> Iterator[str]:
    """Yield SSE frames for a job until it reaches a terminal state (see module docstring)."""
    spec = _KINDS[kind]
    jid = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    deadline = time.monotonic() + max_seconds
    last_hash: str | None = None
    last_snap_at = 0.0
    last_sent = time.monotonic()

    pubsub = None
    try:
        pubsub = _client().pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(channel_name(kind, jid))
    except Exception as exc:  # noqa: BLE001 - fall back to DB polling only
        log.warning("sse_subscribe_failed", kind=kind, error=type(exc).__name__)
        pubsub = None

    def take_snapshot() -> tuple[dict[str, Any] | None, bool]:
        snap = snapshot(kind, jid)
        terminal = bool(snap and snap.get("status") in spec.terminal_statuses)
        return snap, terminal

    try:
        while True:
            now = time.monotonic()
            if now - last_snap_at >= resnapshot_seconds or last_hash is None:
                last_snap_at = now
                snap, terminal = take_snapshot()
                if snap is None:
                    yield _frame("error", {"code": "NOT_FOUND", "message": "job not found"})
                    return
                h = hashlib.sha256(json.dumps(snap, default=str, sort_keys=True).encode()).hexdigest()
                if h != last_hash:
                    last_hash = h
                    last_sent = time.monotonic()
                    yield _frame("snapshot", snap)
                if terminal:
                    yield _frame("end", {"kind": kind, "job_id": str(jid), "status": snap.get("status")})
                    return
            if now >= deadline:
                yield _frame("end", {"kind": kind, "job_id": str(jid), "status": "timeout"})
                return
            msg = None
            if pubsub is not None:
                try:
                    msg = pubsub.get_message(timeout=poll_seconds)
                except Exception as exc:  # noqa: BLE001
                    log.warning("sse_receive_failed", error=type(exc).__name__)
                    pubsub = None
            else:
                time.sleep(poll_seconds)
            if msg and msg.get("type") == "message":
                last_sent = time.monotonic()
                yield _frame("progress", str(msg["data"]))
                last_snap_at = 0.0 if '"done"' in str(msg["data"]) else last_snap_at
            elif time.monotonic() - last_sent >= heartbeat_seconds:
                last_sent = time.monotonic()
                yield ": keepalive\n\n"
    finally:
        if pubsub is not None:
            try:
                pubsub.unsubscribe()
                pubsub.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("sse_unsubscribe_failed", error=type(exc).__name__)
