"""Celery tasks: discovery, monitoring, notifications. Business logic lives in ``app.services``."""
from __future__ import annotations

import uuid

from app.core.db import SessionLocal
from app.core.logging import get_logger
from app.workers.celery_app import celery_app, enqueue

log = get_logger(__name__)


@celery_app.task(name="discovery.run", bind=True, acks_late=True, reject_on_worker_lost=True)
def run_discovery(self, job_id: str) -> str:
    from app.services import discovery

    status = discovery.execute_job(uuid.UUID(job_id))
    log.info("discovery_task_finished", job_id=job_id, status=status)
    return status


@celery_app.task(name="discovery.schedule_all")
def schedule_discovery() -> int:
    """Beat: enqueue discovery for every enabled server whose inventory is older than ``inventory_refresh_minutes``."""
    from app.services import discovery

    with SessionLocal() as db:
        ids = discovery.schedule_due(db)
    for jid in ids:
        enqueue("discovery.run", str(jid))
    return len(ids)


@celery_app.task(name="monitoring.check_expiry")
def check_expiry() -> dict:
    from app.services import monitoring

    with SessionLocal() as db:
        result = monitoring.check_expiry(db)
    log.info("expiry_check_done", **result)
    return result


@celery_app.task(name="monitoring.verify_endpoints")
def verify_endpoints() -> dict:
    from app.services import monitoring

    with SessionLocal() as db:
        result = monitoring.verify_endpoints(db)
    log.info("endpoint_verification_done", **result)
    return result


@celery_app.task(name="notifications.deliver", bind=True, max_retries=5, acks_late=True)
def deliver_notification(self, delivery_id: str) -> str:
    """Deliver one notification; exponential backoff (60s * 2^n, capped at 1h). Final failure is stored on the row."""
    from app.services import notifications

    with SessionLocal() as db:
        outcome = notifications.attempt_delivery(db, uuid.UUID(delivery_id))
    if outcome == "retry":
        raise self.retry(countdown=min(60 * 2 ** self.request.retries, 3600))
    return outcome


@celery_app.task(name="notifications.sweep_pending")
def sweep_pending_notifications() -> int:
    """Beat: re-enqueue deliveries stuck in 'pending' (e.g. broker message lost)."""
    from app.services import notifications

    with SessionLocal() as db:
        ids = notifications.retry_pending(db)
    for did in ids:
        enqueue("notifications.deliver", str(did))
    return len(ids)
