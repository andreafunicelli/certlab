"""Celery tasks of the deployment engine: ``deployments.run`` and the backup retention beat task."""
from __future__ import annotations

import uuid

from celery.schedules import crontab

from app.core.db import SessionLocal
from app.core.logging import get_logger
from app.workers.celery_app import celery_app

log = get_logger(__name__)

# the retention task is scheduled here so the engine owns its own beat entries (celery_app is shared)
celery_app.conf.beat_schedule.setdefault("backups-purge-expired", {
    "task": "backups.purge_expired", "schedule": crontab(hour=3, minute=23)})
celery_app.conf.beat_schedule.setdefault("deployments-purge-locks", {
    "task": "deployments.purge_locks", "schedule": crontab(minute="*/10")})
celery_app.conf.beat_schedule.setdefault("deployments-sweep-pending", {
    "task": "deployments.sweep_pending", "schedule": crontab(minute="*/5")})


@celery_app.task(name="deployments.run", bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=60)
def run_deployment(self, job_id: str) -> str:
    """Execute (or resume after a worker crash) a deployment job. Idempotent: persisted step results and remote
    reconciliation make a re-delivery safe; a live worker on the same job makes this delivery retry later."""
    from app.services import deployment_engine, ssh_limits

    ssh_limits.apply_from_db()
    try:
        status = deployment_engine.run_job(uuid.UUID(job_id))
    except deployment_engine.JobBusy:
        log.info("deployment_job_busy", job_id=job_id)
        raise self.retry(countdown=30) from None
    log.info("deployment_finished", job_id=job_id, status=status)
    return status


@celery_app.task(name="backups.purge_expired")
def purge_expired_backups() -> int:
    from app.services import backups

    with SessionLocal() as db:
        n = backups.purge_expired(db)
    log.info("backups_purged", count=n)
    return n


@celery_app.task(name="deployments.purge_locks")
def purge_expired_locks() -> int:
    from app.services import locks

    return locks.purge_expired()


@celery_app.task(name="deployments.sweep_pending")
def sweep_pending_deployments() -> dict:
    """Beat (K5): re-dispatch approved deployments stuck in ``pending`` (lost broker message), then fail them."""
    from app.services import deployments

    with SessionLocal() as db:
        result = deployments.sweep_stuck_pending(db)
    if result["redispatched"] or result["failed"]:
        log.warning("deployments_pending_sweep", **result)
    return result


@celery_app.task(name="backups.restore", bind=True, acks_late=True, reject_on_worker_lost=True)
def restore_backup_task(self, backup_id: str, actor_id: str, target_id: str | None = None,
                        previous_status: str = "none", permission: str = "backups:restore") -> dict:
    """Manual restore of a backup / manual rollback of a deployment target (moved out of the HTTP request).
    The worker re-authorises the requesting user before touching the host."""
    from app.services import deployment_engine, ssh_limits

    ssh_limits.apply_from_db()
    result = deployment_engine.run_restore(uuid.UUID(backup_id), uuid.UUID(actor_id), uuid.UUID(target_id) if target_id else None,
                                           previous_restore_status=previous_status, permission=permission)
    log.info("backup_restore_finished", backup_id=backup_id, ok=result.get("ok"), error_code=result.get("error_code"))
    return {"ok": bool(result.get("ok")), "error_code": result.get("error_code")}
