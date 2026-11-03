"""API-facing deployment service: plan / create / approve / cancel / retry / rollback / list / get."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, cast, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
from app.core.logging import get_logger
from app.core.permissions import has_permission
from app.models import (
    Backup,
    CertificateInstallation,
    CertificateVersion,
    DeploymentJob,
    DeploymentTarget,
    Environment,
    Server,
    User,
)
from app.models.base import utcnow
from app.services import audit, locks
from app.services import deployment_engine as engine
from app.services import deployment_planner as planner
from app.services import settings as settings_service
from app.services.events import register_kind

TERMINAL = planner.FINAL_JOB_STATUSES
log = get_logger(__name__)

# K5: a deployment that stays ``pending`` this long after its last hand-over to the broker is re-dispatched, at most
# MAX_DISPATCH_ATTEMPTS times in total, and failed with QUEUE_LOST afterwards.
PENDING_REDISPATCH_MINUTES = 10
MAX_DISPATCH_ATTEMPTS = 3


# --------------------------------------------------------------------------- dispatch (monkeypatched in tests)
def dispatch(job_id: uuid.UUID) -> None:
    """Hand the job to a Celery worker (``deployments.run``)."""
    from app.workers.celery_app import enqueue

    enqueue("deployments.run", str(job_id))


def dispatch_restore(backup_id: uuid.UUID, actor_id: uuid.UUID, target_id: uuid.UUID | None, previous_status: str,
                     permission: str) -> None:
    """Hand a manual restore / target rollback to a Celery worker (``backups.restore``)."""
    from app.workers.celery_app import enqueue

    enqueue("backups.restore", str(backup_id), str(actor_id), str(target_id) if target_id else None, previous_status, permission)


def _fail_queue(db: Session, job: DeploymentJob, code: str, message: str, *, actor: User | None, action: str) -> None:
    """The job can never reach a worker: finish it as failed so nothing waits for it forever."""
    before = job.status
    job.status, job.finished_at, job.error_summary = "failed", utcnow(), f"{code}: {message}"
    for t in db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)):
        if t.status not in planner.FINAL_TARGET_STATUSES:
            t.status, t.error_code, t.error_message = "cancelled", code, message
    audit.record(db, action=action, resource_type="deployment", resource_id=job.id, actor=actor,
                 actor_name=None if actor else "deployment-engine", before={"status": before},
                 after={"status": "failed", "error_code": code}, outcome="failure", error=message)
    db.commit()


def _send(db: Session, job: DeploymentJob, actor: User) -> None:
    """Dispatch a committed ``pending`` job. A broker failure fails the job (QUEUE_UNAVAILABLE) instead of leaving it
    ``pending`` forever (K4). Bookkeeping is committed before the send so an eager/fast worker never races our transaction."""
    job.dispatch_attempts = (job.dispatch_attempts or 0) + 1
    job.last_dispatched_at = utcnow()
    db.commit()
    try:
        dispatch(job.id)
    except Exception as exc:
        log.error("deployment_dispatch_failed", job_id=str(job.id), error=type(exc).__name__)
        db.rollback()
        job = get_job(db, job.id)
        _fail_queue(db, job, "QUEUE_UNAVAILABLE", "the job queue is unavailable; the deployment was not started",
                    actor=actor, action="DEPLOYMENT_QUEUE_FAILED")
        raise AppError("QUEUE_UNAVAILABLE", "The job queue is unavailable; the deployment was not started. Try again shortly.",
                       503, {"deployment_id": str(job.id)}) from exc


# --------------------------------------------------------------------------- serialisation
def target_out(db: Session, t: DeploymentTarget, *, detail: bool = True) -> dict[str, Any]:
    inst = db.get(CertificateInstallation, t.installation_id) if t.installation_id else None
    server = db.get(Server, t.server_id)
    meta = t.meta or {}
    out: dict[str, Any] = {
        "id": str(t.id), "job_id": str(t.job_id), "installation_id": str(t.installation_id) if t.installation_id else None,
        "server_id": str(t.server_id), "server_name": server.name if server else None,
        "service_type": inst.service_type if inst else None, "vhost": inst.vhost if inst else None,
        "cert_path": inst.cert_path if inst else None,
        "batch_index": t.batch_index, "is_canary": t.is_canary, "status": t.status, "current_step": t.current_step,
        "previous_fingerprint": t.previous_fingerprint, "new_fingerprint": t.new_fingerprint,
        "backup_id": str(t.backup_id) if t.backup_id else None, "rollback_attempts": t.rollback_attempts,
        "verification": t.verification, "error_code": t.error_code, "error_message": t.error_message,
        "shared_with": meta.get("shared_with", []), "created_at": t.created_at, "updated_at": t.updated_at,
    }
    if detail:
        out["steps"] = t.steps or []
        out["log"] = t.log or []
        out["files"] = [{k: f.get(k) for k in ("dest_path", "realpath", "artifact", "action", "mode", "owner", "group",
                                              "is_symlink")} for f in meta.get("files", [])]
    return out


def job_out(db: Session, job: DeploymentJob, *, detail: bool = False) -> dict[str, Any]:
    version = db.get(CertificateVersion, job.version_id)
    user = db.get(User, job.initiated_by) if job.initiated_by else None
    counts = dict(db.execute(select(DeploymentTarget.status, func.count()).where(DeploymentTarget.job_id == job.id)
                             .group_by(DeploymentTarget.status)).all())
    out: dict[str, Any] = {
        "id": str(job.id), "version_id": str(job.version_id),
        "certificate_id": str(version.certificate_id) if version and version.certificate_id else None,
        "new_fingerprint": version.fingerprint_sha256 if version else None,
        "status": job.status, "strategy": job.strategy, "approval_required": job.approval_required,
        "approved_by": str(job.approved_by) if job.approved_by else None, "approved_at": job.approved_at,
        "initiated_by": str(job.initiated_by) if job.initiated_by else None,
        "initiated_by_name": user.username if user else None,
        "created_at": job.created_at, "started_at": job.started_at, "finished_at": job.finished_at,
        "rollback_status": job.rollback_status, "error_summary": job.error_summary,
        "cancel_requested": job.cancel_requested, "acknowledged_warnings": job.acknowledged_warnings or [],
        "retry_of": str(job.retry_of) if job.retry_of else None, "target_counts": counts,
        "target_total": sum(counts.values()),
    }
    if detail:
        targets = db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)
                             .order_by(DeploymentTarget.batch_index, DeploymentTarget.created_at, DeploymentTarget.id)).all()
        out["targets"] = [target_out(db, t) for t in targets]
        out["plan"] = job.dry_run_plan
    return out


def _snapshot(db: Session, job_id: uuid.UUID) -> dict[str, Any] | None:
    job = db.get(DeploymentJob, job_id)
    if job is None:
        return None
    out = job_out(db, job, detail=True)
    out.pop("plan", None)
    return {"type": "snapshot", "kind": "deployment", "job_id": str(job.id), **out}


register_kind("deployment", _snapshot, set(TERMINAL))


# --------------------------------------------------------------------------- helpers
def get_job(db: Session, job_id: uuid.UUID) -> DeploymentJob:
    job = db.get(DeploymentJob, job_id)
    if job is None:
        raise not_found("DEPLOYMENT_NOT_FOUND", "Deployment not found")
    return job


def _request_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _load_version(db: Session, version_id: uuid.UUID) -> CertificateVersion:
    v = db.get(CertificateVersion, version_id)
    if v is None:
        raise not_found("VERSION_NOT_FOUND", "Certificate version not found")
    return v


def _prepare(db: Session, actor: User, body: dict[str, Any]) -> tuple[CertificateVersion, dict[str, Any], list[dict], list[str]]:
    """Validate privileges for the dangerous knobs and normalise the strategy."""
    version = _load_version(db, body["version_id"])
    strategy = planner.normalize_strategy(body.get("strategy"), settings_service.get_section_data(db, "ssh"))
    is_admin = has_permission(actor.role_names, "deployments:approve")
    if strategy["continue_on_failure"] and not is_admin:
        raise AppError("FORBIDDEN", "continue_on_failure must be authorised by an administrator", 403)
    exceptions = []
    for e in body.get("exception_approvals") or []:
        if not is_admin:
            raise AppError("FORBIDDEN", "exception approvals require an administrator", 403)
        if e["code"] not in planner.EXCEPTIONABLE_CODES:
            raise AppError("VALIDATION_ERROR", f"{e['code']} cannot be excepted", 422)
        if len((e.get("justification") or "").strip()) < 10:
            raise AppError("VALIDATION_ERROR", "an exception needs a justification of at least 10 characters", 422)
        exceptions.append({"code": e["code"], "justification": e["justification"].strip(),
                           "installation_id": str(e["installation_id"]) if e.get("installation_id") else None,
                           "approved_by": actor.username, "approved_at": utcnow().isoformat()})
    return version, strategy, exceptions, sorted(set(body.get("acknowledged_warnings") or []))


# --------------------------------------------------------------------------- plan (read-only)
def plan(db: Session, actor: User, body: dict[str, Any]) -> dict[str, Any]:
    version, strategy, exceptions, ack = _prepare(db, actor, body)
    result = planner.build_plan(db, version, list(body["installation_ids"]), strategy, acknowledged=ack,
                                exceptions=exceptions, host_factory=engine.HOST_FACTORY or planner.default_host_factory)
    audit.record(db, action="DEPLOYMENT_PLANNED", resource_type="certificate_version", resource_id=version.id, actor=actor,
                 after={"installations": [str(i) for i in body["installation_ids"]], "can_proceed": result["summary"]["can_proceed"],
                        "blocking": result["summary"]["blocking"]})
    db.commit()
    return result


# --------------------------------------------------------------------------- create
def _needs_approval(db: Session, plan_targets: list[dict[str, Any]]) -> bool:
    prod_rule = settings_service.get_section_data(db, "security")["require_production_approval"]
    envs = {t["environment"] for t in plan_targets}
    for name in envs:
        env = db.scalar(select(Environment).where(Environment.name == name))
        if env is not None and (env.requires_approval or (prod_rule and env.is_production)):
            return True
    return False


def create(db: Session, actor: User, idempotency_key: str | None, body: dict[str, Any], *, retry_of: uuid.UUID | None = None,
           dispatch_now: bool = True) -> tuple[DeploymentJob, bool]:
    """Returns ``(job, created)``; ``created`` is False when an identical request was replayed."""
    if not idempotency_key or not (1 <= len(idempotency_key) <= 80):
        raise AppError("IDEMPOTENCY_KEY_REQUIRED", "An Idempotency-Key header (1-80 characters) is required", 400)
    stored_key = f"{actor.id.hex}:{idempotency_key}"
    canonical = {"version_id": str(body["version_id"]), "installation_ids": [str(i) for i in body["installation_ids"]],
                 "strategy": body.get("strategy"), "acknowledged_warnings": sorted(set(body.get("acknowledged_warnings") or [])),
                 "exception_approvals": [
                     {"code": e["code"], "justification": e["justification"],
                      "installation_id": str(e["installation_id"]) if e.get("installation_id") else None}
                     for e in body.get("exception_approvals") or []]}
    rhash = _request_hash(canonical)
    existing = db.scalar(select(DeploymentJob).where(DeploymentJob.idempotency_key == stored_key))
    if existing is not None:
        if existing.request_hash != rhash:
            raise AppError("IDEMPOTENCY_KEY_CONFLICT", "This Idempotency-Key was already used with a different request", 409)
        return existing, False

    version, strategy, exceptions, ack = _prepare(db, actor, body)
    result = planner.build_plan(db, version, list(body["installation_ids"]), strategy, acknowledged=ack,
                                exceptions=exceptions, host_factory=engine.HOST_FACTORY or planner.default_host_factory)
    blocking = [f for f in result["findings"] if f["severity"] == "blocking"]
    if blocking or not result["targets"]:
        raise AppError("PREFLIGHT_BLOCKED", "Pre-flight checks found blocking problems; the deployment was not created", 409,
                       {"findings": blocking, "summary": result["summary"]})
    if result["summary"]["unacknowledged_warnings"]:
        raise AppError("WARNINGS_NOT_ACKNOWLEDGED", "All warnings must be acknowledged before deploying", 422,
                       {"codes": result["summary"]["unacknowledged_warnings"], "findings": [
                           f for f in result["findings"] if f["severity"] == "warning"]})
    if not result["summary"]["can_proceed"]:
        raise AppError("PREFLIGHT_BLOCKED", "Not every selected installation could be planned", 409, {"summary": result["summary"]})

    approval = _needs_approval(db, result["targets"])
    job = DeploymentJob(
        id=uuid.uuid4(), version_id=version.id, initiated_by=actor.id, strategy={**strategy, "exceptions": exceptions},
        dry_run_plan=result, status="awaiting_approval" if approval else "pending", approval_required=approval,
        idempotency_key=stored_key, request_hash=rhash, acknowledged_warnings=ack, retry_of=retry_of)
    db.add(job)
    db.flush()
    for t in result["targets"]:
        db.add(DeploymentTarget(
            id=uuid.uuid4(), job_id=job.id, installation_id=uuid.UUID(t["installation_id"]), server_id=uuid.UUID(t["server_id"]),
            batch_index=t["batch_index"], is_canary=t["is_canary"], status="pending",
            previous_fingerprint=t["current_fingerprint"],
            meta={"unit": t["unit"], "files": t["files"], "verify_endpoints": t["verify_endpoints"],
                  "verification_mode": t["verification_mode"], "shared_with": t["shared_with"]}))
    audit.record(db, action="DEPLOYMENT_CREATED", resource_type="deployment", resource_id=job.id, actor=actor,
                 after={"version_id": str(version.id), "targets": len(result["targets"]), "status": job.status,
                        "approval_required": approval, "strategy": strategy, "acknowledged_warnings": ack,
                        "exceptions": [{k: v for k, v in e.items()} for e in exceptions]})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(DeploymentJob).where(DeploymentJob.idempotency_key == stored_key))
        if existing is not None and existing.request_hash == rhash:
            return existing, False
        raise AppError("IDEMPOTENCY_KEY_CONFLICT", "This Idempotency-Key was already used with a different request", 409) from None
    if not approval and dispatch_now:
        _send(db, job, actor)
    return job, True


# --------------------------------------------------------------------------- approve / cancel / retry
def approve(db: Session, actor: User, job_id: uuid.UUID) -> DeploymentJob:
    job = get_job(db, job_id)
    if job.status != "awaiting_approval":
        raise AppError("INVALID_STATE", f"deployment is {job.status}, not awaiting approval", 409)
    sec = settings_service.get_section_data(db, "security")
    if job.initiated_by == actor.id and not sec.get("allow_self_approval"):
        audit.record_independent(action="DEPLOYMENT_APPROVAL_DENIED", resource_type="deployment", resource_id=job.id,
                                 actor=actor, outcome="denied", error="initiator cannot approve their own deployment")
        raise AppError("SELF_APPROVAL_FORBIDDEN", "You cannot approve a deployment you initiated "
                       "(a second administrator is required, or enable security.allow_self_approval)", 403)
    job.approved_by, job.approved_at, job.status = actor.id, utcnow(), "pending"
    audit.record(db, action="DEPLOYMENT_APPROVED", resource_type="deployment", resource_id=job.id, actor=actor,
                 before={"status": "awaiting_approval"}, after={"status": "pending", "self_approved": job.initiated_by == actor.id})
    db.commit()
    _send(db, job, actor)
    return job


MUTATING_TARGET_STATES = ("activating", "reloading", "verifying", "rolling_back")


def cancel(db: Session, actor: User, job_id: uuid.UUID) -> DeploymentJob:
    job = get_job(db, job_id)
    if job.status in TERMINAL:
        raise AppError("INVALID_STATE", f"deployment already finished ({job.status})", 409)
    before = job.status
    cancelled_now = False
    if job.status == "pending" and job.started_at is None:
        # K5: not picked up by any worker yet -> cancel at once. Guarded UPDATE: a worker that starts at the same time wins
        res = db.execute(update(DeploymentJob).where(DeploymentJob.id == job.id, DeploymentJob.status == "pending",
                                                     DeploymentJob.started_at.is_(None))
                         .values(status="cancelled", cancel_requested=True, finished_at=utcnow()))
        cancelled_now = res.rowcount == 1
        db.expire(job)
    if cancelled_now:
        for t in db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)):
            t.status, t.error_code, t.error_message = "cancelled", "CANCELLED", "cancelled before a worker started it"
    else:
        job.cancel_requested = True
        if job.status == "awaiting_approval":
            job.status, job.finished_at = "cancelled", utcnow()
            for t in db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)):
                t.status, t.error_code = "cancelled", "CANCELLED"
    audit.record(db, action="DEPLOYMENT_CANCEL_REQUESTED", resource_type="deployment", resource_id=job.id, actor=actor,
                 before={"status": before}, after={"status": job.status, "cancel_requested": True})
    db.commit()
    return job


def cancel_notice(db: Session, job: DeploymentJob) -> dict[str, Any]:
    """What a cancel request actually did (K7): cancellation is only honoured before activation starts."""
    if job.status == "cancelled":
        return {"effect": "cancelled", "message": "The deployment was cancelled; nothing was changed on any host."}
    active = db.scalar(select(func.count()).select_from(DeploymentTarget).where(
        DeploymentTarget.job_id == job.id, DeploymentTarget.status.in_(MUTATING_TARGET_STATES))) or 0
    if active:
        return {"effect": "too_late", "targets_in_activation": active,
                "message": (f"Cancellation was requested, but activation has already started on {active} target(s). Those cannot "
                            "be cancelled safely: they run to completion or are rolled back automatically. Targets that have "
                            "not started yet will be skipped.")}
    return {"effect": "requested",
            "message": ("Cancellation was requested. It is honoured before backup and before activation; once a target has "
                        "started activating it can no longer be cancelled and finishes or rolls back.")}


def sweep_stuck_pending(db: Session, *, older_than_minutes: int = PENDING_REDISPATCH_MINUTES,
                        max_attempts: int = MAX_DISPATCH_ATTEMPTS, now: datetime | None = None) -> dict[str, list[str]]:
    """Beat task body (K5): jobs that are approved and ``pending`` but were never started by a worker.

    Re-dispatches them (at most ``max_attempts`` hand-overs in total, counted in ``dispatch_attempts``), then fails
    them with QUEUE_LOST. A duplicate delivery is harmless: the job lock and the persisted state make runs idempotent.
    """
    now = now or utcnow()
    cutoff = now - timedelta(minutes=older_than_minutes)
    rows = list(db.scalars(select(DeploymentJob).where(
        DeploymentJob.status == "pending", DeploymentJob.started_at.is_(None),
        (DeploymentJob.approval_required.is_(False)) | (DeploymentJob.approved_by.is_not(None)),
        func.coalesce(DeploymentJob.last_dispatched_at, DeploymentJob.created_at) < cutoff).limit(100)))
    out: dict[str, list[str]] = {"redispatched": [], "failed": []}
    for job in rows:
        if (job.dispatch_attempts or 0) >= max_attempts:
            _fail_queue(db, job, "QUEUE_LOST", f"the deployment was not picked up by a worker after {job.dispatch_attempts} "
                        "dispatch attempts", actor=None, action="DEPLOYMENT_QUEUE_FAILED")
            out["failed"].append(str(job.id))
            continue
        job.dispatch_attempts = (job.dispatch_attempts or 0) + 1
        job.last_dispatched_at = now
        audit.record(db, action="DEPLOYMENT_REDISPATCHED", resource_type="deployment", resource_id=job.id, actor_name="deployment-engine",
                     after={"attempt": job.dispatch_attempts})
        db.commit()
        try:
            dispatch(job.id)
            out["redispatched"].append(str(job.id))
        except Exception as exc:  # noqa: BLE001 - the next sweep tries again until the attempts are used up
            log.error("deployment_redispatch_failed", job_id=str(job.id), error=type(exc).__name__)
    return out


def retry(db: Session, actor: User, job_id: uuid.UUID) -> DeploymentJob:
    job = get_job(db, job_id)
    if job.status not in TERMINAL:
        raise AppError("INVALID_STATE", "only finished deployments can be retried", 409)
    failed = list(db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id,
                                                            DeploymentTarget.status.in_(("failed", "rolled_back")))))
    if not failed:
        raise AppError("NOTHING_TO_RETRY", "no failed or rolled-back targets to retry", 409)
    strategy = {k: v for k, v in (job.strategy or {}).items() if k != "exceptions"}
    body = {"version_id": job.version_id, "installation_ids": [t.installation_id for t in failed if t.installation_id],
            "strategy": strategy, "acknowledged_warnings": list(job.acknowledged_warnings or []),
            "exception_approvals": [{"code": e["code"], "justification": e["justification"],
                                     "installation_id": e.get("installation_id")} for e in (job.strategy or {}).get("exceptions", [])]}
    new, _ = create(db, actor, f"retry-{job.id.hex[:12]}-{uuid.uuid4().hex[:16]}", body, retry_of=job.id)
    audit.record(db, action="DEPLOYMENT_RETRIED", resource_type="deployment", resource_id=job.id, actor=actor,
                 after={"new_deployment_id": str(new.id), "targets": len(failed)})
    db.commit()
    return new


def queue_restore(db: Session, actor: User, backup: Backup, target: DeploymentTarget | None, *,
                  permission: str = "backups:restore") -> dict[str, Any]:
    """Queue a manual restore / manual target rollback for a worker. Permission and re-authentication were checked at
    the API; the worker authorises again. Progress is shown by ``backup.restore_status`` (``in_progress`` ->
    ``restored`` / ``failed``) and, for a target rollback, the target's status and ``current_step``."""
    scope = engine.resolve_restore_scope(db, backup, target)
    unit = engine.manual_restore_targets(scope, target)
    keys = engine.restore_lock_keys(db, backup, target, scope)
    held = locks.active_locks(keys)
    if held:
        raise AppError("LOCK_HELD", "Another deployment or restore holds a lock on this target; try again when it has finished",
                       409, {"resource": held[0].resource_key.split(":", 1)[-1]})
    # no "already queued" refusal: a lost message would block restores for good, and the file locks already
    # serialise two restores of the same files (the routine is idempotent: files that match the backup are skipped)
    prior = backup.restore_status if backup.restore_status != "in_progress" else "none"
    backup.restore_status = "in_progress"
    for t in unit:
        t.current_step = "manual_rollback"
    audit.record(db, action="DEPLOYMENT_MANUAL_ROLLBACK" if target is not None else "BACKUP_RESTORE_REQUESTED",
                 resource_type="deployment_target" if target is not None else "backup",
                 resource_id=target.id if target is not None else backup.id, actor=actor,
                 after={"backup_id": str(backup.id), "queued": True,
                        "unit_target_ids": [str(t.id) for t in unit], "services": scope.service_types()})
    db.commit()
    unit_ids = [t.id for t in unit]
    try:
        dispatch_restore(backup.id, actor.id, target.id if target is not None else None, prior, permission)
    except Exception as exc:
        log.error("restore_dispatch_failed", backup_id=str(backup.id), error=type(exc).__name__)
        db.rollback()
        backup = db.get(Backup, backup.id)
        backup.restore_status = prior
        for tid in unit_ids:
            ut = db.get(DeploymentTarget, tid)
            if ut is not None and ut.current_step == "manual_rollback":
                ut.current_step = None
        audit.record(db, action="BACKUP_RESTORE_FAILED", resource_type="backup", resource_id=backup.id, actor=actor,
                     after={"error_code": "QUEUE_UNAVAILABLE"}, outcome="failure", error="job queue unavailable")
        db.commit()
        raise AppError("QUEUE_UNAVAILABLE", "The job queue is unavailable; the restore was not started. Try again shortly.",
                       503) from exc
    db.expire_all()
    others = [str(i) for i in unit_ids if target is None or i != target.id]
    message = "The restore was queued. Follow backup.restore_status and the target status."
    if others:
        message = (f"The restore was queued. This backup is shared by {len(others)} other target(s) of the same unit "
                   f"({', '.join(others)}): the whole unit is restored and verified together, and all of its targets "
                   "change status. Follow backup.restore_status and the target statuses.")
    return {"accepted": True, "backup_id": str(backup.id), "target_id": str(target.id) if target is not None else None,
            "job_id": str(target.job_id) if target is not None else None, "restore_status": "in_progress",
            "unit_target_ids": [str(i) for i in unit_ids], "services": scope.service_types(), "message": message}


def rollback_target(db: Session, actor: User, job_id: uuid.UUID, target_id: uuid.UUID) -> dict[str, Any]:
    job = get_job(db, job_id)
    t = db.get(DeploymentTarget, target_id)
    if t is None or t.job_id != job.id:
        raise not_found("TARGET_NOT_FOUND", "Deployment target not found")
    if t.status not in ("completed", "manual_intervention_required", "failed"):
        raise AppError("INVALID_STATE", f"target is {t.status}; only completed/failed targets can be rolled back manually", 409)
    backup = db.get(Backup, t.backup_id) if t.backup_id else None
    if backup is None or not backup.verified:
        raise AppError("NO_BACKUP", "this target has no verified backup to restore", 409)
    out = queue_restore(db, actor, backup, t, permission="deployments:rollback")
    db.refresh(t)
    return {**out, "target": target_out(db, t)}


# --------------------------------------------------------------------------- queries
def list_jobs(db: Session, *, offset: int, limit: int, status: str | None = None, version_id: uuid.UUID | None = None,
              server_id: uuid.UUID | None = None, initiated_by: uuid.UUID | None = None, since: datetime | None = None,
              until: datetime | None = None, q: str | None = None):
    stmt = select(DeploymentJob)
    if status:
        stmt = stmt.where(DeploymentJob.status.in_(status.split(",")))
    if version_id:
        stmt = stmt.where(DeploymentJob.version_id == version_id)
    if server_id:
        stmt = stmt.where(DeploymentJob.id.in_(select(DeploymentTarget.job_id).where(DeploymentTarget.server_id == server_id)))
    if initiated_by:
        stmt = stmt.where(DeploymentJob.initiated_by == initiated_by)
    if since:
        stmt = stmt.where(DeploymentJob.created_at >= since)
    if until:
        stmt = stmt.where(DeploymentJob.created_at <= until)
    if q:
        stmt = stmt.where(cast(DeploymentJob.id, String).ilike(f"{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(DeploymentJob.created_at.desc()).offset(offset).limit(limit)).all()
    return rows, total
