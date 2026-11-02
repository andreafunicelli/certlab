"""API-facing deployment service: plan / create / approve / cancel / retry / rollback / list / get."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
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
from app.services import audit
from app.services import deployment_engine as engine
from app.services import deployment_planner as planner
from app.services import settings as settings_service
from app.services.events import register_kind

TERMINAL = planner.FINAL_JOB_STATUSES


# --------------------------------------------------------------------------- dispatch (monkeypatched in tests)
def dispatch(job_id: uuid.UUID) -> None:
    """Hand the job to a Celery worker (``deployments.run``)."""
    from app.workers.celery_app import enqueue

    enqueue("deployments.run", str(job_id))


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
        dispatch(job.id)
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
    dispatch(job.id)
    return job


def cancel(db: Session, actor: User, job_id: uuid.UUID) -> DeploymentJob:
    job = get_job(db, job_id)
    if job.status in TERMINAL:
        raise AppError("INVALID_STATE", f"deployment already finished ({job.status})", 409)
    before = job.status
    job.cancel_requested = True
    if job.status == "awaiting_approval":
        job.status, job.finished_at = "cancelled", utcnow()
        for t in db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)):
            t.status, t.error_code = "cancelled", "CANCELLED"
    audit.record(db, action="DEPLOYMENT_CANCEL_REQUESTED", resource_type="deployment", resource_id=job.id, actor=actor,
                 before={"status": before}, after={"status": job.status, "cancel_requested": True})
    db.commit()
    return job


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
    audit.record(db, action="DEPLOYMENT_MANUAL_ROLLBACK", resource_type="deployment_target", resource_id=t.id, actor=actor,
                 after={"backup_id": str(backup.id)})
    db.commit()
    result = engine.restore_backup(db, backup, actor, target=t)
    job.rollback_status = "rolled_back" if result["ok"] else "manual_intervention_required"
    db.commit()
    return {"ok": result["ok"], "result": result, "target": target_out(db, t)}


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
