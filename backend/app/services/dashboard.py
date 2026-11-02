"""Dashboard aggregates.

Semantics: ``certificates_*`` count UNIQUE certificates (rows in ``certificates`` of type leaf/self_signed);
``installations_*`` count deployed copies (rows in ``certificate_installations`` not marked missing). One
certificate installed on five servers is 1 certificate and 5 installations.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Certificate, CertificateInstallation, DeploymentJob, Server
from app.models.base import utcnow

_DEPLOYABLE = ("leaf", "self_signed")
_FAILED = ("failed", "partially_failed", "rolled_back", "manual_intervention_required")
_UNREACHABLE = ("offline", "auth_error", "host_key_mismatch", "host_key_unknown", "error")


def _count(db: Session, stmt) -> int:
    return db.scalar(select(func.count()).select_from(stmt.subquery())) or 0


def summary(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    certs = select(Certificate.id).where(Certificate.certificate_type.in_(_DEPLOYABLE))
    inst = select(CertificateInstallation.id).where(CertificateInstallation.missing_since.is_(None))
    servers = select(Server.id).where(Server.enabled.is_(True))

    def expiring(days: int) -> int:
        return _count(db, certs.where(Certificate.not_after > now, Certificate.not_after <= now + timedelta(days=days)))

    recent_deployments = db.scalars(
        select(DeploymentJob).order_by(DeploymentJob.created_at.desc()).limit(5)
    ).all()
    activity = db.scalars(select(AuditEvent).order_by(AuditEvent.ts.desc()).limit(10)).all()
    return {
        "certificates_total": _count(db, certs),
        "installations_total": _count(db, inst),
        "certificates_expiring_30": expiring(30),
        "certificates_expiring_7": expiring(7),
        "certificates_expired": _count(db, certs.where(Certificate.not_after <= now)),
        "servers_total": _count(db, select(Server.id)),
        "servers_enabled": _count(db, servers),
        "servers_unreachable": _count(db, servers.where(Server.connection_status.in_(_UNREACHABLE))),
        "discovery_errors": _count(db, servers.where(Server.last_discovery_status.in_(("failed", "partial")))),
        "installation_errors": _count(db, inst.where(CertificateInstallation.classification == "error")),
        "drift": _count(db, inst.where(CertificateInstallation.drift_status.in_(("drifted", "missing")))),
        "failed_deployments_30d": _count(
            db, select(DeploymentJob.id).where(DeploymentJob.status.in_(_FAILED),
                                               DeploymentJob.created_at >= now - timedelta(days=30))),
        "running_deployments": _count(
            db, select(DeploymentJob.id).where(~DeploymentJob.status.in_(
                ("completed", "failed", "rolled_back", "cancelled", "partially_failed",
                 "manual_intervention_required")))),
        "recent_deployments": [
            {"id": str(d.id), "status": d.status, "created_at": d.created_at, "finished_at": d.finished_at,
             "initiated_by": str(d.initiated_by) if d.initiated_by else None}
            for d in recent_deployments
        ],
        "recent_activity": [
            {"id": str(a.id), "ts": a.ts, "actor_name": a.actor_name, "action": a.action,
             "resource_type": a.resource_type, "resource_id": a.resource_id, "outcome": a.outcome}
            for a in activity
        ],
        "generated_at": now,
    }


def expiry_trend(db: Session, now: datetime | None = None) -> dict[str, Any]:
    """Histogram buckets (UI donut/bars) plus per-month expiries for the next 12 months."""
    now = now or utcnow()
    base = select(func.count(Certificate.id)).where(Certificate.certificate_type.in_(_DEPLOYABLE))

    def n(lo: datetime | None, hi: datetime | None) -> int:
        conds = []
        if lo is not None:
            conds.append(Certificate.not_after > lo)
        if hi is not None:
            conds.append(Certificate.not_after <= hi)
        return db.scalar(base.where(and_(*conds)) if conds else base) or 0

    d = lambda days: now + timedelta(days=days)
    buckets = [
        {"bucket": "Expired", "count": n(None, now), "tone": "danger"},
        {"bucket": "< 7 days", "count": n(now, d(7)), "tone": "crit"},
        {"bucket": "7-30 days", "count": n(d(7), d(30)), "tone": "warn"},
        {"bucket": "30-90 days", "count": n(d(30), d(90)), "tone": "info"},
        {"bucket": "> 90 days", "count": n(d(90), None), "tone": "ok"},
    ]
    month = func.date_trunc("month", Certificate.not_after)
    rows = db.execute(
        select(month, func.count(Certificate.id))
        .where(Certificate.certificate_type.in_(_DEPLOYABLE), Certificate.not_after > now,
               Certificate.not_after <= now + timedelta(days=366))
        .group_by(month).order_by(month)
    ).all()
    return {
        "buckets": buckets,
        "monthly": [{"month": r[0].strftime("%Y-%m"), "count": r[1]} for r in rows],
        "generated_at": now,
    }
