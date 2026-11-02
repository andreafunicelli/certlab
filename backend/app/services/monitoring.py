"""Scheduled monitoring: certificate expiry buckets and live-endpoint verification (file-vs-served drift)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.integrations.certificates import days_remaining, expiry_status
from app.models import Certificate, CertificateInstallation, Server
from app.models.base import utcnow
from app.services import inventory, notifications

log = get_logger(__name__)


def expiry_event(status: str) -> tuple[str, str] | None:
    """(event_type, severity) for an expiry status, None when nothing to report."""
    if status == "valid":
        return None
    if status == "expired":
        return "cert.expired", "critical"
    return "cert.expiring", status            # info | warning | high | critical


def expiry_dedupe_key(cert_id: Any, status: str) -> str:
    """One key per certificate and threshold bucket; reminders repeat per rule.reminder_interval_hours."""
    return f"cert.expired:{cert_id}" if status == "expired" else f"cert.expiring:{cert_id}:{status}"


def check_expiry(db: Session, now: datetime | None = None) -> dict[str, int]:
    now = now or utcnow()
    th = inventory.thresholds(db)
    rows = db.execute(
        select(Certificate, CertificateInstallation, Server)
        .join(CertificateInstallation, CertificateInstallation.certificate_id == Certificate.id)
        .join(Server, Server.id == CertificateInstallation.server_id)
        .where(Certificate.certificate_type.in_(inventory.DEPLOYABLE_TYPES),
               CertificateInstallation.missing_since.is_(None))
        .order_by(Certificate.not_after)
    ).all()
    by_cert: dict[Any, dict[str, Any]] = {}
    for cert, _inst, server in rows:
        e = by_cert.setdefault(cert.id, {"cert": cert, "servers": set(), "envs": set(), "n": 0})
        e["servers"].add(server.name)
        e["envs"].add(server.environment)
        e["n"] += 1
    summary = {"checked": len(by_cert), "events": 0, "expired": 0, "expiring": 0}
    for cid, e in by_cert.items():
        cert: Certificate = e["cert"]
        days = days_remaining(cert.not_after, now)
        st = expiry_status(days, th)
        cert.status = inventory.db_status(cert.not_after, now, th)
        ev = expiry_event(st)
        if ev is None:
            continue
        event_type, severity = ev
        payload = {
            "certificate_id": str(cid), "common_name": cert.common_name, "sans": list(cert.sans or [])[:10],
            "fingerprint_sha256": cert.fingerprint_sha256, "not_after": cert.not_after.isoformat(),
            "days_remaining": days, "expiry_status": st, "installation_count": e["n"],
            "servers": sorted(e["servers"])[:20], "environments": sorted(e["envs"]),
        }
        made = notifications.notify(db, event_type, severity, payload, expiry_dedupe_key(cid, st))
        summary["events"] += len(made)
        summary["expired" if st == "expired" else "expiring"] += 1
    db.commit()
    return summary


def verify_endpoints(db: Session, now: datetime | None = None, batch: int = 100) -> dict[str, int]:
    now = now or utcnow()
    th = inventory.thresholds(db)
    stmt = (select(CertificateInstallation, Server)
            .join(Server, Server.id == CertificateInstallation.server_id)
            .where(Server.enabled.is_(True), CertificateInstallation.missing_since.is_(None),
                   CertificateInstallation.certificate_id.is_not(None),
                   CertificateInstallation.classification.in_(("managed", "unmanaged", "requires_mapping")))
            .order_by(CertificateInstallation.last_verification["checked_at"].astext.asc().nulls_first())
            .limit(1000))
    pairs = [(i, s) for i, s in db.execute(stmt).all() if inventory.endpoint_for(i, s) is not None]
    out = {"checked": 0, "ok": 0, "failed": 0, "mismatch": 0, "events": 0}
    for n in range(0, len(pairs), batch):
        chunk = pairs[n:n + batch]
        results = inventory.verify_installations(db, [i for i, _ in chunk])
        for (inst, server), res in zip(chunk, results, strict=True):
            out["checked"] += 1
            if not res["ok"]:
                out["failed"] += 1
                continue
            out["ok"] += 1
            served = res.get("served_fingerprint") or ""
            if res.get("matches_file") is False:
                out["mismatch"] += 1
                if inst.drift_status in ("in_sync", "unknown"):
                    inst.drift_status = "drifted"
                made = notifications.notify(
                    db, "drift.detected", "high",
                    {"server_id": str(server.id), "server_name": server.name, "environment": server.environment,
                     "installation_id": str(inst.id), "cert_path": inst.cert_path, "source": "live_endpoint",
                     "expected_fingerprint": inst.last_observed_fingerprint, "observed_fingerprint": served,
                     "endpoint": f"{res['endpoint']['host']}:{res['endpoint']['port']}"},
                    f"drift:{inst.id}:{served[:16]}")
                out["events"] += len(made)
            not_after = res.get("served_not_after")
            if not_after:
                days = days_remaining(datetime.fromisoformat(not_after), now)
                st = expiry_status(days, th)
                ev = expiry_event(st)
                if ev is not None:
                    made = notifications.notify(
                        db, ev[0], ev[1],
                        {"common_name": res.get("served_common_name"), "days_remaining": days, "expiry_status": st,
                         "not_after": not_after, "source": "live_endpoint", "server_id": str(server.id),
                         "server_name": server.name, "environment": server.environment,
                         "installation_id": str(inst.id),
                         "endpoint": f"{res['endpoint']['host']}:{res['endpoint']['port']}"},
                        f"endpoint-expiry:{inst.id}:{st}")
                    out["events"] += len(made)
        db.commit()
    return out
