"""Certificate & installation inventory: queries, upserts (used by discovery), mapping and endpoint verification."""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
from app.integrations.certificates import days_remaining, expiry_status
from app.integrations.contracts import CertInfo
from app.models import (
    Backup,
    Certificate,
    CertificateInstallation,
    CertificateVersion,
    DeploymentJob,
    DeploymentTarget,
    Server,
    User,
)
from app.models.base import utcnow
from app.models.certificate import make_identity_key
from app.services import audit, trust
from app.services import settings as settings_service
from app.services.cert_status import compute_status

DEPLOYABLE_TYPES = ("leaf", "self_signed")
USER_MANAGED_KEYS = ("owner", "tags", "verify_mapped", "classification_override")


# ------------------------------------------------------------------------------------------- thresholds / status
def thresholds(db: Session) -> dict[str, int]:
    return dict(settings_service.get_section_data(db, "notifications")["thresholds"])


def expiry_view(not_after: datetime, now: datetime, th: dict[str, int]) -> dict[str, Any]:
    days = days_remaining(not_after, now)
    return {"days_remaining": days, "expiry_status": expiry_status(days, th)}


def db_status(not_after: datetime, now: datetime, th: dict[str, int]) -> str:
    return compute_status(not_after, now, warn_days=th["warning"], critical_days=th["critical"])


def _cert_type(info: CertInfo) -> str:
    if info.is_ca:
        return "root" if info.is_self_signed else "intermediate"
    return "self_signed" if info.is_self_signed else "leaf"


# ------------------------------------------------------------------------------------------- upserts
@dataclass
class DiscoveredInstallation:
    """One result of discovery, independent of how it was found (pure data; no DB objects)."""
    service_type: str
    cert_path: str | None
    vhost: str | None
    classification: str
    confidence: float
    message: str
    cert: CertInfo | None = None
    chain: tuple[CertInfo, ...] = ()
    key_path: str | None = None
    chain_path: str | None = None
    is_combined_pem: bool = False
    listen_port: int | None = None
    config_file: str | None = None
    service_identifier: str | None = None
    server_names: tuple[str, ...] = ()
    managed_by_certbot: bool = False
    verify_host: str | None = None
    verify_port: int | None = None
    verify_sni: str | None = None
    file_metadata: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    source: str = "config"                     # "config" | "filesystem"

    def identity_key(self, server_id: uuid.UUID) -> str:
        return make_identity_key(server_id, self.service_type, self.cert_path, self.vhost)


def upsert_certificate(db: Session, info: CertInfo, *, source: str, chain: tuple[CertInfo, ...], now: datetime,
                       th: dict[str, int]) -> tuple[Certificate, bool]:
    cert = db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == info.fingerprint_sha256))
    chain_info = {"chain": [{"subject": c.subject, "issuer": c.issuer, "fingerprint_sha256": c.fingerprint_sha256,
                             "not_after": c.not_after.isoformat(), "is_self_signed": c.is_self_signed}
                            for c in chain]} if chain else None
    status = db_status(info.not_after, now, th)
    if cert is None:
        cert = Certificate(
            fingerprint_sha256=info.fingerprint_sha256, common_name=info.common_name, subject=info.subject,
            sans=list(info.sans), issuer=info.issuer, serial_number=info.serial_number,
            public_key_algorithm=info.public_key_algorithm, public_key_size=info.public_key_size,
            public_key_sha256=info.public_key_sha256, signature_algorithm=info.signature_algorithm,
            not_before=info.not_before, not_after=info.not_after, is_ca=info.is_ca, chain_info=chain_info,
            certificate_type=_cert_type(info), discovery_source=source, status=status, pem=info.pem,
        )
        db.add(cert)
        db.flush()
        return cert, True
    cert.status = status
    if chain_info and not cert.chain_info:
        cert.chain_info = chain_info
    return cert, False


def expected_fingerprint(db: Session, inst: CertificateInstallation) -> str | None:
    """Fingerprint the last deployment left on this installation (None if never deployed by us)."""
    if inst.last_deployment_id is None:
        return None
    t = db.scalar(select(DeploymentTarget).where(DeploymentTarget.job_id == inst.last_deployment_id,
                                                  DeploymentTarget.installation_id == inst.id))
    if t is None:
        return None
    if t.status == "completed":
        return t.new_fingerprint
    if t.status == "rolled_back":
        return t.previous_fingerprint
    return None


def upsert_installation(db: Session, server: Server, d: DiscoveredInstallation, cert: Certificate | None,
                        existing: CertificateInstallation | None, now: datetime) -> tuple[CertificateInstallation, bool, dict]:
    """Create/update the installation for ``d``. Returns (installation, created, changes)."""
    created = existing is None
    inst = existing or CertificateInstallation(server_id=server.id, service_type=d.service_type,
                                               identity_key=d.identity_key(server.id), vhost=d.vhost,
                                               cert_path=d.cert_path)
    changes: dict[str, Any] = {}
    observed = d.cert.fingerprint_sha256 if d.cert else None
    prev_obs, prev_drift, prev_cls = inst.last_observed_fingerprint, inst.drift_status, inst.classification
    meta = dict(inst.file_metadata or {})

    inst.certificate_id = cert.id if cert else None
    inst.service_identifier = d.service_identifier
    inst.key_path, inst.chain_path = d.key_path, d.chain_path
    inst.is_combined_pem = d.is_combined_pem
    inst.listen_port = d.listen_port
    inst.config_file = d.config_file
    inst.server_names = list(d.server_names)
    inst.managed_by_certbot = d.managed_by_certbot
    inst.discovery_confidence = d.confidence
    inst.missing_since = None
    if observed:
        inst.last_observed_fingerprint = observed
        inst.last_observed_at = now
    # operator overrides survive re-discovery
    if meta.get("classification_override") and d.classification in ("managed", "unmanaged", "requires_mapping"):
        inst.classification = inst.classification if not created else d.classification
    else:
        inst.classification = d.classification
    if not meta.get("verify_mapped"):
        inst.verify_host, inst.verify_port, inst.verify_sni = d.verify_host, d.verify_port, d.verify_sni
    new_meta = {k: meta[k] for k in USER_MANAGED_KEYS if k in meta}
    new_meta.update(d.file_metadata)
    inst.file_metadata = new_meta

    # drift: compare what is on disk now with what our last deployment put there
    expected = expected_fingerprint(db, inst)
    if observed is None:
        inst.drift_status = "unknown"
    elif expected is not None and observed != expected:
        inst.drift_status = "drifted"
    else:
        inst.drift_status = "in_sync"
    if created:
        db.add(inst)
    db.flush()
    if prev_obs and observed and prev_obs != observed:
        changes["fingerprint_changed"] = {"from": prev_obs, "to": observed}
    if inst.drift_status == "drifted" and prev_drift != "drifted":
        changes["drift_detected"] = {"expected": expected, "observed": observed}
    if not created and prev_cls != inst.classification:
        changes["classification_changed"] = {"from": prev_cls, "to": inst.classification}
    return inst, created, changes


# ------------------------------------------------------------------------------------------- serialization
def _server_brief(s: Server | None) -> dict[str, Any]:
    if s is None:
        return {"server_name": None, "server_address": None, "environment": None}
    return {"server_name": s.name, "server_address": s.address or s.hostname, "environment": s.environment}


def certificate_summary(c: Certificate, now: datetime, th: dict[str, int], inst_count: int = 0,
                        server_count: int = 0) -> dict[str, Any]:
    return {
        "id": c.id, "common_name": c.common_name, "subject": c.subject, "issuer": c.issuer, "sans": list(c.sans or []),
        "serial_number": c.serial_number, "fingerprint_sha256": c.fingerprint_sha256,
        "not_before": c.not_before, "not_after": c.not_after, "public_key_algorithm": c.public_key_algorithm,
        "public_key_size": c.public_key_size, "signature_algorithm": c.signature_algorithm,
        "certificate_type": c.certificate_type, "status": c.status, **expiry_view(c.not_after, now, th),
        "installation_count": inst_count, "server_count": server_count, "owner": c.owner, "tags": list(c.tags or []),
        "discovery_source": c.discovery_source, "created_at": c.created_at, "updated_at": c.updated_at,
    }


def installation_out(i: CertificateInstallation, server: Server | None, cert: Certificate | None, now: datetime,
                     th: dict[str, int]) -> dict[str, Any]:
    meta = i.file_metadata or {}
    return {
        "id": i.id, "certificate_id": i.certificate_id,
        "certificate": ({"id": cert.id, "common_name": cert.common_name, "fingerprint_sha256": cert.fingerprint_sha256,
                         "not_after": cert.not_after, **expiry_view(cert.not_after, now, th)} if cert else None),
        "server_id": i.server_id, **_server_brief(server),
        "service_type": i.service_type, "service_identifier": i.service_identifier, "cert_path": i.cert_path,
        "key_path": i.key_path, "chain_path": i.chain_path, "is_combined_pem": i.is_combined_pem,
        "listen_port": i.listen_port, "config_file": i.config_file, "vhost": i.vhost,
        "server_names": list(i.server_names or []), "last_observed_fingerprint": i.last_observed_fingerprint,
        "last_observed_at": i.last_observed_at, "last_deployment_id": i.last_deployment_id,
        "drift_status": i.drift_status, "classification": i.classification,
        "discovery_confidence": i.discovery_confidence, "managed_by_certbot": i.managed_by_certbot,
        "verify_host": i.verify_host, "verify_port": i.verify_port, "verify_sni": i.verify_sni,
        "last_verification": i.last_verification, "missing_since": i.missing_since,
        "owner": meta.get("owner"), "tags": list(meta.get("tags") or []),
        "file_metadata": {k: v for k, v in meta.items() if k not in USER_MANAGED_KEYS},
        "created_at": i.created_at, "updated_at": i.updated_at,
    }


# ------------------------------------------------------------------------------------------- certificate queries
def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _status_range(status: str, now: datetime, th: dict[str, int]):
    """SQL condition on Certificate.not_after equivalent to expiry_status(days_remaining) == status."""
    from app.integrations.certificates.validate import DEFAULT_THRESHOLDS

    t = {**DEFAULT_THRESHOLDS, **th}
    d = lambda n: now + timedelta(days=n + 1)
    na = Certificate.not_after
    match status:
        case "expired":
            return na < now
        case "critical":
            return and_(na >= now, na < d(t["critical"]))
        case "high":
            return and_(na >= d(t["critical"]), na < d(t["high"]))
        case "warning":
            return and_(na >= d(t["high"]), na < d(t["warning"]))
        case "info":
            return and_(na >= d(t["warning"]), na < d(t["info"]))
        case "valid":
            return na >= d(t["info"])
        case "expiring":
            return and_(na >= now, na < d(t["warning"]))
    raise AppError("INVALID_STATUS", "status must be one of valid, info, warning, high, critical, expired, expiring", 422)


_SORTS = {
    "not_after": Certificate.not_after, "common_name": func.lower(Certificate.common_name),
    "created_at": Certificate.created_at, "issuer": Certificate.issuer,
}


def list_certificates(db: Session, *, q: str | None, status: str | None, expiring_within: int | None,
                      server_id: uuid.UUID | None, environment: str | None, include_ca: bool, sort: str,
                      offset: int, limit: int, now: datetime | None = None) -> tuple[list[dict[str, Any]], int]:
    now = now or utcnow()
    th = thresholds(db)
    agg = (select(CertificateInstallation.certificate_id.label("cid"), func.count().label("n_inst"),
                  func.count(func.distinct(CertificateInstallation.server_id)).label("n_srv"))
           .where(CertificateInstallation.missing_since.is_(None), CertificateInstallation.certificate_id.is_not(None))
           .group_by(CertificateInstallation.certificate_id).subquery())
    stmt = (select(Certificate, func.coalesce(agg.c.n_inst, 0), func.coalesce(agg.c.n_srv, 0))
            .outerjoin(agg, agg.c.cid == Certificate.id))
    if not include_ca:
        stmt = stmt.where(Certificate.certificate_type.in_(DEPLOYABLE_TYPES))
    if q:
        like = _like(q.strip())
        stmt = stmt.where(or_(
            Certificate.common_name.ilike(like, escape="\\"), Certificate.subject.ilike(like, escape="\\"),
            Certificate.issuer.ilike(like, escape="\\"), Certificate.serial_number.ilike(like, escape="\\"),
            Certificate.fingerprint_sha256.ilike(like, escape="\\"),
            func.array_to_string(Certificate.sans, ",").ilike(like, escape="\\"),
        ))
    if status:
        stmt = stmt.where(_status_range(status, now, th))
    if expiring_within is not None:
        stmt = stmt.where(Certificate.not_after < now + timedelta(days=expiring_within + 1))
    if server_id or environment:
        sub = select(CertificateInstallation.certificate_id).join(Server, Server.id == CertificateInstallation.server_id)
        if server_id:
            sub = sub.where(CertificateInstallation.server_id == server_id)
        if environment:
            sub = sub.where(Server.environment == environment)
        stmt = stmt.where(Certificate.id.in_(sub))
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    desc = sort.startswith("-")
    key = sort.lstrip("-")
    if key == "installations":
        col = func.coalesce(agg.c.n_inst, 0)
    elif key in _SORTS:
        col = _SORTS[key]
    else:
        raise AppError("INVALID_SORT", f"sort must be one of {', '.join(['installations', *_SORTS])} (prefix - for desc)", 422)
    stmt = stmt.order_by(col.desc() if desc else col.asc(), Certificate.id).offset(offset).limit(limit)
    rows = db.execute(stmt).all()
    return [certificate_summary(c, now, th, int(n), int(s)) for c, n, s in rows], total


def get_certificate(db: Session, cert_id: uuid.UUID) -> Certificate:
    c = db.get(Certificate, cert_id)
    if c is None:
        raise not_found("CERTIFICATE_NOT_FOUND", "Certificate not found")
    return c


def certificate_detail(db: Session, cert_id: uuid.UUID, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    th = thresholds(db)
    c = get_certificate(db, cert_id)
    insts = db.scalars(select(CertificateInstallation).where(CertificateInstallation.certificate_id == c.id)
                       .order_by(CertificateInstallation.created_at)).all()
    servers = {s.id: s for s in db.scalars(select(Server).where(Server.id.in_({i.server_id for i in insts})))} if insts else {}
    active = [i for i in insts if i.missing_since is None]
    out = certificate_summary(c, now, th, len(active), len({i.server_id for i in active}))
    out["pem"] = c.pem
    out["chain_info"] = c.chain_info
    out["is_ca"] = c.is_ca
    out["installations"] = [installation_out(i, servers.get(i.server_id), c, now, th) for i in insts]
    versions = db.scalars(select(CertificateVersion).where(CertificateVersion.certificate_id == c.id)
                          .order_by(CertificateVersion.created_at.desc()).limit(50)).all()
    out["versions"] = [{
        "id": v.id, "fingerprint_sha256": v.fingerprint_sha256, "validation_status": v.validation_status,
        "status": v.status, "reuses_existing_key": v.reuses_existing_key, "uploaded_by": v.uploaded_by,
        "created_at": v.created_at, "not_after": (v.leaf_metadata or {}).get("not_after"),
        "common_name": (v.leaf_metadata or {}).get("common_name"),
    } for v in versions]
    ids = [i.id for i in insts]
    deployments: list[dict[str, Any]] = []
    backups: list[dict[str, Any]] = []
    if ids:
        for t, j in db.execute(
            select(DeploymentTarget, DeploymentJob).join(DeploymentJob, DeploymentJob.id == DeploymentTarget.job_id)
            .where(DeploymentTarget.installation_id.in_(ids)).order_by(DeploymentJob.created_at.desc()).limit(50)
        ).all():
            deployments.append({
                "id": j.id, "status": j.status, "created_at": j.created_at, "finished_at": j.finished_at,
                "version_id": j.version_id, "target_id": t.id, "target_status": t.status,
                "installation_id": t.installation_id, "server_id": t.server_id,
                "previous_fingerprint": t.previous_fingerprint, "new_fingerprint": t.new_fingerprint,
            })
        for b in db.scalars(select(Backup).where(Backup.installation_id.in_(ids))
                            .order_by(Backup.created_at.desc()).limit(50)):
            backups.append({"id": b.id, "server_id": b.server_id, "installation_id": b.installation_id,
                            "created_at": b.created_at, "verified": b.verified, "restore_status": b.restore_status,
                            "retention_until": b.retention_until})
    out["deployments"] = deployments
    out["backups"] = backups
    counts = {k: sum(1 for i in active if i.drift_status == k) for k in ("in_sync", "drifted", "missing", "unknown")}
    counts["missing"] += len(insts) - len(active)
    out["drift"] = {**counts, "installation_ids": [i.id for i in insts if i.drift_status in ("drifted", "missing")
                                                    or i.missing_since is not None]}
    return out


# ------------------------------------------------------------------------------------------- installation queries
def get_installation(db: Session, inst_id: uuid.UUID) -> CertificateInstallation:
    i = db.get(CertificateInstallation, inst_id)
    if i is None:
        raise not_found("INSTALLATION_NOT_FOUND", "Installation not found")
    return i


def installation_view(db: Session, i: CertificateInstallation, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    return installation_out(i, db.get(Server, i.server_id), db.get(Certificate, i.certificate_id) if i.certificate_id else None,
                            now, thresholds(db))


def list_installations(db: Session, *, offset: int, limit: int, server_id: uuid.UUID | None = None,
                       certificate_id: uuid.UUID | None = None, classification: str | None = None,
                       drift_status: str | None = None, service_type: str | None = None,
                       environment: str | None = None, q: str | None = None, include_missing: bool = True,
                       ) -> tuple[list[dict[str, Any]], int]:
    now = utcnow()
    th = thresholds(db)
    stmt = (select(CertificateInstallation, Server, Certificate)
            .join(Server, Server.id == CertificateInstallation.server_id)
            .outerjoin(Certificate, Certificate.id == CertificateInstallation.certificate_id))
    if server_id:
        stmt = stmt.where(CertificateInstallation.server_id == server_id)
    if certificate_id:
        stmt = stmt.where(CertificateInstallation.certificate_id == certificate_id)
    if classification:
        stmt = stmt.where(CertificateInstallation.classification == classification)
    if drift_status:
        stmt = stmt.where(CertificateInstallation.drift_status == drift_status)
    if service_type:
        stmt = stmt.where(CertificateInstallation.service_type == service_type)
    if environment:
        stmt = stmt.where(Server.environment == environment)
    if not include_missing:
        stmt = stmt.where(CertificateInstallation.missing_since.is_(None))
    if q:
        like = _like(q.strip())
        stmt = stmt.where(or_(CertificateInstallation.cert_path.ilike(like, escape="\\"),
                              Server.name.ilike(like, escape="\\"), Certificate.common_name.ilike(like, escape="\\"),
                              CertificateInstallation.vhost.ilike(like, escape="\\"),
                              cast(CertificateInstallation.server_names, String).ilike(like, escape="\\")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(Server.name, CertificateInstallation.cert_path, CertificateInstallation.id)
                      .offset(offset).limit(limit)).all()
    return [installation_out(i, s, c, now, th) for i, s, c in rows], total


def update_installation(db: Session, actor: User, inst_id: uuid.UUID, data: dict[str, Any]) -> dict[str, Any]:
    inst = get_installation(db, inst_id)
    before = {k: getattr(inst, k) for k in ("verify_host", "verify_port", "verify_sni", "classification")}
    before["owner"] = (inst.file_metadata or {}).get("owner")
    meta = dict(inst.file_metadata or {})
    if "classification" in data and data["classification"] is not None:
        new = data["classification"]
        if inst.classification in ("unsupported", "unreadable", "error") and new == "managed":
            raise AppError("CLASSIFICATION_NOT_ALLOWED",
                           "An installation that could not be read or parsed cannot be marked managed", 422)
        if new == "managed" and inst.certificate_id is None:
            raise AppError("CLASSIFICATION_NOT_ALLOWED", "No certificate was identified at this location", 422)
        inst.classification = new
        meta["classification_override"] = True
    for f in ("verify_host", "verify_port", "verify_sni"):
        if f in data:
            setattr(inst, f, data[f] or None)
            meta["verify_mapped"] = True
    if "owner" in data:
        meta["owner"] = data["owner"]
    if "tags" in data and data["tags"] is not None:
        meta["tags"] = list(data["tags"])
    inst.file_metadata = meta
    after = {k: getattr(inst, k) for k in ("verify_host", "verify_port", "verify_sni", "classification")}
    after["owner"] = meta.get("owner")
    audit.record(db, action="INSTALLATION_UPDATED", resource_type="installation", resource_id=inst.id, actor=actor,
                 before=before, after=after)
    db.commit()
    db.refresh(inst)
    return installation_view(db, inst)


# ------------------------------------------------------------------------------------------- verification
def endpoint_for(inst: CertificateInstallation, server: Server) -> tuple[str, int, str | None] | None:
    host = inst.verify_host or server.address or server.hostname
    port = inst.verify_port or inst.listen_port
    if not host or not port:
        return None
    sni = inst.verify_sni
    if sni is None:
        sni = next((n for n in (inst.server_names or []) if n and "*" not in n and n != "_" and not n.startswith("~")), None)
    return host, int(port), sni


async def _probe_all(endpoints: list[tuple[str, int, str | None]], timeout: float, anchors_pem: bytes | None,
                     concurrency: int = 8):
    from app.integrations.tls.probe import probe_endpoint

    sem = asyncio.Semaphore(concurrency)

    async def one(ep):
        async with sem:
            try:
                return await asyncio.wait_for(probe_endpoint(ep[0], ep[1], ep[2], timeout, anchors_pem),
                                              timeout=timeout * 3 + 2)
            except Exception as exc:  # noqa: BLE001 - one bad endpoint must not abort the batch
                return type("R", (), {"ok": False, "leaf": None, "chain_valid": None, "hostname_matches": None,
                                      "error": f"{type(exc).__name__}", "tls_version": None})()

    return await asyncio.gather(*(one(e) for e in endpoints))


def verification_record(inst: CertificateInstallation, ep: tuple[str, int, str | None], res: Any,
                        now: datetime) -> dict[str, Any]:
    leaf = getattr(res, "leaf", None)
    served = leaf.fingerprint_sha256 if leaf is not None else None
    return {
        "endpoint": {"host": ep[0], "port": ep[1], "sni": ep[2]}, "ok": bool(res.ok), "error": res.error,
        "served_fingerprint": served, "served_not_after": leaf.not_after.isoformat() if leaf else None,
        "served_common_name": leaf.common_name if leaf else None,
        "expected_fingerprint": inst.last_observed_fingerprint,
        "matches_file": (served == inst.last_observed_fingerprint) if served and inst.last_observed_fingerprint else None,
        "chain_valid": res.chain_valid, "hostname_matches": res.hostname_matches, "tls_version": res.tls_version,
        "checked_at": now.isoformat(),
    }


def verify_installations(db: Session, installs: list[CertificateInstallation]) -> list[dict[str, Any]]:
    """Probe each installation's endpoint (bounded timeouts) and store ``last_verification``. Inline, no commit."""
    ssh = settings_service.get_section_data(db, "ssh")
    timeout = float(min(ssh["connect_timeout"], 10))
    anchors = trust.anchors_pem_for_probe(db)
    servers = {s.id: s for s in db.scalars(select(Server).where(Server.id.in_({i.server_id for i in installs})))} if installs else {}
    plan: list[tuple[CertificateInstallation, tuple[str, int, str | None]]] = []
    results: dict[uuid.UUID, dict[str, Any]] = {}
    now = utcnow()
    for i in installs:
        ep = endpoint_for(i, servers[i.server_id])
        if ep is None:
            rec = {"endpoint": None, "ok": False, "error": "no verification endpoint (set verify host/port)",
                   "served_fingerprint": None, "matches_file": None, "chain_valid": None, "hostname_matches": None,
                   "checked_at": now.isoformat()}
            i.last_verification = rec
            results[i.id] = rec
        else:
            plan.append((i, ep))
    if plan:
        probed = asyncio.run(_probe_all([ep for _, ep in plan], timeout, anchors))
        for (i, ep), res in zip(plan, probed, strict=True):
            rec = verification_record(i, ep, res, now)
            i.last_verification = rec
            results[i.id] = rec
    return [{"installation_id": i.id, **results[i.id]} for i in installs]


def verify_installation(db: Session, actor: User, inst_id: uuid.UUID) -> dict[str, Any]:
    inst = get_installation(db, inst_id)
    res = verify_installations(db, [inst])[0]
    audit.record(db, action="INSTALLATION_VERIFIED", resource_type="installation", resource_id=inst.id, actor=actor,
                 after={"ok": res["ok"], "matches_file": res.get("matches_file"), "chain_valid": res.get("chain_valid"),
                        "hostname_matches": res.get("hostname_matches")})
    db.commit()
    return res


def verify_certificate(db: Session, actor: User, cert_id: uuid.UUID) -> dict[str, Any]:
    cert = get_certificate(db, cert_id)
    insts = list(db.scalars(
        select(CertificateInstallation).join(Server, Server.id == CertificateInstallation.server_id)
        .where(CertificateInstallation.certificate_id == cert.id, CertificateInstallation.missing_since.is_(None),
               CertificateInstallation.classification.notin_(("unsupported", "error")))
        .order_by(CertificateInstallation.created_at).limit(50)))
    results = verify_installations(db, insts)
    summary = {
        "total": len(results),
        "matching": sum(1 for r in results if r.get("matches_file") is True),
        "mismatching": sum(1 for r in results if r.get("matches_file") is False),
        "failed": sum(1 for r in results if not r["ok"]),
    }
    audit.record(db, action="CERTIFICATE_VERIFIED", resource_type="certificate", resource_id=cert.id, actor=actor,
                 after=summary)
    db.commit()
    return {"certificate_id": cert.id, "summary": summary, "results": results}
