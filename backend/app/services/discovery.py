"""Server discovery: connect -> probe -> adapters -> resolve certificates -> filesystem scan -> classify -> upsert.

Layers
* ``collect`` (async, no DB) talks to a ``RemoteHost`` and returns a :class:`Collection` of
  :class:`~app.services.inventory.DiscoveredInstallation` -- unit-testable with a fake host.
* ``persist_collection`` (sync) upserts certificates/installations idempotently and marks vanished installations.
* ``execute_job`` is what the Celery task ``discovery.run`` calls; ``start_discovery`` / ``start_bulk`` are the API entries.

Private keys are never read: certificate files are read with ``read_public_file`` (the helper refuses key material)
and key paths are only ``stat``-ed.
"""
from __future__ import annotations

import asyncio
import fnmatch
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.core.errors import AppError, conflict, not_found
from app.core.logging import get_logger
from app.core.permissions import authorize
from app.integrations.certificates import parse_upload
from app.integrations.certificates.parse import classify_pem
from app.integrations.contracts import (
    CertInfo,
    ConfigCertRef,
    FileKind,
    HostProbe,
    RemoteError,
    RemoteErrorCode,
    RemoteFileStat,
    ServiceType,
)
from app.models import (
    CertificateInstallation,
    DiscoveryFinding,
    DiscoveryJob,
    Server,
    User,
)
from app.models.base import utcnow
from app.services import audit, events, inventory, notifications
from app.services import settings as settings_service
from app.services.inventory import DiscoveredInstallation

log = get_logger(__name__)

CERTBOT_LIVE = "/etc/letsencrypt/live/"
CERTBOT_ARCHIVE = "/etc/letsencrypt/archive/"
STALE_AFTER = timedelta(minutes=30)
JOB_TIMEOUT_SECONDS = 20 * 60
ProgressFn = Callable[[str, int, str], None]


def is_certbot_path(path: str | None, realpath: str | None = None) -> bool:
    return bool((path and path.startswith(CERTBOT_LIVE)) or (realpath and realpath.startswith(CERTBOT_ARCHIVE)))


# =============================================================================================== collection
@dataclass
class Note:
    """A finding that is not an installation (unsupported file, failed service, ...)."""
    path: str | None
    classification: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Collection:
    probe: HostProbe | None = None
    items: list[DiscoveredInstallation] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    ok_services: set[str] = field(default_factory=set)
    failed_services: dict[str, str] = field(default_factory=dict)


def _stat_meta(st: RemoteFileStat | None) -> dict[str, Any] | None:
    if st is None:
        return None
    return {"path": st.path, "exists": st.exists, "file_type": st.file_type, "realpath": st.realpath,
            "symlink_target": st.symlink_target, "broken_symlink": st.broken_symlink,
            "mode": oct(st.mode) if st.mode is not None else None, "owner": st.owner, "group": st.group,
            "size": st.size, "sha256": st.sha256, "selinux_context": st.selinux_context, "readable": st.readable}


def _err_text(exc: RemoteError) -> str:
    return exc.message[:200]


class _Resolver:
    def __init__(self, host: Any, endpoint_host: str, probe_fn: Callable | None, timeout: float):
        self.host, self.endpoint_host, self.probe_fn, self.timeout = host, endpoint_host, probe_fn, timeout
        self.stats: dict[str, RemoteFileStat | RemoteError] = {}
        self.referenced_realpaths: set[str] = set()
        self.referenced_paths: set[str] = set()

    async def stat(self, path: str) -> RemoteFileStat:
        cached = self.stats.get(path)
        if isinstance(cached, RemoteError):
            raise cached
        if cached is not None:
            return cached
        try:
            st = await self.host.stat(path)
        except RemoteError as exc:
            self.stats[path] = exc
            raise
        self.stats[path] = st
        return st

    async def endpoint_leaf(self, port: int | None, sni: str | None) -> tuple[CertInfo | None, tuple[CertInfo, ...], str | None]:
        if self.probe_fn is None or not port:
            return None, (), "no live endpoint available"
        res = await self.probe_fn(self.endpoint_host, port, sni, self.timeout)
        if not res.ok or res.leaf is None:
            return None, (), res.error or "endpoint did not present a certificate"
        return res.leaf, tuple(res.chain), None

    async def resolve(self, ref: ConfigCertRef, adapter: Any) -> DiscoveredInstallation:
        names = tuple(n for n in ref.server_names if n)
        ports = tuple(ref.listen_ports)
        vhost = (",".join(sorted(names)) or "-") + ":" + ",".join(str(p) for p in sorted(ports)) if (names or ports) else None
        d = DiscoveredInstallation(
            service_type=ref.service.value, cert_path=ref.cert_path, vhost=vhost[:255] if vhost else None,
            classification="unsupported", confidence=max(0.0, min(1.0, ref.confidence)), message="",
            key_path=ref.key_path, chain_path=ref.chain_path, is_combined_pem=ref.is_combined_pem,
            listen_port=ports[0] if ports else None, config_file=ref.config_file,
            service_identifier=(ref.context or "")[:255] or None, server_names=names,
            file_metadata={"line": ref.line, "context": ref.context},
        )
        # default verification endpoint (server address + listen port + SNI from server_names)
        try:
            eps = adapter.default_verify_endpoints(ref)
        except Exception:  # noqa: BLE001
            eps = []
        if eps:
            _, port, sni = eps[0]
            d.verify_host, d.verify_port, d.verify_sni = self.endpoint_host, port, sni
        elif d.listen_port:
            d.verify_host, d.verify_port = self.endpoint_host, d.listen_port

        if ref.unresolved_expression:
            d.message = f"certificate path uses an unresolved expression ({ref.unresolved_expression[:80]}); not supported"
            d.file_metadata["unresolved_expression"] = ref.unresolved_expression
            return d
        if not ref.cert_path:
            d.message = "no certificate path could be resolved from the configuration"
            return d
        if ref.is_directory:
            d.classification, d.message = "requires_mapping", "directory of certificates; map individual files to deploy"
            return d
        self.referenced_paths.add(ref.cert_path)

        # ---- stat the certificate file
        try:
            st = await self.stat(ref.cert_path)
        except RemoteError as exc:
            if exc.code in (RemoteErrorCode.PERMISSION_DENIED, RemoteErrorCode.PATH_NOT_ALLOWED):
                d.classification, d.message = "unreadable", f"cannot access certificate file: {_err_text(exc)}"
            else:
                d.classification, d.message = "error", f"cannot stat certificate file: {_err_text(exc)}"
            return d
        d.file_metadata["cert_stat"] = _stat_meta(st)
        if st.realpath:
            self.referenced_realpaths.add(st.realpath)
        d.managed_by_certbot = is_certbot_path(ref.cert_path, st.realpath)
        if not st.exists:
            d.classification = "error"
            d.message = (f"broken symlink -> {st.symlink_target}" if st.broken_symlink
                         else "certificate file does not exist")
            d.notes.append("broken_symlink" if st.broken_symlink else "missing_file")
            return d
        if st.file_type == "dir":
            d.classification, d.message = "error", "certificate path is a directory"
            return d
        if not st.readable:
            d.classification, d.message = "unreadable", "certificate file is not readable by the service account"
            return d

        # ---- read + parse (public data only)
        cert: CertInfo | None = None
        chain: tuple[CertInfo, ...] = ()
        source = "file"
        try:
            data = await self.host.read_public_file(ref.cert_path)
        except RemoteError as exc:
            helper = exc.details.get("helper_error")
            if helper == "PRIVATE_KEY_REFUSED":
                # combined PEM (cert + key): the key must not be read, learn the certificate from the live endpoint
                cert, chain, err = await self.endpoint_leaf(d.verify_port, d.verify_sni)
                if cert is None:
                    d.classification = "unreadable"
                    d.message = f"file contains private key material and the live endpoint probe failed ({err})"
                    d.confidence = min(d.confidence, 0.3)
                    return d
                source = "endpoint"
                d.notes.append("fingerprint taken from live endpoint (file contains private key)")
                d.confidence = min(d.confidence, 0.7)
            elif exc.code in (RemoteErrorCode.PERMISSION_DENIED, RemoteErrorCode.PATH_NOT_ALLOWED):
                d.classification, d.message = "unreadable", f"cannot read certificate file: {_err_text(exc)}"
                return d
            elif exc.details.get("exit_status") == 11:
                d.classification, d.message = "unsupported", "certificate file is larger than the 1 MiB read limit"
                return d
            else:
                d.classification, d.message = "error", f"cannot read certificate file: {_err_text(exc)}"
                return d
        else:
            kind = classify_pem(data)
            bundle = parse_upload(cert_pem=data)
            if bundle.leaf is None:
                if kind in (FileKind.PKCS12, FileKind.JKS):
                    d.classification, d.message = "unsupported", f"unsupported certificate container ({kind.value})"
                else:
                    msgs = "; ".join(f.message for f in bundle.findings)[:200]
                    d.classification, d.message = "error", f"no certificate could be parsed ({msgs or kind.value})"
                return d
            cert, chain = bundle.leaf, tuple(bundle.chain)
        d.cert, d.chain = cert, chain
        d.file_metadata["fingerprint_source"] = source

        # ---- separate chain file (apache)
        if ref.chain_path:
            self.referenced_paths.add(ref.chain_path)
            try:
                cst = await self.stat(ref.chain_path)
                d.file_metadata["chain_stat"] = _stat_meta(cst)
                if cst.realpath:
                    self.referenced_realpaths.add(cst.realpath)
                if cst.exists and cst.readable:
                    extra = parse_upload(cert_pem=await self.host.read_public_file(ref.chain_path))
                    have = {c.fingerprint_sha256 for c in d.chain}
                    d.chain = d.chain + tuple(c for c in ([extra.leaf] if extra.leaf else []) + list(extra.chain)
                                              if c.fingerprint_sha256 not in have)
                else:
                    d.notes.append("chain file missing or unreadable")
            except RemoteError as exc:
                d.notes.append(f"chain file not readable: {_err_text(exc)}")

        # ---- key presence (stat only, never content)
        key_exists: bool | None = None
        if ref.is_combined_pem or source == "endpoint":
            key_exists = True if source == "endpoint" else None
        elif ref.key_path:
            self.referenced_paths.add(ref.key_path)
            try:
                kst = await self.stat(ref.key_path)
                key_exists = bool(kst.exists)
                d.file_metadata["key_stat"] = _stat_meta(kst)
                if kst.realpath:
                    self.referenced_realpaths.add(kst.realpath)
            except RemoteError as exc:
                d.notes.append(f"private key path not accessible: {_err_text(exc)}")
        d.file_metadata["key_exists"] = key_exists

        # ---- classification
        plan_error: str | None = None
        try:
            adapter.plan_files(ref)
        except Exception as exc:  # noqa: BLE001 - PlanError or anything adapter specific
            plan_error = str(exc)
        if d.managed_by_certbot:
            d.classification = "unmanaged"
            d.message = "certificate is managed by certbot (renewed by certbot; deployments would be overwritten)"
        elif plan_error:
            d.classification, d.message = "requires_mapping", f"cannot deploy automatically: {plan_error}"
            d.confidence = min(d.confidence, 0.6)
        elif key_exists is False or (key_exists is None and not ref.is_combined_pem):
            d.classification = "requires_mapping"
            d.message = "private key file was not found; confirm the key path before deploying"
            d.confidence = min(d.confidence, 0.6)
        else:
            d.classification, d.message = "managed", "certificate and key located; eligible for deployment"
        return d


async def _scan(host: Any, res: _Resolver, ssh: dict[str, Any], col: Collection, progress: ProgressFn) -> None:
    # the SSH layer only understands absolute path prefixes; glob-style excludes are applied here
    prefixes = [e for e in ssh["discovery_exclude"] if e.startswith("/") and not any(c in e for c in "*?[")]
    globs = [e for e in ssh["discovery_exclude"] if e not in prefixes]
    found = [
        (p, k) for p, k in await host.find_cert_files(ssh["discovery_roots"], ssh["discovery_max_depth"],
                                                      ssh["discovery_max_files"], prefixes)
        if not any(fnmatch.fnmatch(p, g) for g in globs)
    ]
    candidates: list[str] = []
    for path, kind in found:
        if path in res.referenced_paths:
            continue
        if kind in (FileKind.CERTIFICATE, FileKind.CERT_BUNDLE):
            candidates.append(path)
        elif kind in (FileKind.PKCS12, FileKind.JKS):
            col.notes.append(Note(path, "unsupported", f"{kind.value} container is not supported", {"kind": kind.value}))
        elif kind == FileKind.COMBINED_PEM:
            col.notes.append(Note(path, "unreadable", "combined PEM contains private key material; content not read",
                                  {"kind": kind.value}))
    progress("scan", 85, f"{len(candidates)} certificate file(s) found by filesystem scan")
    groups: dict[str, list[tuple[str, RemoteFileStat]]] = {}
    for path in sorted(candidates):
        try:
            st = await res.stat(path)
        except RemoteError as exc:
            col.notes.append(Note(path, "unreadable", f"cannot stat: {_err_text(exc)}"))
            continue
        if not st.exists or not st.readable:
            col.notes.append(Note(path, "unreadable" if st.exists else "error",
                                  "file not readable" if st.exists else "broken symlink or missing file"))
            continue
        groups.setdefault(st.realpath or path, []).append((path, st))
    for real, members in groups.items():
        if real in res.referenced_realpaths:
            continue
        # prefer the stable pointer (symlink, e.g. certbot "live") over the real file
        members.sort(key=lambda m: (m[1].file_type != "symlink", m[0]))
        path, st = members[0]
        try:
            data = await host.read_public_file(path)
        except RemoteError as exc:
            helper = exc.details.get("helper_error")
            col.notes.append(Note(path, "unreadable", f"cannot read: {helper or _err_text(exc)}"))
            continue
        bundle = parse_upload(cert_pem=data)
        if bundle.leaf is None:
            msg = "; ".join(f.message for f in bundle.findings)[:200] or "no certificate"
            col.notes.append(Note(path, "unsupported", f"not parsed: {msg}"))
            continue
        if bundle.leaf.is_ca:
            continue                         # CA certificates lying around are not server certificates
        d = DiscoveredInstallation(
            service_type=ServiceType.FILESYSTEM.value, cert_path=path, vhost=None, classification="unmanaged",
            confidence=0.5, message="certificate found by filesystem scan; no service configuration references it",
            cert=bundle.leaf, chain=tuple(bundle.chain), managed_by_certbot=is_certbot_path(path, st.realpath),
            file_metadata={"cert_stat": _stat_meta(st), "fingerprint_source": "file", "found_by": "filesystem_scan"},
            source="filesystem",
        )
        col.items.append(d)


async def collect(host: Any, *, endpoint_host: str, ssh: dict[str, Any], probe_fn: Callable | None = None,
                  adapter_for: Callable[[Any], Any] | None = None, progress: ProgressFn | None = None) -> Collection:
    """Run the whole read-only discovery workflow against ``host`` (a ``RemoteHost``)."""
    from app.integrations.services.adapters import UnsupportedServiceError, get_adapter

    progress = progress or (lambda *_: None)
    adapter_for = adapter_for or get_adapter
    col = Collection()
    progress("probe", 10, "probing host")
    col.probe = await host.probe()
    res = _Resolver(host, endpoint_host, probe_fn, float(min(ssh.get("connect_timeout", 10), 10)))
    installed = [sp for sp in col.probe.services if sp.installed]
    for n, sp in enumerate(installed):
        name = sp.service.value
        pct = 20 + int(50 * n / max(1, len(installed)))
        try:
            adapter = adapter_for(sp.service)
        except UnsupportedServiceError:
            col.notes.append(Note(None, "unsupported", f"no adapter for service {name}"))
            continue
        progress(f"service:{name}", pct, f"reading {name} configuration")
        try:
            refs = await adapter.discover(host)
        except RemoteError as exc:
            col.failed_services[name] = _err_text(exc)
            col.notes.append(Note(None, "error", f"{name} configuration could not be read: {_err_text(exc)}",
                                  {"service": name, "code": exc.code.value}))
            continue
        except Exception as exc:  # noqa: BLE001 - a parser bug on one service must not fail the whole job
            col.failed_services[name] = type(exc).__name__
            col.notes.append(Note(None, "error", f"{name} configuration could not be parsed ({type(exc).__name__})",
                                  {"service": name}))
            continue
        col.ok_services.add(name)
        progress(f"service:{name}", pct + 5, f"{len(refs)} certificate reference(s) in {name}")
        for ref in refs:
            col.items.append(await res.resolve(ref, adapter))
    progress("scan", 80, "scanning filesystem roots")
    try:
        await _scan(host, res, ssh, col, progress)
        col.ok_services.add(ServiceType.FILESYSTEM.value)
    except RemoteError as exc:
        col.failed_services[ServiceType.FILESYSTEM.value] = _err_text(exc)
        col.notes.append(Note(None, "error", f"filesystem scan failed: {_err_text(exc)}"))
    # one installation per identity (a service may declare the same cert in several blocks)
    seen: dict[tuple, DiscoveredInstallation] = {}
    for it in col.items:
        seen.setdefault((it.service_type, it.cert_path, it.vhost), it)
    col.items = list(seen.values())
    return col


# =============================================================================================== persistence
def persist_collection(db: Session, server: Server, col: Collection, now: datetime) -> dict[str, Any]:
    """Idempotent upsert. Returns stats + side-effect events (drift) for the caller to notify on."""
    th = inventory.thresholds(db)
    existing = {i.identity_key: i for i in db.scalars(
        select(CertificateInstallation).where(CertificateInstallation.server_id == server.id))}
    stats = {"references": len(col.items), "installations_created": 0, "installations_updated": 0,
             "certificates_created": 0, "marked_missing": 0, "by_classification": {}}
    seen_keys: set[str] = set()
    events_out: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for d in col.items:
        cert = None
        if d.cert is not None:
            cert, created_cert = inventory.upsert_certificate(db, d.cert, source=d.source, chain=d.chain, now=now, th=th)
            stats["certificates_created"] += int(created_cert)
        key = d.identity_key(server.id)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        inst, created, changes = inventory.upsert_installation(db, server, d, cert, existing.get(key), now)
        stats["installations_created" if created else "installations_updated"] += 1
        stats["by_classification"][d.classification] = stats["by_classification"].get(d.classification, 0) + 1
        if changes.get("drift_detected"):
            events_out.append({"type": "drift", "installation_id": inst.id, "cert_path": inst.cert_path, **changes["drift_detected"]})
        details: dict[str, Any] = {"installation_id": str(inst.id), "service_type": d.service_type,
                                   "confidence": d.confidence, "managed_by_certbot": d.managed_by_certbot,
                                   "notes": d.notes, "created": created}
        if d.cert is not None:
            details["fingerprint_sha256"] = d.cert.fingerprint_sha256
            details["common_name"] = d.cert.common_name
        if changes:
            details["changes"] = changes
        findings.append({"path": d.cert_path, "classification": d.classification, "message": d.message,
                         "details": details})
    for note in col.notes:
        findings.append({"path": note.path, "classification": note.classification, "message": note.message,
                         "details": {"kind": "note", **note.details}})
    # installations not seen any more (only for service types whose discovery completed)
    for key, inst in existing.items():
        if key in seen_keys or inst.missing_since is not None:
            continue
        if inst.service_type in col.ok_services:
            inst.drift_status, inst.missing_since = "missing", now
            stats["marked_missing"] += 1
            findings.append({"path": inst.cert_path, "classification": inst.classification,
                             "message": "installation no longer found on the server",
                             "details": {"installation_id": str(inst.id), "kind": "missing"}})
    stats["findings"] = len(findings)
    return {"stats": stats, "events": events_out, "findings": findings}


def _apply_probe(server: Server, probe: HostProbe, now: datetime) -> None:
    from app.services.connectivity import _to_dict

    server.os_family, server.os_version, server.os_pretty = probe.os_family, probe.os_version, probe.os_pretty
    server.detected_services = {
        "services": [_to_dict(sp) for sp in probe.services], "kernel": probe.kernel, "remote_user": probe.remote_user,
        "helper_version": probe.helper_version, "privilege_mode": probe.privilege_mode, "supported": probe.supported,
        "checked_at": now.isoformat(),
    }


# =============================================================================================== job lifecycle (API)
def job_out(job: DiscoveryJob, server_name: str | None = None, findings: list[DiscoveryFinding] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": job.id, "server_id": job.server_id, "server_name": server_name, "requested_by": job.requested_by,
        "scheduled": job.requested_by is None, "status": job.status, "started_at": job.started_at,
        "finished_at": job.finished_at, "stats": job.stats, "error": job.error, "created_at": job.created_at,
    }
    if findings is not None:
        out["findings"] = [{"id": f.id, "path": f.path, "classification": f.classification, "message": f.message,
                            "details": f.details, "created_at": f.created_at} for f in findings]
    return out


def _expire_stale(db: Session, server_id: uuid.UUID) -> None:
    cutoff = utcnow() - STALE_AFTER
    for j in db.scalars(select(DiscoveryJob).where(DiscoveryJob.server_id == server_id,
                                                   DiscoveryJob.status.in_(("pending", "running")),
                                                   func.coalesce(DiscoveryJob.started_at, DiscoveryJob.created_at) < cutoff)):
        j.status, j.finished_at, j.error = "failed", utcnow(), "abandoned: no progress for 30 minutes"
    db.flush()


def create_job(db: Session, server: Server, requested_by: User | None) -> DiscoveryJob:
    if not server.enabled:
        raise AppError("SERVER_DISABLED", "Server is disabled", 409)
    _expire_stale(db, server.id)
    running = db.scalar(select(DiscoveryJob.id).where(DiscoveryJob.server_id == server.id,
                                                      DiscoveryJob.status.in_(("pending", "running"))))
    if running:
        db.rollback()
        raise conflict("DISCOVERY_ALREADY_RUNNING", "A discovery job is already running for this server",
                       {"job_id": str(running)})
    job = DiscoveryJob(server_id=server.id, requested_by=requested_by.id if requested_by else None, status="pending")
    db.add(job)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise conflict("DISCOVERY_ALREADY_RUNNING", "A discovery job is already running for this server") from exc
    audit.record(db, action="DISCOVERY_REQUESTED", resource_type="server", resource_id=server.id, actor=requested_by,
                 actor_name=None if requested_by else "system", after={"job_id": str(job.id)})
    db.commit()
    return job


def _enqueue(db: Session, job: DiscoveryJob) -> None:
    from app.workers.celery_app import enqueue

    try:
        enqueue("discovery.run", str(job.id))
    except Exception as exc:
        job.status, job.finished_at, job.error = "failed", utcnow(), "job queue unavailable"
        db.commit()
        log.error("discovery_enqueue_failed", error=type(exc).__name__)
        raise AppError("QUEUE_UNAVAILABLE", "The job queue is unavailable; try again shortly", 503) from exc


def start_discovery(db: Session, user: User, server_id: uuid.UUID) -> DiscoveryJob:
    authorize(user, "discovery:run")
    server = db.get(Server, server_id)
    if server is None:
        raise not_found("SERVER_NOT_FOUND", "Server not found")
    job = create_job(db, server, user)
    _enqueue(db, job)
    db.refresh(job)
    return job


def start_bulk(db: Session, user: User, server_ids: list[uuid.UUID]) -> dict[str, Any]:
    authorize(user, "discovery:run")
    jobs, errors = [], []
    for sid in dict.fromkeys(server_ids):
        try:
            j = start_discovery(db, user, sid)
            jobs.append(job_out(j, db.scalar(select(Server.name).where(Server.id == sid))))
        except AppError as exc:
            errors.append({"server_id": str(sid), "code": exc.code, "message": exc.message})
    return {"jobs": jobs, "errors": errors}


def list_jobs(db: Session, *, offset: int, limit: int, server_id: uuid.UUID | None = None,
              status: str | None = None) -> tuple[list[dict[str, Any]], int]:
    stmt = select(DiscoveryJob, Server.name).join(Server, Server.id == DiscoveryJob.server_id)
    if server_id:
        stmt = stmt.where(DiscoveryJob.server_id == server_id)
    if status:
        stmt = stmt.where(DiscoveryJob.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(DiscoveryJob.created_at.desc()).offset(offset).limit(limit)).all()
    return [job_out(j, name) for j, name in rows], total


def get_job(db: Session, job_id: uuid.UUID) -> dict[str, Any]:
    job = db.get(DiscoveryJob, job_id)
    if job is None:
        raise not_found("DISCOVERY_JOB_NOT_FOUND", "Discovery job not found")
    findings = list(db.scalars(select(DiscoveryFinding).where(DiscoveryFinding.job_id == job_id)
                               .order_by(DiscoveryFinding.created_at, DiscoveryFinding.path)))
    return job_out(job, db.scalar(select(Server.name).where(Server.id == job.server_id)), findings)


def schedule_due(db: Session, now: datetime | None = None) -> list[uuid.UUID]:
    """Create jobs (system actor) for enabled, enrolled servers whose last discovery is older than the refresh interval."""
    now = now or utcnow()
    interval = timedelta(minutes=settings_service.get_section_data(db, "general")["inventory_refresh_minutes"])
    due = db.scalars(select(Server).where(
        Server.enabled.is_(True), Server.credential_id.is_not(None), Server.host_public_key.is_not(None),
        (Server.last_discovery_at.is_(None)) | (Server.last_discovery_at <= now - interval),
    ).order_by(Server.last_discovery_at.asc().nulls_first()).limit(200)).all()
    out = []
    for s in due:
        try:
            job = create_job(db, s, None)
        except AppError:
            continue
        out.append(job.id)
    return out


# =============================================================================================== job execution (worker)
def _fail(db: Session, job: DiscoveryJob, server: Server | None, code: str, message: str, *, remote_code: str | None = None,
          scheduled: bool = False) -> str:
    from app.services.connectivity import _STATUS_BY_ERROR

    now = utcnow()
    job.status, job.finished_at, job.error = "failed", now, f"{code}: {message}"[:1000]
    if job.stats is None:
        job.stats = {}
    if server is not None:
        server.last_discovery_at, server.last_discovery_status, server.discovery_error = now, "failed", message[:500]
        if remote_code:
            server.connection_status = _STATUS_BY_ERROR.get(remote_code, "error")
    audit.record(db, action="DISCOVERY_FAILED", resource_type="server", resource_id=job.server_id,
                 actor_name="system" if job.requested_by is None else None, outcome="failure", error=message,
                 after={"job_id": str(job.id), "code": code})
    payload = {"server_id": str(job.server_id), "server_name": server.name if server else None,
               "environment": server.environment if server else None, "job_id": str(job.id), "error_code": code,
               "error": message[:300], "scheduled": scheduled}
    day = now.strftime("%Y-%m-%d")
    try:
        if code == "HOST_KEY_MISMATCH":
            audit.record(db, action="HOST_KEY_CHANGED", resource_type="server", resource_id=job.server_id,
                         actor_name="system", outcome="failure", error="presented host key differs from the enrolled key")
            notifications.notify(db, "hostkey.changed", "critical", payload, f"hostkey.changed:{job.server_id}:{day}")
        else:
            notifications.notify(db, "discovery.failed", "high" if scheduled else "warning", payload,
                                 f"discovery.failed:{job.server_id}:{day}")
        if remote_code in ("TIMEOUT", "CONNECTION_REFUSED", "DNS_FAILURE", "AUTH_REJECTED"):
            notifications.notify(db, "server.unreachable", "high", payload, f"server.unreachable:{job.server_id}")
    except Exception as exc:  # noqa: BLE001 - notification problems must not mask the discovery result
        log.error("discovery_notify_failed", error=type(exc).__name__)
    db.commit()
    events.publish_job_event("discovery", job.id, {"type": "done", "status": "failed", "error_code": code,
                                                   "message": message[:300], "percent": 100})
    return "failed"


def execute_job(job_id: uuid.UUID | str, *, connect_factory: Callable | None = None,
                probe_fn: Callable | None = None) -> str:
    """Run one discovery job to completion. Returns the final job status (or 'skipped'/'missing').

    ``connect_factory(target, credential)`` -> async context manager yielding a RemoteHost (tests inject fakes).
    """
    jid = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, jid, with_for_update=True)
        if job is None:
            return "missing"
        now = utcnow()
        if job.status == "running" and job.started_at and now - job.started_at < STALE_AFTER:
            db.rollback()
            return "skipped"                       # another worker is on it
        if job.status not in ("pending", "running"):
            db.rollback()
            return "skipped"
        server = db.get(Server, job.server_id)
        scheduled = job.requested_by is None
        job.status, job.started_at = "running", now
        db.commit()
        events.publish_job_event("discovery", jid, {"type": "status", "status": "running", "percent": 2,
                                                    "message": "discovery started"})
        # --- re-authorize the initiating user (rights may have changed since the request was queued)
        if not scheduled:
            user = db.get(User, job.requested_by)
            try:
                if user is None:
                    raise AppError("FORBIDDEN", "Requesting user no longer exists", 403)
                authorize(user, "discovery:run")
            except AppError as exc:
                audit.record(db, action="DISCOVERY_FAILED", resource_type="server", resource_id=job.server_id,
                             actor=user, outcome="denied", error=exc.message)
                return _fail(db, job, server, "AUTHORIZATION_REVOKED", exc.message, scheduled=scheduled)
        if server is None:
            return _fail(db, job, None, "SERVER_NOT_FOUND", "server was deleted", scheduled=scheduled)
        if not server.enabled:
            return _fail(db, job, server, "SERVER_DISABLED", "server is disabled", scheduled=scheduled)

        ssh_settings = settings_service.get_section_data(db, "ssh")
        from app.services import connectivity

        try:
            target = connectivity.build_target(server, ssh_settings)
            credential = connectivity.load_credential(server)
        except AppError as exc:
            return _fail(db, job, server, exc.code, exc.message, scheduled=scheduled)
        endpoint_host = server.address or server.hostname

        def progress(stage: str, pct: int, message: str) -> None:
            events.publish_job_event("discovery", jid, {"type": "progress", "stage": stage, "percent": pct,
                                                        "message": message})

        async def run() -> Collection:
            from app.integrations.ssh import connect

            cf = connect_factory or connect
            async with cf(target, credential) as host:
                progress("connected", 8, "connected")
                return await asyncio.wait_for(
                    collect(host, endpoint_host=endpoint_host, ssh=ssh_settings, probe_fn=probe_fn or _default_probe,
                            progress=progress),
                    timeout=JOB_TIMEOUT_SECONDS)

        progress("connecting", 4, f"connecting to {endpoint_host}")
        try:
            col = asyncio.run(run())
        except RemoteError as exc:
            return _fail(db, job, server, exc.code.value, exc.message, remote_code=exc.code.value, scheduled=scheduled)
        except TimeoutError:
            return _fail(db, job, server, "TIMEOUT", "discovery timed out", remote_code="TIMEOUT", scheduled=scheduled)
        except AppError as exc:
            return _fail(db, job, server, exc.code, exc.message, scheduled=scheduled)
        except Exception as exc:
            log.error("discovery_unexpected_error", job_id=str(jid), error=type(exc).__name__, exc_info=exc)
            return _fail(db, job, server, "UNEXPECTED_ERROR", f"unexpected error ({type(exc).__name__})",
                         scheduled=scheduled)

        progress("persisting", 92, "saving results")
        now = utcnow()
        try:
            result = persist_collection(db, server, col, now)
        except Exception as exc:
            db.rollback()
            log.error("discovery_persist_failed", job_id=str(jid), error=type(exc).__name__, exc_info=exc)
            job = db.get(DiscoveryJob, jid)
            server = db.get(Server, job.server_id)
            return _fail(db, job, server, "PERSIST_FAILED", f"could not save results ({type(exc).__name__})",
                         scheduled=scheduled)
        if col.probe is not None:
            _apply_probe(server, col.probe, now)
        partial = bool(col.failed_services)
        stats = result["stats"]
        stats.update({"services": sorted(col.ok_services), "failed_services": col.failed_services,
                      "duration_ms": int((now - job.started_at).total_seconds() * 1000)})
        job.status, job.finished_at, job.stats = ("partial" if partial else "completed"), now, stats
        job.error = ("; ".join(f"{k}: {v}" for k, v in col.failed_services.items())[:1000]) if partial else None
        server.connection_status, server.last_connected_at = "connected", now
        server.last_discovery_at, server.last_discovery_status = now, job.status
        server.discovery_error = job.error
        for f in result["findings"]:
            db.add(DiscoveryFinding(job_id=jid, path=f["path"], classification=f["classification"][:24],
                                    message=(f["message"] or "")[:2000], details=f["details"]))
        audit.record(db, action="DISCOVERY_COMPLETED", resource_type="server", resource_id=server.id,
                     actor_name="system" if scheduled else None, after={"job_id": str(jid), "status": job.status,
                                                                         **{k: v for k, v in stats.items() if isinstance(v, (int, str))}})
        for ev in result["events"]:
            notifications.notify(
                db, "drift.detected", "high",
                {"server_id": str(server.id), "server_name": server.name, "environment": server.environment,
                 "installation_id": str(ev["installation_id"]), "cert_path": ev["cert_path"],
                 "expected_fingerprint": ev["expected"], "observed_fingerprint": ev["observed"]},
                f"drift:{ev['installation_id']}:{(ev['observed'] or '')[:16]}")
        if partial:
            notifications.notify(db, "discovery.failed", "warning",
                                 {"server_id": str(server.id), "server_name": server.name,
                                  "environment": server.environment, "job_id": str(jid), "error": job.error[:300],
                                  "error_code": "PARTIAL", "scheduled": scheduled},
                                 f"discovery.partial:{server.id}:{now.strftime('%Y-%m-%d')}")
        db.commit()
        events.publish_job_event("discovery", jid, {"type": "done", "status": job.status, "percent": 100,
                                                    "message": "discovery finished", "stats": stats})
        return job.status


async def _default_probe(host: str, port: int, sni: str | None, timeout: float):
    from app.integrations.tls.probe import probe_endpoint

    return await probe_endpoint(host, port, sni, timeout)
