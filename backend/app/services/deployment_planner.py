"""Deployment pre-flight and dry-run planning.

``build_plan`` performs a GENUINE read-only dry run against every target server: it stats every affected path,
reads the currently installed certificate, runs the service's config test, probes helper availability and the live
verify endpoint, and cross-checks shared paths, locks, other deployments and the candidate certificate. It never
writes anything remotely (no stage dirs, no backups, no installs) - ``tests/integration/test_deploy_live.py``
asserts that the remote filesystem is byte-identical afterwards.

The same function is re-run server-side when a deployment is created and again when the worker starts, so a client
supplied plan is never trusted.
"""
from __future__ import annotations

import asyncio
import hashlib
import posixpath
import uuid
from collections.abc import Callable, Iterable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import VaultError, get_vault
from app.core.errors import AppError
from app.core.logging import get_logger
from app.integrations.certificates import (
    ValidationPolicy,
    load_private_key,
    parse_pem_certificates,
    validate_bundle,
)
from app.integrations.certificates.errors import CertificateError
from app.integrations.contracts import (
    CertInfo,
    ParsedBundle,
    RemoteError,
    RemoteFileStat,
    RemoteHost,
    Severity,
)
from app.integrations.services.adapters import (
    ArtifactKind,
    PlanError,
    PlannedFile,
    UnsupportedServiceError,
    get_adapter,
)
from app.models import (
    CertificateInstallation,
    CertificateVersion,
    DeploymentJob,
    DeploymentTarget,
    Environment,
    Server,
)
from app.models.base import utcnow
from app.services import locks
from app.services import settings as settings_service
from app.services import trust as trust_service
from app.services.verify_sni import required_hostnames as _required_hostnames
from app.services.verify_sni import resolve_verify_sni

log = get_logger(__name__)

FINAL_JOB_STATUSES = frozenset({"completed", "failed", "rolled_back", "cancelled", "partially_failed",
                                "manual_intervention_required"})
FINAL_TARGET_STATUSES = FINAL_JOB_STATUSES
EXCEPTIONABLE_CODES = frozenset({"SAN_MISMATCH"})
MAX_FILE_BYTES = 10 * 1024 * 1024

HostFactory = Callable[[Server], AbstractAsyncContextManager[RemoteHost]]


# --------------------------------------------------------------------------- host access
def default_host_factory(server: Server) -> AbstractAsyncContextManager[RemoteHost]:
    """Strict host-key SSH session through the remote helper (see integrations/ssh)."""
    from sqlalchemy.orm import object_session

    from app.integrations.ssh import connect
    from app.services.connectivity import build_target, load_credential

    db = object_session(server)
    ssh_settings = settings_service.get_section_data(db, "ssh")
    return connect(build_target(server, ssh_settings), load_credential(server))


# --------------------------------------------------------------------------- strategy
def normalize_strategy(raw: dict[str, Any] | None, ssh_settings: dict[str, Any]) -> dict[str, Any]:
    raw = dict(raw or {})
    mode = raw.get("mode") or ("canary" if ssh_settings.get("canary", True) else "batch")
    if mode not in ("canary", "batch", "all"):
        raise AppError("VALIDATION_ERROR", "strategy.mode must be canary, batch or all", 422)

    def _int(key: str, default: int, lo: int, hi: int) -> int:
        v = raw.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise AppError("VALIDATION_ERROR", f"strategy.{key} must be an integer between {lo} and {hi}", 422)
        return v

    return {
        "mode": mode,
        "concurrency": _int("concurrency", int(ssh_settings.get("deployment_concurrency", 3)), 1, 50),
        # 0 = never stop starting new targets because of failures
        "failure_threshold": _int("failure_threshold", int(ssh_settings.get("failure_threshold", 1)), 0, 100),
        "continue_on_failure": bool(raw.get("continue_on_failure", False)),
        "allow_restart": bool(raw.get("allow_restart", False)),
        "allow_file_only_verification": bool(raw.get("allow_file_only_verification", False)),
        "verify_retries": _int("verify_retries", 5, 1, 30),
        "verify_delay_seconds": raw.get("verify_delay_seconds", 1.5)
        if isinstance(raw.get("verify_delay_seconds", 1.5), (int, float)) else 1.5,
    }


# --------------------------------------------------------------------------- candidate material
@dataclass
class ArtifactSet:
    """Candidate certificate material, in memory only."""
    leaf: CertInfo
    chain: tuple[CertInfo, ...]
    key_pem: bytes | None
    key_spki: str | None
    reuses_existing_key: bool


def _pem(c: CertInfo) -> bytes:
    return c.pem.strip().encode() + b"\n"


def load_artifacts(db: Session, version: CertificateVersion) -> ArtifactSet:
    vault = get_vault()
    if version.cert_artifact_id is None:
        raise AppError("VERSION_INVALID", "certificate version has no certificate", 422)
    try:
        cert_bytes = vault.load(version.cert_artifact_id, db=db)
        chain_bytes = vault.load(version.chain_artifact_id, db=db) if version.chain_artifact_id else None
        key_bytes = vault.load(version.key_artifact_id, db=db) if version.key_artifact_id else None
    except VaultError as exc:
        raise AppError("VERSION_ARTIFACT_UNAVAILABLE", "stored certificate material could not be decrypted", 500) from exc
    certs = parse_pem_certificates(cert_bytes)
    if not certs:
        raise AppError("VERSION_INVALID", "certificate artifact contains no certificate", 422)
    leaf, rest = certs[0], certs[1:]
    chain = tuple(parse_pem_certificates(chain_bytes)) if chain_bytes else tuple(rest)
    key_pem = key_spki = None
    if key_bytes and not version.reuses_existing_key:
        try:
            key_pem, key_spki, _ = load_private_key(key_bytes, None)
        except CertificateError as exc:
            raise AppError("VERSION_KEY_INVALID", "the stored private key cannot be used (encrypted or malformed)", 422) from exc
    return ArtifactSet(leaf, chain, key_pem, key_spki, bool(version.reuses_existing_key))


class _InstShim:
    def __init__(self, inst: CertificateInstallation):
        self.cert_path = inst.cert_path or inst.fullchain_path
        self.key_path = inst.key_path
        self.chain_path = inst.chain_path
        self.is_combined_pem = inst.is_combined_pem
        self.is_directory = False


def planned_files(inst: CertificateInstallation, art: ArtifactSet) -> list[PlannedFile]:
    """Files to write for ``inst`` (key files are skipped when the existing key is reused)."""
    adapter = get_adapter(inst.service_type)
    files = adapter.plan_files(_InstShim(inst))
    dests = [f.dest_path for f in files]
    if len(set(dests)) != len(dests):
        raise PlanError("two artifacts would be written to the same path")
    if art.reuses_existing_key:
        files = [f for f in files if f.artifact != ArtifactKind.KEY]
    return files


def render(kind: ArtifactKind, art: ArtifactSet, existing_key_pem: bytes | None) -> bytes:
    leaf = _pem(art.leaf)
    chain = b"".join(_pem(c) for c in art.chain)
    if kind == ArtifactKind.CERT:
        return leaf
    if kind == ArtifactKind.CHAIN:
        return chain
    if kind == ArtifactKind.FULLCHAIN:
        return leaf + chain
    key = art.key_pem if art.key_pem is not None else existing_key_pem
    if kind == ArtifactKind.KEY:
        if key is None:
            raise AppError("KEY_REQUIRED", "a private key is required", 422)
        return key if key.endswith(b"\n") else key + b"\n"
    if kind == ArtifactKind.COMBINED:
        if key is None:
            raise AppError("KEY_REQUIRED", "a private key is required", 422)
        return leaf + chain + (key if key.endswith(b"\n") else key + b"\n")
    raise AppError("PLAN_ERROR", f"unsupported artifact kind {kind}", 422)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_endpoints_for(inst: CertificateInstallation, server: Server,
                         leaf_sans: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Endpoint(s) probed to verify ``inst``. The SNI is always a real hostname or ``None`` (see ``verify_sni``)."""
    host = inst.verify_host or server.address or server.hostname
    port = inst.verify_port or inst.listen_port
    if not port:
        return []
    sni = resolve_verify_sni(inst.verify_sni, inst.server_names, leaf_sans)
    return [{"host": host, "port": int(port), "sni": sni}]


def required_hostnames(inst: CertificateInstallation) -> list[str]:
    return _required_hostnames(inst.server_names, inst.vhost, inst.verify_sni)


# --------------------------------------------------------------------------- findings
def finding(code: str, severity: str, message: str, installation_id: uuid.UUID | str | None = None,
            **details: Any) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message,
            "installation_id": str(installation_id) if installation_id else None, "details": details}


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


def _stat_dict(st: RemoteFileStat | None) -> dict[str, Any] | None:
    if st is None:
        return None
    return {"exists": st.exists, "file_type": st.file_type, "realpath": st.realpath, "symlink_target": st.symlink_target,
            "broken_symlink": st.broken_symlink, "mode": st.mode, "owner": st.owner, "group": st.group,
            "sha256": st.sha256, "size": st.size, "selinux_context": st.selinux_context, "readable": st.readable}


# --------------------------------------------------------------------------- planning
@dataclass
class _Ctx:
    db: Session
    version: CertificateVersion
    art: ArtifactSet
    strategy: dict[str, Any]
    acknowledged: set[str]
    exceptions: dict[tuple[str, str | None], str]    # (code, installation_id|None) -> justification
    host_factory: HostFactory
    now: datetime
    anchors: list[bytes]
    job_id: uuid.UUID | None


def _apply_exception(ctx: _Ctx, f: dict[str, Any]) -> dict[str, Any]:
    if f["severity"] != "blocking" or f["code"] not in EXCEPTIONABLE_CODES:
        return f
    just = ctx.exceptions.get((f["code"], f["installation_id"])) or ctx.exceptions.get((f["code"], None))
    if just:
        return {**f, "severity": "warning", "excepted": True, "exception_justification": just,
                "message": f["message"] + " (administrator exception recorded)"}
    return f


def _downgrade_acknowledged(ctx: _Ctx, f: dict[str, Any]) -> dict[str, Any]:
    if f["code"] == "INVENTORY_STALE" and f["severity"] == "blocking" and "INVENTORY_STALE" in ctx.acknowledged:
        return {**f, "severity": "warning", "message": f["message"] + " (acknowledged)"}
    return f


async def _inspect_target(ctx: _Ctx, host: RemoteHost, inst: CertificateInstallation, server: Server,
                          probe_cache: dict, config_cache: dict, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Read-only inspection of one installation. Returns the plan target dict."""
    iid = inst.id
    art = ctx.art
    t: dict[str, Any] = {
        "installation_id": str(iid), "server_id": str(server.id), "server_name": server.name,
        "environment": server.environment, "service_type": inst.service_type, "vhost": inst.vhost,
        "server_names": list(inst.server_names or []), "files": [], "backups": [], "reload": None,
        "config_test": None, "verify_endpoints": [], "rollback": None, "disk": None, "privilege": None,
        "current_fingerprint": None, "inventory_fingerprint": inst.last_observed_fingerprint,
        "new_fingerprint": art.leaf.fingerprint_sha256, "shared_with": [], "unit": None,
        "is_canary": False, "batch_index": 0, "verification_mode": "live",
    }

    def add(code: str, sev: str, msg: str, **details: Any) -> None:
        findings.append(finding(code, sev, msg, iid, **details))

    # ----- static eligibility
    if inst.managed_by_certbot:
        add("CERTBOT_MANAGED", "blocking",
            "this installation is managed by certbot; automatic replacement is unsupported - "
            "leave the certbot-managed paths alone and use a certbot deploy hook instead (see docs/deployment-engine.md, section 'Certbot policy', anchor #15-certbot-policy)")
        return t
    if inst.classification in ("unsupported", "unreadable", "error", "requires_mapping"):
        add("INSTALLATION_NOT_DEPLOYABLE", "blocking",
            f"installation is classified '{inst.classification}' and cannot be deployed to automatically")
        return t
    try:
        get_adapter(inst.service_type)
        files = planned_files(inst, art)
    except UnsupportedServiceError:
        add("UNSUPPORTED_SERVICE", "blocking", f"service type '{inst.service_type}' is not supported for deployment")
        return t
    except PlanError as exc:
        add("PLAN_ERROR", "blocking", f"cannot plan files for this installation: {exc}")
        return t

    # ----- privilege / helper
    try:
        if server.id not in probe_cache:
            probe_cache[server.id] = await host.probe()
        probe = probe_cache[server.id]
    except RemoteError as exc:
        add("HELPER_UNAVAILABLE", "blocking", f"remote helper / privileges unavailable: {exc.message}",
            remote_error=exc.code.value)
        return t
    t["privilege"] = {"mode": probe.privilege_mode, "helper_version": probe.helper_version, "os": probe.os_pretty,
                      "supported_os": probe.supported}
    if probe.privilege_mode != "helper-sudo" or not probe.helper_version:
        add("HELPER_UNAVAILABLE", "blocking", "the privileged remote helper is not available for this account")
        return t
    if not probe.supported:
        add("UNSUPPORTED_OS", "warning", f"operating system '{probe.os_pretty}' is not officially supported")
    svc_probe = next((s for s in probe.services if s.service.value == inst.service_type), None)
    if svc_probe is not None and not svc_probe.installed:
        add("SERVICE_NOT_INSTALLED", "blocking", f"{inst.service_type} is not installed on this server")
        return t

    # ----- stat every affected path
    stats: dict[str, RemoteFileStat] = {}
    all_paths = {f.dest_path for f in files}
    if inst.key_path:
        all_paths.add(inst.key_path)
    for path in sorted(all_paths):
        try:
            stats[path] = await host.stat(path)
        except RemoteError as exc:
            add("PATH_UNREADABLE", "blocking", f"cannot stat {path}: {exc.message}", path=path,
                remote_error=exc.code.value)
            return t
    ok = True
    for f in files:
        st = stats[f.dest_path]
        if not st.exists or st.broken_symlink:
            add("PATH_MISSING", "blocking", f"{f.dest_path} does not exist (or is a broken symlink); refusing to create it",
                path=f.dest_path)
            ok = False
        elif st.file_type == "dir" or (st.file_type not in ("file", "symlink")):
            add("PATH_NOT_REGULAR", "blocking", f"{f.dest_path} is not a regular file", path=f.dest_path)
            ok = False
        elif not st.readable or st.sha256 is None:
            add("PATH_UNREADABLE", "blocking", f"{f.dest_path} is not readable", path=f.dest_path)
            ok = False
        elif st.size is not None and st.size > MAX_FILE_BYTES:
            add("PATH_TOO_LARGE", "blocking", f"{f.dest_path} is unexpectedly large", path=f.dest_path)
            ok = False
        if st.symlink_target:
            add("SYMLINK", "info", f"{f.dest_path} is a symlink to {st.realpath}; the link is kept and its target replaced",
                path=f.dest_path, realpath=st.realpath)
    if not ok:
        return t

    # ----- current on-disk certificate (stale detection / key reuse proof)
    current_leaf: CertInfo | None = None
    existing_key: bytes | None = None
    cert_file = inst.cert_path or inst.fullchain_path
    try:
        if inst.is_combined_pem:
            data, _ = await host.backup_file(cert_file)           # in memory only; contains the key
            certs = parse_pem_certificates(data)
            current_leaf = certs[0] if certs else None
            if art.reuses_existing_key:
                try:
                    existing_key, spki, _ = load_private_key(data, None)
                    if current_leaf is not None and spki != current_leaf.public_key_sha256:
                        add("CURRENT_KEY_MISMATCH", "warning", "the key in the installed combined PEM does not match its certificate")
                except CertificateError:
                    existing_key = None
            del data
        else:
            data = await host.read_public_file(cert_file)
            certs = parse_pem_certificates(data)
            current_leaf = certs[0] if certs else None
    except RemoteError as exc:
        add("CURRENT_CERT_UNREADABLE", "warning", f"could not read the installed certificate: {exc.message}",
            remote_error=exc.code.value)
    if current_leaf is None and not any(f["code"] == "CURRENT_CERT_UNREADABLE" for f in findings if f["installation_id"] == str(iid)):
        add("CURRENT_CERT_UNREADABLE", "warning", "the installed file does not contain a parseable certificate")
    t["current_fingerprint"] = current_leaf.fingerprint_sha256 if current_leaf else None

    if inst.last_observed_fingerprint and current_leaf and inst.last_observed_fingerprint != current_leaf.fingerprint_sha256:
        add("INVENTORY_STALE", "blocking",
            "the certificate on disk differs from the last inventory observation; re-run discovery/verification "
            "or acknowledge to proceed", inventory=inst.last_observed_fingerprint,
            on_disk=current_leaf.fingerprint_sha256)
    elif not inst.last_observed_fingerprint:
        add("INVENTORY_UNKNOWN", "info", "no inventory baseline recorded for this installation")

    # ----- key handling
    if art.reuses_existing_key:
        if current_leaf is None:
            add("REUSE_KEY_UNVERIFIABLE", "blocking",
                "cannot prove the new certificate matches the installed key because the installed certificate is unreadable")
        elif art.leaf.public_key_sha256 != current_leaf.public_key_sha256:
            add("REUSE_KEY_MISMATCH", "blocking",
                "the new certificate's public key differs from the installed certificate's: the existing private key "
                "cannot be reused - upload the matching private key", new_spki=art.leaf.public_key_sha256,
                installed_spki=current_leaf.public_key_sha256)
        if inst.is_combined_pem and existing_key is None:
            add("REUSE_KEY_UNAVAILABLE", "blocking", "the existing private key could not be extracted from the combined PEM")
    elif art.key_pem is None:
        add("KEY_REQUIRED", "blocking", "the certificate version has no private key and does not reuse the existing key")

    # ----- candidate validation against this installation's hostnames
    bundle = ParsedBundle(art.leaf, art.chain, art.key_pem, art.key_spki, False, ())
    for f in validate_bundle(bundle, now=ctx.now, trust_anchors=_anchor_objs(ctx), required_hostnames=required_hostnames(inst),
                             current_cert=current_leaf, policy=ValidationPolicy(allow_self_signed=False)):
        if f.code.startswith("SAN_") or f.code in ("SHORTER_VALIDITY_THAN_CURRENT", "REPLACES_DIFFERENT_KEY_TYPE",
                                                   "SAME_AS_CURRENT"):
            findings.append(finding(f.code, f.severity.value, f.message, iid, **f.details))

    # ----- exact files, content, ownership
    new_total = 0
    try:
        for f in files:
            st = stats[f.dest_path]
            content = render(f.artifact, art, existing_key)
            new_total += len(content)
            realpath = st.realpath or f.dest_path
            t["files"].append({
                "dest_path": f.dest_path, "realpath": realpath, "artifact": f.artifact.value,
                "action": "replace", "is_symlink": bool(st.symlink_target), "symlink_target": st.symlink_target,
                "mode": st.mode if st.mode is not None else f.mode, "owner": st.owner, "group": st.group,
                "contains_private_key": f.contains_private_key, "current_sha256": st.sha256,
                "new_sha256": sha256(content), "size": len(content), "selinux_context": st.selinux_context,
            })
            t["backups"].append(f.dest_path)
    except AppError as exc:
        add(exc.code, "blocking", exc.message)
    if art.reuses_existing_key and inst.key_path and not inst.is_combined_pem:
        kst = stats.get(inst.key_path)
        t["files"].append({"dest_path": inst.key_path, "realpath": (kst.realpath if kst else None) or inst.key_path,
                           "artifact": "key", "action": "keep", "current_sha256": kst.sha256 if kst else None,
                           "contains_private_key": True})

    # ----- disk space
    first_real = t["files"][0]["realpath"] if t["files"] else cert_file
    try:
        free = await host.free_bytes(posixpath.dirname(first_real))
        need = max(4 * new_total, 1024 * 1024)
        t["disk"] = {"free_bytes": free, "required_bytes": need}
        if free < need:
            add("DISK_SPACE", "blocking", "not enough free disk space on the target filesystem", free_bytes=free, required_bytes=need)
    except RemoteError as exc:
        add("DISK_CHECK_FAILED", "warning", f"could not determine free disk space: {exc.message}")

    # ----- service config test: the CURRENT config must be valid
    key = (server.id, inst.service_type)
    if key not in config_cache:
        try:
            res = await get_adapter(inst.service_type).config_test(host)
            config_cache[key] = (res.exit_status == 0, (res.stdout or "")[:500])
        except RemoteError as exc:
            config_cache[key] = (False, f"config test could not run: {exc.message}")
    cfg_ok, cfg_out = config_cache[key]
    t["config_test"] = {"supported": True, "current_ok": cfg_ok, "output": cfg_out}
    if not cfg_ok:
        add("CONFIG_BROKEN", "blocking", f"the current {inst.service_type} configuration does not pass its config test; "
            "fix it before deploying", output=cfg_out)

    # ----- reload / rollback description
    t["reload"] = {"service": inst.service_type, "mode": "restart" if ctx.strategy["allow_restart"] else "graceful reload",
                   "allow_restart": ctx.strategy["allow_restart"]}
    t["rollback"] = ("automatic: on any config-test / reload / verification failure every backed-up file is restored with "
                     "its original mode and owner, the config test and reload are repeated and the previous "
                     "certificate must be served again; otherwise the target is marked manual_intervention_required")

    # ----- verification endpoints
    eps = verify_endpoints_for(inst, server, art.leaf.sans)
    baseline: list[dict[str, Any]] = []
    if eps:
        from app.integrations.tls.probe import probe_endpoint
        for ep in eps:
            res = await probe_endpoint(ep["host"], ep["port"], ep["sni"], 5.0,
                                       trust_anchors_pem=b"\n".join(ctx.anchors) or None, expected_hostname=ep["sni"])
            row = {**ep, "reachable": res.ok, "served_fingerprint": res.leaf.fingerprint_sha256 if res.leaf else None,
                   "error": res.error}
            baseline.append(row)
            if res.ok and current_leaf and row["served_fingerprint"] != current_leaf.fingerprint_sha256:
                add("ENDPOINT_SERVES_DIFFERENT_CERT", "warning",
                    f"{ep['host']}:{ep['port']} currently serves a different certificate than the file on disk",
                    served=row["served_fingerprint"], on_disk=current_leaf.fingerprint_sha256)
    t["verify_endpoints"] = baseline or []
    if not eps or not any(b["reachable"] for b in baseline):
        t["verification_mode"] = "file_only"
        code = "NO_VERIFY_ENDPOINT" if not eps else "VERIFY_ENDPOINT_UNREACHABLE"
        msg = ("no verification endpoint is configured" if not eps else "the verification endpoint is not reachable")
        if ctx.strategy["allow_file_only_verification"]:
            add(code, "info", msg + "; deployment will be verified by file contents only (allowed by strategy)")
        else:
            add(code, "blocking", msg + "; enable strategy.allow_file_only_verification to accept file-only verification")
    return t


def _anchor_objs(ctx: _Ctx) -> list:
    from cryptography import x509
    out = []
    for pem in ctx.anchors:
        try:
            out.extend(x509.load_pem_x509_certificates(pem))
        except Exception:  # noqa: BLE001, S112
            continue
    return out


def _union_units(targets: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    """Group targets that write the same (server, realpath) into one unit; detect conflicting content."""
    parent = {t["installation_id"]: t["installation_id"] for t in targets}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owners: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    for t in targets:
        for f in t["files"]:
            if f.get("action") != "replace":
                continue
            k = (t["server_id"], f["realpath"])
            if k in owners:
                other_id, other_f = owners[k]
                if other_f["new_sha256"] != f["new_sha256"] or other_f["mode"] != f["mode"] or other_f["owner"] != f["owner"]:
                    findings.append(finding("PATH_CONTENT_CONFLICT", "blocking",
                                            f"{f['realpath']} is shared by installations that need different content",
                                            t["installation_id"], path=f["realpath"], other=other_id))
                parent[find(t["installation_id"])] = find(other_id)
            else:
                owners[k] = (t["installation_id"], f)
    groups: dict[str, list[dict[str, Any]]] = {}
    for t in targets:
        groups.setdefault(find(t["installation_id"]), []).append(t)
    for i, members in enumerate(groups.values()):
        for m in members:
            m["unit"] = i
            m["shared_with"] = [x["installation_id"] for x in members if x is not m]


def _assign_batches(targets: list[dict[str, Any]], strategy: dict[str, Any]) -> None:
    units: dict[int, list[dict[str, Any]]] = {}
    for t in targets:
        units.setdefault(t["unit"], []).append(t)
    ordered = sorted(units.values(), key=lambda ms: min(targets.index(m) for m in ms))
    mode, conc = strategy["mode"], strategy["concurrency"]
    batch = 0
    rest = ordered
    if mode == "canary" and len(ordered) > 0:
        for m in ordered[0]:
            m["is_canary"], m["batch_index"] = True, 0
        rest, batch = ordered[1:], 1
    if mode == "all":
        for ms in rest:
            for m in ms:
                m["batch_index"] = batch
    else:
        for i, ms in enumerate(rest):
            for m in ms:
                m["batch_index"] = batch + i // conc


async def build_plan_async(
    db: Session, version: CertificateVersion, installation_ids: list[uuid.UUID], strategy: dict[str, Any], *,
    acknowledged: list[str] | None = None, exceptions: list[dict[str, Any]] | None = None,
    host_factory: HostFactory = default_host_factory, job_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    now = utcnow()
    art = load_artifacts(db, version)
    security = settings_service.get_section_data(db, "security")
    anchors = [security["trust_anchors_pem"].encode()] if security.get("trust_anchors_pem") else []
    exc_map: dict[tuple[str, str | None], str] = {}
    for e in exceptions or []:
        if e.get("code") in EXCEPTIONABLE_CODES and (e.get("justification") or "").strip():
            exc_map[(e["code"], str(e["installation_id"]) if e.get("installation_id") else None)] = e["justification"].strip()
    ctx = _Ctx(db, version, art, strategy, set(acknowledged or []), exc_map, host_factory, now, anchors, job_id)
    findings: list[dict[str, Any]] = []

    # ---- candidate-level checks (independent of the targets)
    if version.status in ("rejected", "superseded"):
        findings.append(finding("VERSION_NOT_DEPLOYABLE", "blocking", f"certificate version is {version.status}"))
    if version.validation_status == "invalid":
        findings.append(finding("VERSION_INVALID", "blocking", "the certificate version failed validation"))
    if version.fingerprint_sha256 and version.fingerprint_sha256 != art.leaf.fingerprint_sha256:
        findings.append(finding("VERSION_INTEGRITY", "blocking", "stored certificate does not match the version's fingerprint"))
    generic = validate_bundle(ParsedBundle(art.leaf, art.chain, art.key_pem, art.key_spki, False, ()), now=now,
                              trust_anchors=_anchor_objs(ctx), policy=ValidationPolicy(allow_self_signed=False))
    for f in generic:
        if f.code.startswith("SAN_") or f.code in ("SHORTER_VALIDITY_THAN_CURRENT", "REPLACES_DIFFERENT_KEY_TYPE",
                                                   "SAME_AS_CURRENT", "KEY_MISSING"):
            continue
        if f.code == "KEY_MISMATCH" or f.severity != Severity.INFO:
            findings.append(finding(f.code, f.severity.value, f.message, None, **f.details))

    # ---- load installations / servers
    insts = list(db.scalars(select(CertificateInstallation).where(CertificateInstallation.id.in_(installation_ids))))
    by_id = {i.id: i for i in insts}
    missing = [str(i) for i in installation_ids if i not in by_id]
    if missing:
        raise AppError("INSTALLATION_NOT_FOUND", "one or more installations do not exist", 404, {"ids": missing})
    ordered_insts = [by_id[i] for i in dict.fromkeys(installation_ids)]
    servers = {s.id: s for s in db.scalars(select(Server).where(Server.id.in_({i.server_id for i in ordered_insts})))}

    # ---- strict chain environments (K8): the bundle's chain must validate against the trust anchors
    strict_envs = {e.name for e in db.scalars(select(Environment).where(
        Environment.name.in_({s.environment for s in servers.values()}), Environment.require_trusted_chain.is_(True)))}
    if strict_envs:
        problems = trust_service.chain_trust_problems(db, art.leaf, art.chain, now=now)
        if problems:
            for i in ordered_insts:
                if servers[i.server_id].environment in strict_envs:
                    findings.append(finding(
                        "CHAIN_UNTRUSTED", "blocking",
                        f"environment '{servers[i.server_id].environment}' requires a trusted certificate chain, but "
                        f"the chain does not validate against the trust anchors: {problems[0]}", i.id,
                        environment=servers[i.server_id].environment, problems=problems))

    targets_by_inst: dict[uuid.UUID, dict[str, Any]] = {}
    probe_cache: dict = {}
    config_cache: dict = {}
    by_server: dict[uuid.UUID, list[CertificateInstallation]] = {}
    for i in ordered_insts:
        by_server.setdefault(i.server_id, []).append(i)

    async def per_server(server: Server, group: list[CertificateInstallation]) -> None:
        local: list[dict[str, Any]] = []
        if not server.enabled:
            for i in group:
                local.append(finding("SERVER_DISABLED", "blocking", f"server {server.name} is disabled", i.id))
            findings.extend(local)
            return
        if not server.host_public_key:
            for i in group:
                findings.append(finding("HOST_KEY_UNKNOWN", "blocking", f"no SSH host key is enrolled for {server.name}", i.id))
            return
        try:
            async with ctx.host_factory(server) as host:
                for i in group:
                    # inspect sequentially on one connection
                    t = await _inspect_target(ctx, host, i, server, probe_cache, config_cache, findings)
                    targets_by_inst[i.id] = t
                # shared path detection against installations that are NOT in the plan
                others = list(db.scalars(select(CertificateInstallation).where(
                    CertificateInstallation.server_id == server.id,
                    CertificateInstallation.id.not_in([i.id for i in group]),
                    CertificateInstallation.missing_since.is_(None))))
                await _check_shared_outside_plan(host, group, others, targets_by_inst, set(by_id), findings)
        except RemoteError as exc:
            for i in group:
                if i.id not in targets_by_inst:
                    findings.append(finding("CONNECT_FAILED", "blocking",
                                            f"cannot connect to {server.name}: {exc.message}", i.id,
                                            remote_error=exc.code.value))
        except AppError as exc:
            for i in group:
                if i.id not in targets_by_inst:
                    findings.append(finding(exc.code, "blocking", exc.message, i.id))

    await asyncio.gather(*(per_server(servers[sid], g) for sid, g in by_server.items()))

    targets = [targets_by_inst[i.id] for i in ordered_insts if i.id in targets_by_inst]
    complete = [t for t in targets if t["files"]]
    _union_units(complete, findings)
    _assign_batches(complete, strategy)

    # ---- locks and concurrent deployments
    _check_concurrency(db, ordered_insts, complete, job_id, findings)

    # ---- approvals of exceptions / acknowledgements
    findings = [_downgrade_acknowledged(ctx, _apply_exception(ctx, f)) for f in findings]
    findings = _dedupe(findings)
    blocking = [f for f in findings if f["severity"] == "blocking"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    unacked = sorted({f["code"] for f in warnings if f["code"] not in ctx.acknowledged and not f.get("excepted")})
    return {
        "generated_at": now.isoformat(),
        "version": {"id": str(version.id), "fingerprint_sha256": art.leaf.fingerprint_sha256,
                    "subject": art.leaf.subject, "sans": list(art.leaf.sans), "not_after": art.leaf.not_after.isoformat(),
                    "reuses_existing_key": art.reuses_existing_key, "has_private_key": art.key_pem is not None},
        "strategy": strategy,
        "targets": targets,
        "findings": findings,
        "summary": {"targets": len(targets), "blocking": len(blocking), "warnings": len(warnings),
                    "unacknowledged_warnings": unacked, "can_proceed": not blocking and not unacked and bool(targets)
                    and len(targets) == len(ordered_insts)},
        "read_only": True,
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen, out = set(), []
    for f in findings:
        k = (f["code"], f["installation_id"], f["message"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


async def _check_shared_outside_plan(host: RemoteHost, group: list[CertificateInstallation],
                                     others: list[CertificateInstallation], targets: dict[uuid.UUID, dict[str, Any]],
                                     selected: set[uuid.UUID], findings: list[dict[str, Any]]) -> None:
    written: dict[str, uuid.UUID] = {}
    for i in group:
        t = targets.get(i.id)
        for f in (t or {}).get("files", []):
            if f.get("action") == "replace":
                written[f["realpath"]] = i.id
                written[f["dest_path"]] = i.id
    if not written:
        return
    for o in others:
        for path in {o.cert_path, o.fullchain_path, o.chain_path, o.key_path} - {None}:
            hit = path if path in written else None
            if hit is None:
                try:
                    st = await host.stat(path)
                except RemoteError:
                    continue
                hit = st.realpath if st.realpath in written else None
            if hit is not None:
                findings.append(finding(
                    "SHARED_PATH_NOT_IN_PLAN", "blocking",
                    f"{hit} is also used by installation {o.id} ({o.service_type}) which is not part of this deployment; "
                    "all installations sharing a path must be deployed together", written[hit], path=hit,
                    other_installation_id=str(o.id), other_service=o.service_type))
                break


def _check_concurrency(db: Session, insts: list[CertificateInstallation], targets: list[dict[str, Any]],
                       job_id: uuid.UUID | None, findings: list[dict[str, Any]]) -> None:
    ids = [i.id for i in insts]
    rows = db.execute(
        select(DeploymentTarget.installation_id, DeploymentTarget.job_id, DeploymentTarget.status, DeploymentJob.status)
        .join(DeploymentJob, DeploymentJob.id == DeploymentTarget.job_id)
        .where(DeploymentTarget.installation_id.in_(ids))
    ).all()
    for inst_id, jid, tstatus, jstatus in rows:
        if job_id is not None and jid == job_id:
            continue
        if tstatus == "manual_intervention_required":
            findings.append(finding("MANUAL_INTERVENTION_PENDING", "blocking",
                                    "a previous deployment to this installation requires manual intervention", inst_id,
                                    job_id=str(jid)))
        elif jstatus not in FINAL_JOB_STATUSES and tstatus not in FINAL_TARGET_STATUSES:
            findings.append(finding("ACTIVE_DEPLOYMENT", "blocking",
                                    "another deployment to this installation is pending or running", inst_id,
                                    job_id=str(jid)))
    keys: dict[str, str] = {}
    for t in targets:
        for f in t["files"]:
            if f.get("action") == "replace":
                keys[locks.file_key(t["server_id"], f["realpath"])] = t["installation_id"]
        keys[locks.service_key(t["server_id"], t["service_type"])] = t["installation_id"]
    for lock in locks.active_locks(keys, exclude_job=job_id):
        findings.append(finding("LOCKED", "blocking", "a deployment lock is currently held on a path or service of this target",
                                keys[lock.resource_key], resource=lock.resource_key.split(":", 1)[-1],
                                expires_at=_iso(lock.expires_at)))


def build_plan(db: Session, version: CertificateVersion, installation_ids: list[uuid.UUID], strategy: dict[str, Any],
               **kw: Any) -> dict[str, Any]:
    """Synchronous wrapper (API threadpool). Not to be called from a running event loop."""
    return asyncio.run(build_plan_async(db, version, installation_ids, strategy, **kw))
