"""SSH-facing helpers: target/credential construction, host-key scan/enroll, connection test.

Streams that run remote work (discovery, deployment) reuse ``build_target`` / ``load_credential``.
The SSH integration is imported lazily inside functions.
"""
from __future__ import annotations

import asyncio
import importlib
import uuid
from dataclasses import is_dataclass
from typing import Any

from sqlalchemy.orm import Session, object_session

from app.core.crypto import get_vault
from app.core.errors import AppError, not_found
from app.models import Server, User
from app.models.base import utcnow
from app.services import audit
from app.services import settings as settings_service

_STATUS_BY_ERROR = {
    "HOST_KEY_UNKNOWN": "host_key_unknown",
    "HOST_KEY_MISMATCH": "host_key_mismatch",
    "AUTH_REJECTED": "auth_error",
    "TIMEOUT": "offline",
    "CONNECTION_REFUSED": "offline",
    "DNS_FAILURE": "offline",
}


def build_target(server: Server, settings: dict[str, Any], *, _depth: int = 0):
    """Build an ``SSHTarget`` for ``server``. ``settings`` is the effective ``ssh`` settings section
    (``settings_service.get_section_data(db, "ssh")``). Resolves one bastion hop."""
    from app.integrations.ssh import SSHTarget

    jump = None
    if server.bastion_server_id is not None and _depth < 2:
        db = object_session(server)
        bastion = db.get(Server, server.bastion_server_id) if db is not None else None
        if bastion is not None:
            jump = build_target(bastion, settings, _depth=_depth + 1)
    return SSHTarget(
        host=server.address or server.hostname,
        port=server.ssh_port,
        username=server.ssh_username,
        host_public_key=server.host_public_key,
        connect_timeout=float(settings["connect_timeout"]),
        command_timeout=float(settings["command_timeout"]),
        jump=jump,
        privilege_mode=server.privilege_mode,
    )


def load_credential(server: Server):
    """Decrypt the server's SSH credential into an in-memory ``SSHCredential`` (never persisted/logged)."""
    from app.integrations.ssh import SSHCredential

    cred = server.credential
    if cred is None:
        raise AppError("SERVER_HAS_NO_CREDENTIAL", "Server has no SSH credential assigned", 422)
    vault = get_vault()
    pem = vault.load(cred.encrypted_artifact_id, db=object_session(server))
    passphrase = vault.decrypt_value(cred.passphrase_encrypted) if cred.passphrase_encrypted else None
    return SSHCredential(private_key_pem=pem, passphrase=passphrase)


def _get_server(db: Session, server_id: uuid.UUID) -> Server:
    s = db.get(Server, server_id)
    if s is None:
        raise not_found("SERVER_NOT_FOUND", "Server not found")
    return s


def _import_ssh():
    try:
        return importlib.import_module("app.integrations.ssh")
    except ImportError as exc:
        raise AppError("SSH_UNAVAILABLE", "SSH integration is not available", 503) from exc


def _run(coro):
    """Run a coroutine from a sync (threadpool) context."""
    return asyncio.run(coro)


def _norm_fp(fp: str) -> str:
    fp = fp.strip()
    return fp if fp.startswith("SHA256:") else f"SHA256:{fp}"


def scan_host_key(db: Session, actor: User, server_id: uuid.UUID) -> dict[str, str]:
    ssh = _import_ssh()
    server = _get_server(db, server_id)
    settings = settings_service.get_section_data(db, "ssh")
    try:
        info = _run(ssh.scan_host_key(server.address or server.hostname, server.ssh_port,
                                      float(settings["connect_timeout"])))
    except AppError:
        raise
    except Exception as exc:
        audit.record(db, action="HOST_KEY_SCAN", resource_type="server", resource_id=server.id, actor=actor,
                     outcome="failure", error=type(exc).__name__)
        db.commit()
        raise AppError("HOST_KEY_SCAN_FAILED", "Could not retrieve the host key from the server", 502,
                       {"reason": getattr(exc, "message", type(exc).__name__)}) from exc
    audit.record(db, action="HOST_KEY_SCAN", resource_type="server", resource_id=server.id, actor=actor,
                 after={"fingerprint": info.fingerprint_sha256, "key_type": info.key_type})
    db.commit()
    return {"key_type": info.key_type, "fingerprint_sha256": info.fingerprint_sha256,
            "public_key": info.public_key_openssh}


def scan_many(targets: list[tuple[Any, str, int]], timeout: float, concurrency: int = 5) -> dict[Any, tuple[Any, dict | None]]:
    """Scan host keys of many ``(key, host, port)`` targets with bounded concurrency and a per-host timeout.

    Returns ``{key: (HostKeyInfo | None, None | {"code", "message"})}``. Never raises for per-host failures.
    """
    ssh = _import_ssh()

    async def one(sem: asyncio.Semaphore, host: str, port: int):
        async with sem:
            try:
                return await asyncio.wait_for(ssh.scan_host_key(host, port, timeout), timeout + 2), None
            except Exception as exc:  # noqa: BLE001 - per-host failure is reported, not raised
                code = getattr(exc, "code", None)
                from app.integrations.ssh.sanitize import sanitize_output

                msg = getattr(exc, "message", None) or type(exc).__name__
                return None, {"code": getattr(code, "value", None) or ("TIMEOUT" if isinstance(exc, TimeoutError) else "UNKNOWN"),
                              "message": sanitize_output(str(msg), 200)}

    async def main():
        sem = asyncio.Semaphore(concurrency)
        results = await asyncio.gather(*(one(sem, h, p) for _, h, p in targets))
        return {k: r for (k, _, _), r in zip(targets, results, strict=True)}

    return _run(main()) if targets else {}


def enroll_host_key(db: Session, actor: User, server_id: uuid.UUID, public_key: str, fingerprint: str,
                    replace: bool, *, fresh: Any = None, note: str | None = None) -> Server:
    """Admin-confirmed enrollment: the posted fingerprint AND key must equal a fresh scan.

    ``fresh`` lets bulk callers supply an already-performed fresh scan (same verification applies)."""
    server = _get_server(db, server_id)
    if fresh is None:
        ssh = _import_ssh()
        settings = settings_service.get_section_data(db, "ssh")
        try:
            fresh = _run(ssh.scan_host_key(server.address or server.hostname, server.ssh_port,
                                           float(settings["connect_timeout"])))
        except Exception as exc:
            raise AppError("HOST_KEY_SCAN_FAILED", "Could not retrieve the host key from the server", 502,
                           {"reason": getattr(exc, "message", type(exc).__name__)}) from exc
    posted_key = " ".join(public_key.split()[:2])
    fresh_key = " ".join(fresh.public_key_openssh.split()[:2])
    if _norm_fp(fingerprint) != _norm_fp(fresh.fingerprint_sha256) or posted_key != fresh_key:
        audit.record(db, action="HOST_KEY_ENROLL", resource_type="server", resource_id=server.id, actor=actor,
                     outcome="failure", error="fingerprint does not match the key presented by the server",
                     after={"posted": _norm_fp(fingerprint), "presented": fresh.fingerprint_sha256})
        db.commit()
        raise AppError("HOST_KEY_CHANGED_DURING_ENROLL",
                       "The key presented by the server does not match the confirmed fingerprint", 409,
                       {"presented_fingerprint": fresh.fingerprint_sha256})
    previous = server.host_key_fingerprint
    if server.host_public_key and previous != fresh.fingerprint_sha256 and not replace:
        raise AppError("HOST_KEY_ALREADY_ENROLLED",
                       "A different host key is enrolled; pass replace=true to explicitly replace it", 409,
                       {"enrolled_fingerprint": previous, "presented_fingerprint": fresh.fingerprint_sha256})
    server.host_public_key = fresh.public_key_openssh
    server.host_key_type = fresh.key_type
    server.host_key_fingerprint = fresh.fingerprint_sha256
    server.host_key_enrolled_at = utcnow()
    server.host_key_enrolled_by = actor.id
    if server.connection_status in ("host_key_unknown", "host_key_mismatch"):
        server.connection_status = "unknown"
    audit.record(db, action="HOST_KEY_REPLACED" if previous and previous != fresh.fingerprint_sha256 else "HOST_KEY_ENROLLED",
                 resource_type="server", resource_id=server.id, actor=actor,
                 before={"fingerprint": previous}, after={"fingerprint": fresh.fingerprint_sha256,
                                                          "key_type": fresh.key_type,
                                                          **({"detail": note} if note else {})})
    db.commit()
    return server


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f: _to_dict(getattr(obj, f)) for f in obj.__dataclass_fields__}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool)):
        return obj.value
    return obj


def test_connection(db: Session, actor: User, server_id: uuid.UUID) -> dict[str, Any]:
    ssh = _import_ssh()
    server = _get_server(db, server_id)
    settings = settings_service.get_section_data(db, "ssh")
    target = build_target(server, settings)
    credential = load_credential(server)
    try:
        report = _run(ssh.test_connection(target, credential))
    except Exception as exc:  # noqa: BLE001 - any transport failure becomes a failed report
        report = None
        err_code, err_msg = "UNKNOWN", f"Connection test failed ({type(exc).__name__})"
    else:
        err_code = report.error_code.value if report.error_code is not None else None
        err_msg = report.error_message
    now = utcnow()
    before = {"connection_status": server.connection_status}
    if report is not None and report.ok:
        server.connection_status = "connected"
        server.last_connected_at = now
        probe = report.probe
        if probe is not None:
            server.os_family, server.os_version, server.os_pretty = probe.os_family, probe.os_version, probe.os_pretty
            server.detected_services = {
                "services": [_to_dict(sp) for sp in probe.services],
                "kernel": probe.kernel, "remote_user": probe.remote_user, "helper_version": probe.helper_version,
                "privilege_mode": probe.privilege_mode, "supported": probe.supported, "checked_at": now.isoformat(),
            }
    else:
        server.connection_status = _STATUS_BY_ERROR.get(err_code or "", "error")
    audit.record(db, action="SSH_CONNECTION_TEST", resource_type="server", resource_id=server.id, actor=actor,
                 before=before, after={"connection_status": server.connection_status, "error_code": err_code},
                 outcome="success" if server.connection_status == "connected" else "failure", error=err_msg)
    db.commit()
    return {
        "ok": bool(report and report.ok),
        "steps": [_to_dict(s) for s in (report.steps if report else [])],
        "probe": _to_dict(report.probe) if report and report.probe else None,
        "error_code": err_code,
        "error_message": err_msg,
    }
