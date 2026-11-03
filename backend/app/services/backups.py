"""Central, encrypted, verified backups of the remote files a deployment is about to overwrite.

A ``Backup`` row belongs to one deployment target (server + installation) and covers every file the target changes.
File content (certificates and private keys!) is stored only as Vault artifacts (envelope encrypted); the
``manifest`` JSON carries metadata (sha256, mode, owner, symlink info, SELinux context, artifact ids) and never
content. ``integrity_sha256`` is an HMAC over the canonical manifest, so a modified manifest is detected before any
restore. A backup is ``verified`` only after every artifact was decrypted again and re-hashed.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import posixpath
import tarfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import VaultError, get_vault
from app.core.errors import AppError, not_found
from app.core.logging import get_logger
from app.integrations.contracts import RemoteError, RemoteFileStat, RemoteHost
from app.models import Backup, DeploymentTarget, User
from app.models.base import utcnow
from app.services import audit
from app.services import settings as settings_service

log = get_logger(__name__)


class BackupIntegrityError(Exception):
    pass


class _RestoreMismatch(Exception):
    pass


# --------------------------------------------------------------------------- manifest
def _canonical(files: list[dict[str, Any]]) -> bytes:
    return json.dumps(files, sort_keys=True, separators=(",", ":"), default=str).encode()


def manifest_mac(files: list[dict[str, Any]]) -> str:
    key = get_vault().derive_key("backup-manifest")
    return hmac.new(key, _canonical(files), hashlib.sha256).hexdigest()


def _entry(index: int, path: str, content: bytes, st: RemoteFileStat, artifact_id: uuid.UUID) -> dict[str, Any]:
    return {
        "index": index, "path": path, "realpath": st.realpath or path, "existed": True,
        "file_type": st.file_type, "symlink_target": st.symlink_target,
        "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
        "mode": st.mode, "uid": st.uid, "gid": st.gid, "owner": st.owner, "group": st.group,
        "selinux_context": st.selinux_context, "artifact_id": str(artifact_id),
    }


def public_manifest(backup: Backup) -> dict[str, Any]:
    m = backup.manifest or {}
    return {**m, "files": [dict(f) for f in m.get("files", [])]}


# --------------------------------------------------------------------------- verification
def verify_backup(backup: Backup, db: Session | None = None) -> None:
    """Raise :class:`BackupIntegrityError` unless the manifest MAC matches and every artifact decrypts to its hash."""
    files = (backup.manifest or {}).get("files")
    if not files or not backup.integrity_sha256:
        raise BackupIntegrityError("backup has no manifest")
    if not hmac.compare_digest(manifest_mac(files), backup.integrity_sha256):
        raise BackupIntegrityError("backup manifest failed its integrity check (modified?)")
    vault = get_vault()
    for f in files:
        try:
            data = vault.load(uuid.UUID(f["artifact_id"]), db=db)
        except (VaultError, ValueError) as exc:
            raise BackupIntegrityError(f"backup content for {f['path']} cannot be decrypted") from exc
        if hashlib.sha256(data).hexdigest() != f["sha256"] or len(data) != f["size"]:
            raise BackupIntegrityError(f"backup content for {f['path']} does not match the manifest")


def load_file_content(entry: dict[str, Any], db: Session | None = None) -> bytes:
    data = get_vault().load(uuid.UUID(entry["artifact_id"]), db=db)
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise BackupIntegrityError(f"backup content for {entry['path']} does not match the manifest")
    return data


# --------------------------------------------------------------------------- creation
async def create_backup(db: Session, host: RemoteHost, *, server_id: uuid.UUID, installation_id: uuid.UUID | None,
                        target_id: uuid.UUID | None, paths: list[str]) -> Backup:
    """Read every path from the remote host, store it encrypted, verify by decrypting and re-hashing.

    Raises ``AppError("BACKUP_FAILED")`` (nothing may proceed) on any failure; partially stored artifacts of a failed
    attempt are removed again.
    """
    vault = get_vault()
    stored: list[uuid.UUID] = []
    files: list[dict[str, Any]] = []
    try:
        for i, path in enumerate(paths):
            content, st = await host.backup_file(path)
            if not st.exists:
                raise AppError("BACKUP_FAILED", f"{path} does not exist on the server", 409)
            remote_sha = st.sha256
            local_sha = hashlib.sha256(content).hexdigest()
            if remote_sha is not None and remote_sha != local_sha:
                raise AppError("BACKUP_FAILED", f"content of {path} changed or was corrupted while it was read", 409)
            ref = vault.store(content, "backup", db=db)
            stored.append(ref.id)
            files.append(_entry(i, path, content, st, ref.id))
    except RemoteError as exc:
        _discard(db, stored)
        raise AppError("BACKUP_FAILED", f"could not read a file for backup: {exc.message}", 502,
                       {"remote_error": exc.code.value}) from exc
    except BaseException:
        _discard(db, stored)
        raise
    settings = settings_service.get_section_data(db, "general")
    backup = Backup(
        id=uuid.uuid4(), server_id=server_id, installation_id=installation_id, deployment_target_id=target_id,
        manifest={"version": 1, "created_at": utcnow().isoformat(), "files": files},
        integrity_sha256=manifest_mac(files), verified=False,
        retention_until=utcnow() + timedelta(days=int(settings["backup_retention_days"])),
    )
    db.add(backup)
    db.flush()
    try:
        verify_backup(backup, db)
    except BackupIntegrityError as exc:
        db.rollback()
        _discard(db, stored)
        raise AppError("BACKUP_FAILED", f"backup verification failed: {exc}", 500) from exc
    backup.verified = True
    db.commit()
    return backup


def _discard(db: Session, ids: list[uuid.UUID]) -> None:
    vault = get_vault()
    for i in ids:
        try:
            vault.delete(i, db=db)
        except Exception:  # noqa: BLE001
            log.warning("backup_discard_failed", artifact_id=str(i))
    try:
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


# --------------------------------------------------------------------------- restore (file level)
@dataclass
class FileRestoreResult:
    path: str
    action: str                      # "unchanged" | "restored" | "failed"
    detail: str = ""


@dataclass
class RestoreOutcome:
    ok: bool
    files: list[FileRestoreResult] = field(default_factory=list)
    error: str | None = None


async def restore_files(db: Session, host: RemoteHost, backup: Backup, *, only_changed: bool = True,
                        before_change: Callable[[], None] | None = None) -> RestoreOutcome:
    """Write every backed-up file back (content, mode, owner, group) and verify by re-stat.

    Idempotent: files whose current sha256/mode/owner already equal the backup are left alone. The caller is
    responsible for config test / reload / service verification afterwards. Never raises for per-file remote failures;
    they are reported in the outcome (the caller then escalates to manual intervention). ``before_change`` checks
    lock ownership before remote mutations; a failed check aborts the restore.
    """
    try:
        verify_backup(backup, db)
    except BackupIntegrityError as exc:
        return RestoreOutcome(False, [], f"backup integrity check failed: {exc}")
    out = RestoreOutcome(True)
    stage = None
    try:
        for f in backup.manifest["files"]:
            if before_change:
                before_change()
            path = f["path"]
            try:
                cur = await host.stat(path)
                same = (cur.exists and cur.sha256 == f["sha256"] and cur.mode == f["mode"]
                        and cur.owner == f["owner"] and cur.group == f["group"])
                if same and only_changed:
                    out.files.append(FileRestoreResult(path, "unchanged"))
                    continue
                content = load_file_content(f, db)
                if before_change:
                    before_change()
                if stage is None:
                    stage = await host.stage_dir()
                name = f"restore-{f['index']:02d}.bin"
                if before_change:
                    before_change()
                await host.write_staged(stage, name, content, 0o600)
                if before_change:
                    before_change()
                await host.install(posixpath.join(stage, name), path, int(f["mode"]), f["owner"], f["group"])
                after = await host.stat(path)
                if after.sha256 != f["sha256"] or after.mode != f["mode"]:
                    raise _RestoreMismatch("file does not match the backup after it was written")
            except (RemoteError, BackupIntegrityError, VaultError, _RestoreMismatch, TypeError, KeyError) as exc:
                msg = getattr(exc, "message", None) or str(exc) or type(exc).__name__
                out.files.append(FileRestoreResult(path, "failed", msg[:300]))
                out.ok = False
                continue
            except Exception as exc:  # noqa: BLE001
                out.files.append(FileRestoreResult(path, "failed", type(exc).__name__))
                out.ok = False
                continue
            out.files.append(FileRestoreResult(path, "restored"))
    finally:
        if stage is not None:
            try:
                await host.cleanup(stage)
            except Exception:  # noqa: BLE001 - leftover staging is cleaned by the helper's own housekeeping
                log.warning("restore_cleanup_failed")
    if before_change:
        before_change()
    return out


async def verify_files_match(host: RemoteHost, backup: Backup) -> list[str]:
    """Return a list of problems (empty = every file's sha256/mode/owner/symlink equals the backup)."""
    problems: list[str] = []
    for f in backup.manifest["files"]:
        try:
            cur = await host.stat(f["path"])
        except RemoteError as exc:
            problems.append(f"{f['path']}: cannot stat ({exc.code.value})")
            continue
        if not cur.exists or cur.sha256 != f["sha256"]:
            problems.append(f"{f['path']}: content differs from backup")
        elif cur.mode != f["mode"] or cur.owner != f["owner"] or cur.group != f["group"]:
            problems.append(f"{f['path']}: mode/owner differs from backup")
        elif (cur.symlink_target or None) != (f.get("symlink_target") or None):
            problems.append(f"{f['path']}: symlink target differs from backup")
    return problems


# --------------------------------------------------------------------------- queries
def get_backup(db: Session, backup_id: uuid.UUID) -> Backup:
    b = db.get(Backup, backup_id)
    if b is None:
        raise not_found("BACKUP_NOT_FOUND", "Backup not found")
    return b


def list_backups(db: Session, *, offset: int, limit: int, server_id: uuid.UUID | None = None,
                 installation_id: uuid.UUID | None = None, deployment_id: uuid.UUID | None = None):
    q = select(Backup)
    if server_id:
        q = q.where(Backup.server_id == server_id)
    if installation_id:
        q = q.where(Backup.installation_id == installation_id)
    if deployment_id:
        q = q.where(Backup.deployment_target_id.in_(
            select(DeploymentTarget.id).where(DeploymentTarget.job_id == deployment_id)))
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.scalars(q.order_by(Backup.created_at.desc()).offset(offset).limit(limit)).all()
    return rows, total


def backup_out(db: Session, b: Backup) -> dict[str, Any]:
    target = db.get(DeploymentTarget, b.deployment_target_id) if b.deployment_target_id else None
    m = b.manifest or {}
    return {
        "id": str(b.id), "server_id": str(b.server_id),
        "installation_id": str(b.installation_id) if b.installation_id else None,
        "deployment_target_id": str(b.deployment_target_id) if b.deployment_target_id else None,
        "deployment_id": str(target.job_id) if target else None,
        "created_at": b.created_at, "verified": b.verified, "retention_until": b.retention_until,
        "restore_status": b.restore_status, "restored_at": b.restored_at,
        "integrity_sha256": b.integrity_sha256,
        "file_count": len(m.get("files", [])),
        "files": [{k: v for k, v in f.items() if k != "artifact_id"} for f in m.get("files", [])],
    }


# --------------------------------------------------------------------------- download
def build_archive(db: Session, backup: Backup) -> bytes:
    """tar.gz with the decrypted files (paths made relative) and ``manifest.json``. Verifies integrity first."""
    try:
        verify_backup(backup, db)
    except BackupIntegrityError as exc:
        raise AppError("BACKUP_INTEGRITY_FAILED", str(exc), 409) from exc
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        manifest_bytes = json.dumps(public_manifest(backup) | {"backup_id": str(backup.id)}, indent=2,
                                    default=str).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size, info.mtime, info.mode = len(manifest_bytes), int(utcnow().timestamp()), 0o600
        tar.addfile(info, io.BytesIO(manifest_bytes))
        for f in backup.manifest["files"]:
            data = load_file_content(f, db)
            name = "files/" + f["path"].lstrip("/")
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(utcnow().timestamp()), 0o600
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def download(db: Session, actor: User, backup_id: uuid.UUID) -> tuple[bytes, str]:
    b = get_backup(db, backup_id)
    data = build_archive(db, b)
    audit.record(db, action="BACKUP_DOWNLOADED", resource_type="backup", resource_id=b.id, actor=actor,
                 after={"files": [f["path"] for f in b.manifest["files"]], "server_id": str(b.server_id)})
    db.commit()
    return data, f"backup-{b.id}.tar.gz"


# --------------------------------------------------------------------------- retention
def purge_expired(db: Session, now=None) -> int:
    """Delete backups past ``retention_until`` (artifacts too), but never the newest backup of an installation."""
    now = now or utcnow()
    vault = get_vault()
    expired = db.scalars(select(Backup).where(Backup.retention_until.is_not(None), Backup.retention_until < now)).all()
    purged = 0
    for b in expired:
        scope = (Backup.installation_id == b.installation_id) if b.installation_id else (
            (Backup.server_id == b.server_id) & Backup.installation_id.is_(None))
        newest = db.scalar(select(Backup.id).where(scope).order_by(Backup.created_at.desc(), Backup.id.desc()).limit(1))
        if newest == b.id:
            continue
        for f in (b.manifest or {}).get("files", []):
            try:
                vault.delete(uuid.UUID(f["artifact_id"]), db=db)
            except Exception:  # noqa: BLE001
                log.warning("backup_artifact_delete_failed", backup_id=str(b.id))
        audit.record(db, action="BACKUP_PURGED", resource_type="backup", resource_id=b.id, actor_name="retention",
                     after={"retention_until": b.retention_until, "server_id": str(b.server_id)})
        db.delete(b)
        purged += 1
    db.commit()
    return purged
