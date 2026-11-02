from __future__ import annotations

import io
import tarfile
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.crypto import get_vault
from app.core.errors import AppError
from app.models import Backup, EncryptedArtifact
from app.models.base import utcnow
from app.services import backups
from app.services import deployment_engine as engine
from tests.unit.deploy.helpers import FakeHost, add_installation, add_server

pytestmark = pytest.mark.usefixtures("net")


@pytest.fixture
async def backup(db, net, pkis):
    server = add_server(db, "b-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="bk", link=True)
    b = await backups.create_backup(db, FakeHost(fs), server_id=server.id, installation_id=inst.id, target_id=None,
                                    paths=[inst.cert_path, inst.key_path])
    return b, server, fs, inst


async def test_backup_is_encrypted_verified_and_has_full_manifest(db, backup):
    b, _server, _fs, _inst = backup
    assert b.verified and b.retention_until > utcnow() + timedelta(days=80)
    f = b.manifest["files"][0]
    assert {"path", "realpath", "sha256", "mode", "uid", "gid", "owner", "group", "symlink_target", "selinux_context",
            "artifact_id", "size"} <= set(f)
    assert f["symlink_target"] == "releases/fullchain.pem" and f["realpath"].endswith("releases/fullchain.pem")
    art = db.get(EncryptedArtifact, uuid.UUID(f["artifact_id"]))
    raw = get_vault()._path(art.id).read_bytes()
    assert b"BEGIN CERTIFICATE" not in raw and b"PRIVATE KEY" not in raw          # only ciphertext on disk
    out = backups.backup_out(db, b)
    assert "artifact_id" not in str(out["files"]) and "BEGIN" not in str(out)      # API view: manifest without content


async def test_tampered_manifest_is_detected(db, backup):
    b, *_ = backup
    backups.verify_backup(b, db)
    files = [dict(f) for f in b.manifest["files"]]
    files[0]["mode"] = 0o666                                  # an attacker weakens the recorded permissions
    b.manifest = {**b.manifest, "files": files}
    db.commit()
    with pytest.raises(backups.BackupIntegrityError, match="manifest"):
        backups.verify_backup(b, db)


async def test_tampered_manifest_hash_swap_is_detected_by_vault(db, backup):
    b, *_ = backup
    files = [dict(f) for f in b.manifest["files"]]
    files[0]["artifact_id"], files[1]["artifact_id"] = files[1]["artifact_id"], files[0]["artifact_id"]
    b.manifest = {**b.manifest, "files": files}
    b.integrity_sha256 = backups.manifest_mac(files)          # even with a recomputed MAC the content hash fails
    db.commit()
    with pytest.raises(backups.BackupIntegrityError, match="does not match"):
        backups.verify_backup(b, db)


async def test_corrupted_ciphertext_is_detected(db, backup):
    b, *_ = backup
    path = get_vault()._path(uuid.UUID(b.manifest["files"][1]["artifact_id"]))
    data = bytearray(path.read_bytes())
    data[3] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(backups.BackupIntegrityError, match="decrypted"):
        backups.verify_backup(b, db)


async def test_restore_refuses_a_tampered_backup_and_writes_nothing(db, backup):
    b, _server, fs, inst = backup
    b.integrity_sha256 = "0" * 64
    db.commit()
    snap = dict(fs.snapshot())
    fs.files[fs.resolve(inst.cert_path)].content = b"changed"
    out = await backups.restore_files(db, FakeHost(fs), b)
    assert not out.ok and "integrity" in out.error and fs.files[fs.resolve(inst.cert_path)].content == b"changed"
    del snap


async def test_restore_files_is_idempotent_and_restores_mode_owner(db, backup):
    b, _server, fs, inst = backup
    real = fs.resolve(inst.key_path)
    original = fs.files[real].content
    fs.files[real].content, fs.files[real].mode = b"x", 0o644
    out = await backups.restore_files(db, FakeHost(fs), b)
    assert out.ok and [r.action for r in out.files] == ["unchanged", "restored"]
    assert fs.files[real].content == original and fs.files[real].mode == 0o600
    again = await backups.restore_files(db, FakeHost(fs), b)
    assert [r.action for r in again.files] == ["unchanged", "unchanged"]
    assert await backups.verify_files_match(FakeHost(fs), b) == []


async def test_download_archive_contains_decrypted_files_and_is_audited(db, backup, admin_user):
    b, _server, _fs, _inst = backup
    data, name = backups.download(db, admin_user, b.id)
    assert name.endswith(".tar.gz")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names and any(n.endswith("privkey.pem") for n in names)
        key = next(n for n in names if n.endswith("privkey.pem"))
        assert b"PRIVATE KEY" in tar.extractfile(key).read()
    from app.models import AuditEvent

    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "BACKUP_DOWNLOADED"))


async def test_retention_purge_keeps_latest_backup_per_installation(db, backup):
    b, server, fs, inst = backup
    newer = await backups.create_backup(db, FakeHost(fs), server_id=server.id, installation_id=inst.id, target_id=None,
                                        paths=[inst.cert_path])
    newer.created_at = utcnow() + timedelta(seconds=5)
    b.retention_until = newer.retention_until = utcnow() - timedelta(days=1)
    db.commit()
    old_artifacts = [uuid.UUID(f["artifact_id"]) for f in b.manifest["files"]]
    assert backups.purge_expired(db) == 1
    assert db.get(Backup, b.id) is None and db.get(Backup, newer.id) is not None
    assert all(db.get(EncryptedArtifact, a).deleted_at is not None for a in old_artifacts)
    assert backups.purge_expired(db) == 0               # the newest one is never purged, even when expired


async def test_failed_backup_leaves_no_artifacts(db, net, pkis):
    server = add_server(db, "b2")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="b2")
    before = db.query(EncryptedArtifact).count()
    with pytest.raises(AppError):
        await backups.create_backup(db, FakeHost(fs), server_id=server.id, installation_id=inst.id, target_id=None,
                                    paths=[inst.cert_path, "/etc/ssl/missing.pem"])
    assert db.query(EncryptedArtifact).filter(EncryptedArtifact.deleted_at.is_(None)).count() == before


def test_manual_restore_through_engine_restores_previous_certificate(db, net, pkis, operator, monkeypatch):
    from app.services import deployments
    from tests.unit.deploy.conftest import FAST
    from tests.unit.deploy.helpers import add_version

    monkeypatch.setattr(deployments, "dispatch", lambda j: None)
    queued = []
    monkeypatch.setattr(deployments, "dispatch_restore", lambda *a: queued.append(a))
    server = add_server(db, "m-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="man")
    version = add_version(db, pkis["new"])
    job, _ = deployments.create(db, operator, "m1", {"version_id": version.id, "installation_ids": [inst.id],
                                                      "strategy": dict(FAST), "acknowledged_warnings": []})
    assert engine.run_job(job.id) == "completed"
    old_fp = fs.served and next(t["current_fingerprint"] for t in job.dry_run_plan["targets"])
    assert fs.leaf_fp(inst.cert_path) == version.fingerprint_sha256
    db.expire_all()
    from app.models import DeploymentTarget

    t = db.scalar(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id))
    from tests.conftest import make_user

    admin = make_user(db, "restorer", "admin")
    res = deployments.rollback_target(db, admin, job.id, t.id)
    assert res["accepted"] and res["restore_status"] == "in_progress" and queued       # queued, not run in the request
    args = queued[0]
    assert engine.run_restore(args[0], args[1], args[2], previous_restore_status=args[3], permission=args[4])["ok"]
    db.expire_all()
    res = {"target": {"status": db.get(DeploymentTarget, t.id).status}}
    assert res["target"]["status"] == "rolled_back"
    assert fs.leaf_fp(inst.cert_path) == old_fp and fs.served[(server.address, 8443)] == old_fp
    db.refresh(inst)
    assert inst.last_observed_fingerprint == old_fp
    assert db.get(Backup, t.backup_id).restore_status == "restored"
