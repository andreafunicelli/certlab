"""Deployment engine against the disposable local target (nginx :8443, apache :9443, haproxy :10443).

Every test generates fresh leaf certificates signed by the test CA under /etc/ssl/cdp-test/ca. A session fixture
snapshots ALL files under /etc/ssl/cdp-test before the first test and restores them (and reloads the services)
afterwards, so the target ends in its original state. Scenarios: (a) nginx, (b) apache, (c) cert-only/reuse key,
(d) haproxy combined PEM, (e) config-test failure -> verified rollback, (f) verification mismatch -> rollback,
(g) rollback failure -> manual intervention, (h) lock conflict, (i) read-only dry run, (j) certbot blocked,
(k) worker crash + resume, (l) multi-target canary stop.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import subprocess
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select, text

from app.core.crypto import get_vault
from app.core.db import SessionLocal
from app.integrations.certificates import parse_pem_certificates
from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.integrations.ssh import connect
from app.models import (
    CertificateInstallation,
    CertificateVersion,
    DeploymentJob,
    DeploymentTarget,
    Server,
)
from app.models.certificate import make_identity_key
from app.services import deployment_engine as engine
from app.services import deployment_planner as planner
from app.services import deployments, locks
from tests.conftest import make_user
from tests.integration.conftest import CERTS, SSH_PORT, STATE

pytestmark = pytest.mark.integration
FAST = {"verify_retries": 6, "verify_delay_seconds": 0.5}
CA = CERTS / "ca"


# --------------------------------------------------------------------------- helpers
def _tree_hash() -> dict[str, str]:
    out = {}
    for p in sorted(CERTS.rglob("*")):
        if p.is_file() and "scratch" not in p.parts:
            out[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
        elif p.is_symlink():
            out[str(p)] = "link:" + os.readlink(p)
    return out


def _all_dirs() -> set[str]:
    return {str(p) for p in CERTS.rglob("*") if p.is_dir()}


def _reload_all() -> None:
    subprocess.run(["nginx", "-s", "reload"], check=False, capture_output=True)
    subprocess.run(["apachectl", "-k", "graceful"], check=False, capture_output=True)
    pid = Path("/run/haproxy.pid")
    if pid.exists():
        subprocess.run(["bash", "-c", "haproxy -f /etc/haproxy/haproxy.cfg -D -p /run/haproxy.pid -sf $(cat /run/haproxy.pid)"],
                       check=False, capture_output=True)


def _restore(snap) -> None:
    for p, (data, mode, uid, gid) in snap.items():
        p.write_bytes(data)
        os.chmod(p, mode)
        os.chown(p, uid, gid)
    _reload_all()


@pytest.fixture(scope="session")
def _original_target(target_up):
    snap = {}
    for p in CERTS.rglob("*"):
        if p.is_file() and not p.is_symlink() and "scratch" not in p.parts:
            st = p.stat()
            snap[p] = (p.read_bytes(), st.st_mode & 0o7777, st.st_uid, st.st_gid)
    yield snap
    _restore(snap)


@pytest.fixture(autouse=True)
def restore_target(_original_target):
    """Put every file below /etc/ssl/cdp-test back after EACH test (other suites rely on the original certs)."""
    yield
    _restore(_original_target)


def _leaf(sans, key=None, days=700):
    ca_key = serialization.load_pem_private_key((CA / "inter.key").read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate((CA / "inter.pem").read_bytes())
    key = key or rsa.generate_private_key(65537, 2048)
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem, kp, key


def _version(db, sans, *, key=None, with_key=True, reuse=False):
    pem, kp, key = _leaf(sans, key)
    vault = get_vault()
    leaf = parse_pem_certificates(pem)[0]
    v = CertificateVersion(
        fingerprint_sha256=leaf.fingerprint_sha256, cert_artifact_id=vault.store(pem, "cert", db=db).id,
        chain_artifact_id=vault.store((CA / "inter.pem").read_bytes(), "chain", db=db).id,
        key_artifact_id=vault.store(kp, "key", db=db).id if with_key else None, validation_status="valid",
        status="validated", reuses_existing_key=reuse)
    db.add(v)
    db.commit()
    return v, leaf.fingerprint_sha256


def _fp(path: Path) -> str:
    return parse_pem_certificates(path.read_bytes())[0].fingerprint_sha256


def _served(port: int, sni: str) -> str:
    import asyncio

    from app.integrations.tls.probe import probe_endpoint

    res = asyncio.run(probe_endpoint("127.0.0.1", port, sni, 5))
    assert res.ok, res.error
    return res.leaf.fingerprint_sha256


@pytest.fixture
def world(db, host_pub):
    """A Server row pointing at the local sshd, plus an operator."""
    from app.core.crypto import get_vault as gv
    from app.models import Credential

    vault = gv()
    art = vault.store((STATE / "id_ed25519").read_bytes(), "ssh_key", db=db)
    cred = Credential(name="local-target", encrypted_artifact_id=art.id, public_key=(STATE / "id_ed25519.pub").read_text(),
                      fingerprint_sha256="x")
    db.add(cred)
    db.flush()
    server = Server(name="local-target", hostname="localhost", address="127.0.0.1", ssh_port=SSH_PORT,
                    ssh_username="cdpdeploy", credential_id=cred.id, environment="Test", host_public_key=host_pub,
                    host_key_type="ssh-ed25519", connection_status="connected")
    db.add(server)
    db.commit()
    with SessionLocal() as s:
        s.execute(text("DELETE FROM deployment_locks"))
        s.commit()
    return server, make_user(db, "live-op", "operator")


def _inst(db, server, service, cert, key, port, sni, **kw):
    i = CertificateInstallation(
        server_id=server.id, service_type=service, cert_path=str(cert), key_path=str(key) if key else None,
        listen_port=port, vhost=sni, server_names=[sni], verify_host="127.0.0.1", verify_port=port, verify_sni=sni,
        classification="managed", identity_key=make_identity_key(server.id, service, str(cert), sni),
        last_observed_fingerprint=_fp(Path(cert)), **kw)
    db.add(i)
    db.commit()
    return i


def _req(version, insts, **strategy):
    return {"version_id": version.id, "installation_ids": [i.id for i in insts], "strategy": {**FAST, **strategy},
            "acknowledged_warnings": ["SHORTER_VALIDITY_THAN_CURRENT"]}


def _create(db, user, version, insts, **strategy):
    try:
        job, _ = deployments.create(db, user, uuid.uuid4().hex, _req(version, insts, **strategy), dispatch_now=False)
    except AppErrorType as exc:
        raise AssertionError(exc.details) from exc
    return job


def _status(db, job):
    db.expire_all()
    j = db.get(DeploymentJob, job.id)
    ts = list(db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id).order_by(DeploymentTarget.batch_index)))
    return j, ts


def _nginx(db, server):
    return _inst(db, server, "nginx", CERTS / "nginx/fullchain.pem", CERTS / "nginx/privkey.pem", 8443, "nginx.test.local")


# --------------------------------------------------------------------------- fault injecting host
class FaultHost:
    """Wraps the real SSH host; faults are enabled by attributes. Everything else is the genuine remote operation."""

    def __init__(self, real, faults):
        self._r, self.f = real, faults

    def __getattr__(self, name):
        return getattr(self._r, name)

    async def install(self, staged, dest, mode, owner, group):
        f = self.f
        if f.get("fail_restore") and f.get("config_failed"):
            raise RemoteError(RemoteErrorCode.PERMISSION_DENIED, "injected: cannot write destination during restore")
        res = await self._r.install(staged, dest, mode, owner, group)
        f.setdefault("installs", []).append(dest)
        if f.get("tamper_key") and dest == f["tamper_key"] and not f.get("tampered"):
            f["tampered"] = True                                  # a genuinely different key lands on disk
            other = _leaf(["x.test.local"])[1]
            sd = await self._r.stage_dir()
            await self._r.write_staged(sd, "tamper.pem", other, 0o600)
            await self._r.install(f"{sd}/tamper.pem", dest, mode, owner, group)
            await self._r.cleanup(sd)
        if f.get("crash_after") and len(f["installs"]) == f["crash_after"] and not f.get("crashed"):
            f["crashed"] = True
            raise SimulatedCrash()
        return res

    async def config_test(self, service):
        res = await self._r.config_test(service)
        if res.exit_status != 0:
            self.f["config_failed"] = True
        return res


class SimulatedCrash(BaseException):
    pass


@pytest.fixture
def faults(monkeypatch, world):
    f: dict = {}

    @asynccontextmanager
    async def factory(server):
        from app.services import settings as st
        from app.services.connectivity import build_target, load_credential

        with SessionLocal() as s:
            srv = s.get(Server, server.id)
            target = build_target(srv, st.get_section_data(s, "ssh"))
            cred = load_credential(srv)
        async with connect(target, cred) as real:
            yield FaultHost(real, f)

    monkeypatch.setattr(engine, "HOST_FACTORY", factory)
    return f


# --------------------------------------------------------------------------- (a) nginx
def test_a_nginx_full_deployment_new_cert_and_key(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    old_fp = _fp(CERTS / "nginx/fullchain.pem")
    old_files = {p: (CERTS / "nginx" / p).read_bytes() for p in ("fullchain.pem", "privkey.pem")}
    version, new_fp = _version(db, ["nginx.test.local"])
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "completed"
    j, (t,) = _status(db, job)
    assert j.status == "completed" and t.verification["mode"] == "live"
    assert _served(8443, "nginx.test.local") == new_fp != old_fp
    assert _fp(CERTS / "nginx/fullchain.pem") == new_fp
    assert oct((CERTS / "nginx/privkey.pem").stat().st_mode & 0o777) == "0o600"
    # the backup is restorable: restoring brings the old certificate back
    from app.models import Backup

    b = db.get(Backup, t.backup_id)
    assert b.verified
    res = engine.restore_backup(db, b, op)
    assert res["ok"], res
    assert _served(8443, "nginx.test.local") == old_fp
    assert {p: (CERTS / "nginx" / p).read_bytes() for p in old_files} == old_files


# --------------------------------------------------------------------------- (b) apache
def test_b_apache_deployment_with_separate_chain(db, world, faults):
    server, op = world
    inst = _inst(db, server, "apache", CERTS / "apache/cert.pem", CERTS / "apache/privkey.pem", 9443,
                 "apache.test.local", chain_path=str(CERTS / "apache/chain.pem"))
    version, new_fp = _version(db, ["apache.test.local"])
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "completed"
    assert _served(9443, "apache.test.local") == new_fp


# --------------------------------------------------------------------------- (c) cert only, key reused
def test_c_cert_only_replacement_reusing_key(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    cur_key = serialization.load_pem_private_key((CERTS / "nginx/privkey.pem").read_bytes(), None)
    key_bytes_before = (CERTS / "nginx/privkey.pem").read_bytes()
    version, new_fp = _version(db, ["nginx.test.local"], key=cur_key, with_key=False, reuse=True)
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "completed"
    assert (CERTS / "nginx/privkey.pem").read_bytes() == key_bytes_before
    assert _served(8443, "nginx.test.local") == new_fp


# --------------------------------------------------------------------------- (d) haproxy combined
def test_d_haproxy_combined_pem(db, world, faults):
    server, op = world
    inst = _inst(db, server, "haproxy", CERTS / "haproxy/combined.pem", None, 10443, "haproxy.test.local",
                 is_combined_pem=True)
    version, new_fp = _version(db, ["haproxy.test.local"])
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "completed"
    data = (CERTS / "haproxy/combined.pem").read_bytes()
    assert data.index(b"BEGIN CERTIFICATE") < data.index(b"PRIVATE KEY")
    assert _served(10443, "haproxy.test.local") == new_fp


# --------------------------------------------------------------------------- (e) config test failure
def test_e_config_test_failure_rolls_back_with_verification(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    old_fp = _fp(CERTS / "nginx/fullchain.pem")
    before = _tree_hash()
    version, _ = _version(db, ["nginx.test.local"])
    faults["tamper_key"] = inst.key_path          # a mismatching key lands on disk -> real `nginx -t` fails
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "rolled_back"
    _j, (t,) = _status(db, job)
    assert t.status == "rolled_back" and t.error_code == "CONFIG_TEST_FAILED" and t.rollback_attempts == 1
    assert _served(8443, "nginx.test.local") == old_fp
    assert _tree_hash() == before


# --------------------------------------------------------------------------- (f) verification mismatch
def test_f_verification_mismatch_rolls_back(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    inst.verify_port = 9443                       # endpoint serves the apache certificate, never the new one
    db.commit()
    old_fp = _fp(CERTS / "nginx/fullchain.pem")
    before = _tree_hash()
    version, _ = _version(db, ["nginx.test.local"])
    body = _req(version, [inst])
    body["acknowledged_warnings"] += ["ENDPOINT_SERVES_DIFFERENT_CERT"]
    job, _ = deployments.create(db, op, uuid.uuid4().hex, body, dispatch_now=False)
    assert engine.run_job(job.id) == "rolled_back"
    _, (t,) = _status(db, job)
    assert t.error_code == "VERIFY_FINGERPRINT_MISMATCH"
    assert _fp(CERTS / "nginx/fullchain.pem") == old_fp and _tree_hash() == before


# --------------------------------------------------------------------------- (g) rollback failure
def test_g_rollback_failure_needs_manual_intervention(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    version, _ = _version(db, ["nginx.test.local"])
    faults.update(tamper_key=inst.key_path, fail_restore=True)
    job = _create(db, op, version, [inst])
    assert engine.run_job(job.id) == "manual_intervention_required"
    j, (t,) = _status(db, job)
    assert t.status == "manual_intervention_required" and j.rollback_status == "manual_intervention_required"
    assert not db.scalars(select(__import__("app.models", fromlist=["DeploymentLock"]).DeploymentLock)).all()
    # leave the target healthy for the following tests: restore via the verified manual path
    faults.clear()
    from app.models import Backup

    assert engine.restore_backup(db, db.get(Backup, t.backup_id), op)["ok"]


# --------------------------------------------------------------------------- (h) lock conflict
def test_h_concurrent_deployment_on_same_path_is_blocked_by_lock(db, world, faults, monkeypatch):
    server, op = world
    inst = _nginx(db, server)
    version, _ = _version(db, ["nginx.test.local"])
    job = _create(db, op, version, [inst])
    real = os.path.realpath(inst.cert_path)
    assert locks.acquire(locks.file_key(server.id, real), owner="other-deployment")
    with pytest.raises(AppErrorType):
        deployments.create(db, op, uuid.uuid4().hex, _req(version, [inst]), dispatch_now=False)
    monkeypatch.setattr(planner, "_check_concurrency", lambda *a, **k: None)
    before = _tree_hash()
    assert engine.run_job(job.id) == "failed"
    _, (t,) = _status(db, job)
    assert t.error_code == "LOCK_HELD" and _tree_hash() == before
    locks.release(locks.file_key(server.id, real), owner="other-deployment")


from app.core.errors import AppError as AppErrorType


# --------------------------------------------------------------------------- (i) dry run
def test_i_dry_run_leaves_remote_filesystem_byte_identical(db, world, faults):
    server, op = world
    inst = _nginx(db, server)
    apache = _inst(db, server, "apache", CERTS / "apache/cert.pem", CERTS / "apache/privkey.pem", 9443,
                   "apache.test.local", chain_path=str(CERTS / "apache/chain.pem"))
    version, _ = _version(db, ["nginx.test.local"])
    stage_root = Path("/var/lib/cdp-helper/staging")
    stage_before = sorted(os.listdir(stage_root)) if stage_root.exists() else []
    before, dirs = _tree_hash(), _all_dirs()
    plan = deployments.plan(db, op, _req(version, [inst]))
    assert plan["read_only"] and plan["targets"][0]["files"] and plan["targets"][0]["config_test"]["current_ok"]
    plan2 = deployments.plan(db, op, _req(version, [inst, apache]))
    assert any(f["code"] == "SAN_MISMATCH" for f in plan2["findings"])          # apache.test.local not covered
    assert _tree_hash() == before and _all_dirs() == dirs
    assert (sorted(os.listdir(stage_root)) if stage_root.exists() else []) == stage_before


# --------------------------------------------------------------------------- (j) certbot
def test_j_certbot_managed_path_is_blocked(db, world, faults):
    server, op = world
    le = Path("/etc/letsencrypt/live/certbot.test.local")
    inst = _inst(db, server, "nginx", le / "fullchain.pem", le / "privkey.pem", 8443, "certbot.test.local",
                 managed_by_certbot=True)
    version, _ = _version(db, ["certbot.test.local"])
    plan = deployments.plan(db, op, _req(version, [inst]))
    assert "CERTBOT_MANAGED" in {f["code"] for f in plan["findings"] if f["severity"] == "blocking"}
    with pytest.raises(AppErrorType) as ei:
        deployments.create(db, op, uuid.uuid4().hex, _req(version, [inst]), dispatch_now=False)
    assert ei.value.code == "PREFLIGHT_BLOCKED"


# --------------------------------------------------------------------------- (k) crash + resume
def test_k_worker_killed_mid_activation_then_resumed(db, world, faults, monkeypatch):
    server, op = world
    inst = _nginx(db, server)
    old_fp = _fp(CERTS / "nginx/fullchain.pem")
    before = _tree_hash()
    version, _ = _version(db, ["nginx.test.local"])
    job = _create(db, op, version, [inst])
    faults["crash_after"] = 1                     # killed after the first file was installed
    with monkeypatch.context() as m:
        m.setattr(locks, "release", lambda *a, **k: True)       # a killed worker leaves its locks behind
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    assert _tree_hash() != before                 # genuinely half-applied on the real host
    with SessionLocal() as s:
        s.execute(text("UPDATE deployment_locks SET expires_at = now() - interval '1 minute'"))
        s.commit()
    assert engine.run_job(job.id) == "rolled_back"
    _, (t,) = _status(db, job)
    assert t.error_code == "WORKER_INTERRUPTED"
    assert next(s for s in t.steps if s["name"] == "reconcile")["detail"]["classification"] == "mixed"
    assert _tree_hash() == before and _served(8443, "nginx.test.local") == old_fp


def test_k2_crash_after_all_files_installed_continues_without_reinstalling(db, world, faults, monkeypatch):
    server, op = world
    inst = _nginx(db, server)
    version, new_fp = _version(db, ["nginx.test.local"])
    job = _create(db, op, version, [inst])
    faults["crash_after"] = 2
    with monkeypatch.context() as m:
        m.setattr(locks, "release", lambda *a, **k: True)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    with SessionLocal() as s:
        s.execute(text("UPDATE deployment_locks SET expires_at = now() - interval '1 minute'"))
        s.commit()
    n = len(faults["installs"])
    assert engine.run_job(job.id) == "completed"
    assert len(faults["installs"]) == n
    assert _served(8443, "nginx.test.local") == new_fp


# --------------------------------------------------------------------------- (l) multi target canary stop
def test_l_multi_target_canary_failure_stops_further_activations(db, world, faults):
    server, op = world
    nginx = _nginx(db, server)
    apache = _inst(db, server, "apache", CERTS / "apache/cert.pem", CERTS / "apache/privkey.pem", 9443,
                   "apache.test.local", chain_path=str(CERTS / "apache/chain.pem"))
    version, _ = _version(db, ["nginx.test.local", "apache.test.local"])
    before = _tree_hash()
    faults["tamper_key"] = nginx.key_path          # canary (first) fails its config test
    job = _create(db, op, version, [nginx, apache], mode="canary", failure_threshold=1)
    assert engine.run_job(job.id) == "rolled_back"
    _, ts = _status(db, job)
    by = {t.installation_id: t for t in ts}
    assert by[nginx.id].status == "rolled_back" and by[nginx.id].is_canary
    assert by[apache.id].status == "cancelled" and by[apache.id].error_code == "SKIPPED"
    assert _tree_hash() == before
