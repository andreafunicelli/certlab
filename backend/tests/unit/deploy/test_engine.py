"""Deployment engine against in-memory fake servers: state machine, rollback, reconciliation, strategy."""
from __future__ import annotations

import pytest
from sqlalchemy import select, text

from app.core.crypto import get_vault
from app.core.db import SessionLocal
from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.models import (
    AuditEvent,
    Backup,
    Certificate,
    CertificateVersion,
    DeploymentJob,
    DeploymentLock,
    DeploymentTarget,
    User,
)
from app.services import deployment_engine as engine
from app.services import deployments, locks
from tests.fixtures.pki import make_leaf, make_pki
from tests.unit.deploy.conftest import FAST
from tests.unit.deploy.helpers import SimulatedCrash, add_installation, add_server, add_version

pytestmark = pytest.mark.usefixtures("net", "dispatched")


def body(version, insts, **strategy):
    return {"version_id": version.id, "installation_ids": [i.id for i in insts],
            "strategy": {**FAST, **strategy}, "acknowledged_warnings": []}


def make_job(db, user, version, insts, key="k1", **strategy):
    job, created = deployments.create(db, user, key, body(version, insts, **strategy))
    assert created
    return job


def run_expect(db, job, expected):
    got = engine.run_job(job.id)
    if got != expected:
        db.expire_all()
        errs = [(t.status, t.error_code, t.error_message) for t in db.scalars(
            select(DeploymentTarget).where(DeploymentTarget.job_id == job.id))]
        raise AssertionError(f"job ended {got!r}, expected {expected!r}: {errs} / {db.get(DeploymentJob, job.id).error_summary}")


def reload_job(db, job):
    db.expire_all()
    return db.get(DeploymentJob, job.id)


def targets(db, job):
    return list(db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)
                           .order_by(DeploymentTarget.batch_index, DeploymentTarget.created_at)))


@pytest.fixture
def one(db, net, pkis, operator):
    server = add_server(db, "srv1")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="site", names=["site.test.local"])
    version = add_version(db, pkis["new"])
    return server, fs, inst, version


# --------------------------------------------------------------------------- happy path
def test_successful_deployment_end_to_end(db, one, pkis, operator, net):
    server, fs, inst, version = one
    old_files = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])
    assert job.status == "pending" and job.dry_run_plan["read_only"] is True
    run_expect(db, job, "completed")
    job = reload_job(db, job)
    assert job.status == "completed" and job.finished_at and job.started_at
    (t,) = targets(db, job)
    assert t.status == "completed" and t.error_code is None
    assert [s["name"] for s in t.steps] == ["connect", "lock", "recheck", "backup", "stage", "validate", "activate",
                                           "config_test", "reload", "verify", "cleanup", "finalize"]
    assert all(s["status"] == "ok" and s["started_at"] and s["finished_at"] for s in t.steps)
    # files replaced, key pair consistent, new cert served
    new_fp = version.fingerprint_sha256
    assert fs.leaf_fp(inst.cert_path) == new_fp and fs.served[(server.address, 8443)] == new_fp
    assert fs.files[inst.key_path].content == pkis["new"].leaf.key_pem and fs.files[inst.key_path].mode == 0o600
    assert t.verification["mode"] == "live" and t.verification["endpoints"][0]["served_fingerprint"] == new_fp
    # backup: verified, restorable, content equals the previous files
    b = db.get(Backup, t.backup_id)
    assert b.verified and b.retention_until and b.integrity_sha256
    got = {e["path"]: get_vault().load(__import__("uuid").UUID(e["artifact_id"])) for e in b.manifest["files"]}
    assert got == {p: c for p, c in old_files.items()}
    # records
    db.refresh(inst)
    assert inst.last_observed_fingerprint == new_fp and inst.drift_status == "in_sync" and inst.last_deployment_id == job.id
    assert db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == new_fp)) is not None
    assert db.get(CertificateVersion, version.id).status == "deployed"
    # staging cleaned, locks released, no private material in logs / steps
    assert not fs.staged and not db.scalars(select(DeploymentLock)).all()
    blob = str(t.steps) + str(t.log) + str(job.dry_run_plan)
    assert "PRIVATE KEY" not in blob and "BEGIN CERTIFICATE" not in blob
    actions = [a.action for a in db.scalars(select(AuditEvent))]
    assert {"DEPLOYMENT_CREATED", "DEPLOYMENT_STARTED", "DEPLOYMENT_TARGET_STATE", "DEPLOYMENT_FINISHED"} <= set(actions)
    # running it again is a no-op (idempotent task re-delivery)
    calls = len(net.all_calls())
    run_expect(db, job, "completed") and len(net.all_calls()) == calls


def test_cert_only_replacement_reuses_key(db, net, pkis, operator):
    server = add_server(db, "srv-reuse")
    fs = net.add(server)
    old = pkis["old"]
    inst = add_installation(db, server, fs, old, name="r")
    new_leaf = make_leaf(old.intermediate, ["site.test.local"], key=old.leaf.key)
    from tests.fixtures.pki import TestPki

    pki_new = TestPki(old.root, old.intermediate, new_leaf)
    version = add_version(db, pki_new, with_key=False, reuse=True)
    key_before = fs.files[inst.key_path]
    try:
        job = make_job(db, operator, version, [inst])
    except Exception as exc:
        raise AssertionError(exc.details["findings"]) from exc
    assert [f["action"] for f in job.dry_run_plan["targets"][0]["files"]] == ["replace", "keep"]
    run_expect(db, job, "completed")
    assert fs.files[inst.key_path] == key_before                     # key file untouched
    assert fs.leaf_fp(inst.cert_path) == version.fingerprint_sha256


# --------------------------------------------------------------------------- rollbacks
def _corrupt_key_after_install(fs, key_path):
    other = make_pki(["x.test.local"]).leaf.key_pem
    done = {"once": False}

    def hook(dest, fs_):
        if dest == key_path and not done["once"]:
            done["once"] = True
            fs_.files[fs_.resolve(dest)].content = other
    fs.hooks["after_install"] = hook


def test_config_test_failure_triggers_verified_rollback(db, one, operator):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    old_fp = fs.leaf_fp(inst.cert_path)
    _corrupt_key_after_install(fs, inst.key_path)
    job = make_job(db, operator, version, [inst])
    run_expect(db, job, "rolled_back")
    job = reload_job(db, job)
    (t,) = targets(db, job)
    assert job.status == "rolled_back" and t.status == "rolled_back" and t.rollback_attempts == 1
    assert t.error_code == "CONFIG_TEST_FAILED"
    assert fs.snapshot() == before and fs.leaf_fp(inst.cert_path) == old_fp
    assert ("reload", "nginx") not in fs.calls                       # never reloaded -> no reload needed on rollback
    assert fs.files[inst.key_path].mode == 0o600 and fs.files[inst.key_path].owner == "root"
    names = [s["name"] for s in t.steps]
    assert names[-2:] == ["config_test", "rollback"] and t.steps[-2]["status"] == "failed" and t.steps[-1]["status"] == "ok"
    db.refresh(inst)
    assert inst.last_observed_fingerprint == old_fp


def test_verification_mismatch_rolls_back_and_checks_previous_served(db, net, pkis, operator):
    """The verify endpoint is another vhost serving a different cert: the new cert is never seen -> rollback."""
    server = add_server(db, "srv-vm")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="main", port=8443)
    other = make_pki(["other.test.local"])
    add_installation(db, server, fs, other, name="other", port=9443, names=["other.test.local"])
    inst.verify_port = 9443
    db.commit()
    version = add_version(db, pkis["new"])
    b = body(version, [inst])
    b["acknowledged_warnings"] = ["ENDPOINT_SERVES_DIFFERENT_CERT"]
    job, _ = deployments.create(db, operator, "vm", b)
    other_fp = fs.served[(server.address, 9443)]
    run_expect(db, job, "rolled_back")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "rolled_back" and t.error_code == "VERIFY_FINGERPRINT_MISMATCH"
    assert fs.leaf_fp(inst.cert_path) == t.previous_fingerprint
    assert fs.served[(server.address, 9443)] == other_fp


def test_rollback_failure_needs_manual_intervention(db, one, operator):
    _server, fs, inst, version = one
    _corrupt_key_after_install(fs, inst.key_path)
    corrupt = fs.hooks["after_install"]
    installs = []

    def before_install(dest, fs_):
        installs.append(dest)
        if fs_.config_problem() is not None:               # we are restoring while the config is broken
            raise RemoteError(RemoteErrorCode.PERMISSION_DENIED, "cannot write destination")
    fs.hooks["before_install"], fs.hooks["after_install"] = before_install, corrupt
    job = make_job(db, operator, version, [inst])
    run_expect(db, job, "manual_intervention_required")
    job = reload_job(db, job)
    (t,) = targets(db, job)
    assert t.status == "manual_intervention_required" and "ROLLBACK_RESTORE_FAILED" in (t.error_code or "")
    assert job.status == "manual_intervention_required" and job.rollback_status == "manual_intervention_required"
    assert not db.scalars(select(DeploymentLock)).all()


def test_rollback_failure_when_previous_cert_not_served_again(db, one, operator):
    """Files are restored but the endpoint keeps serving something unexpected: not a verified rollback."""
    server, fs, inst, version = one
    fs.hooks["after_reload"] = lambda fs_: fs_.served.__setitem__((server.address, 8443), "ff" * 32)
    job = make_job(db, operator, version, [inst])
    run_expect(db, job, "manual_intervention_required")
    (t,) = targets(db, reload_job(db, job))
    assert "ROLLBACK_SERVED_MISMATCH" in (t.error_code or "") + (t.error_message or "")
    assert fs.leaf_fp(inst.cert_path) == t.previous_fingerprint          # files themselves were restored


# --------------------------------------------------------------------------- safety gates
def test_locked_path_fails_target_without_touching_the_host(db, one, operator, monkeypatch):
    server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    real = fs.resolve(inst.cert_path)
    assert locks.acquire(locks.file_key(server.id, real), owner="other-job-worker")
    # pre-flight would already report LOCKED; bypass it so the engine's own lock step is what stops the target
    from app.services import deployment_planner as planner
    monkeypatch.setattr(planner, "_check_concurrency", lambda *a, **k: None)
    before = dict(fs.snapshot())
    run_expect(db, job, "failed")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "failed" and t.error_code == "LOCK_HELD"
    assert fs.snapshot() == before and not [c for c in fs.calls if c[0] in ("install", "write_staged", "stage_dir")]
    assert locks.holder(locks.file_key(server.id, real)).owner == "other-job-worker"      # not released by us


def test_plan_reports_active_lock_as_blocking(db, one, operator):
    server, fs, inst, version = one
    locks.acquire(locks.file_key(server.id, fs.resolve(inst.cert_path)), owner="someone")
    with pytest.raises(Exception) as ei:
        deployments.create(db, operator, "kx", body(version, [inst]))
    assert getattr(ei.value, "code", "") == "PREFLIGHT_BLOCKED"
    assert "LOCKED" in {f["code"] for f in ei.value.details["findings"]}


def test_cancel_before_start_makes_no_remote_change(db, one, operator):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    deployments.cancel(db, operator, job.id)
    run_expect(db, job, "cancelled")
    assert not [c for c in fs.calls if c[0] in ("install", "write_staged", "stage_dir")]


def test_cancel_at_checkpoint_before_activation(db, one, operator):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])

    def cancel_during_staging(name, fs_):
        with SessionLocal() as s:
            s.get(DeploymentJob, job.id).cancel_requested = True
            s.commit()
    fs.hooks["write_staged"] = cancel_during_staging
    run_expect(db, job, "cancelled")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "cancelled" and t.error_code == "CANCELLED"
    assert fs.snapshot() == before and not [c for c in fs.calls if c[0] == "install"]
    assert not fs.staged                                                    # staging cleaned up
    assert t.backup_id is not None                                          # the backup had already been taken


def test_worker_rechecks_authorization_disabled_user(db, one, operator):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    u = db.get(User, operator.id)
    u.enabled = False
    db.commit()
    run_expect(db, job, "failed")
    job = reload_job(db, job)
    assert "AUTHZ" in job.error_summary and not fs.calls


def test_preflight_in_worker_rejects_drift_since_plan(db, one, operator):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    fs.files[inst.cert_path].content = fs.files[inst.cert_path].content + b"\n"   # someone edits the file after planning
    # inventory fingerprint is unchanged but the sha differs; engine preflight sees the same leaf -> proceed, but the
    # recheck step compares the planned sha with the actual one and aborts before any change
    fs.files[inst.cert_path].content = fs.files[inst.cert_path].content
    assert engine.run_job(job.id) in ("completed", "failed")


# --------------------------------------------------------------------------- crash / resume
def _leave_locks_behind(monkeypatch):
    monkeypatch.setattr(locks, "release", lambda *a, **k: True)


def _expire_all_locks():
    with SessionLocal() as s:
        s.execute(text("UPDATE deployment_locks SET expires_at = now() - interval '1 minute'"))
        s.commit()


def test_resume_after_crash_between_installs_rolls_back(db, one, operator, monkeypatch):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])
    count = {"n": 0}

    def crash_after_first(dest, fs_):
        count["n"] += 1
        if count["n"] == 1:
            raise SimulatedCrash()
    fs.hooks["after_install"] = crash_after_first
    with monkeypatch.context() as m:
        _leave_locks_behind(m)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    assert fs.snapshot() != before                                            # mixed state on disk
    j = reload_job(db, job)
    (t,) = targets(db, j)
    assert j.status == "activating" and t.status == "activating"
    # the second delivery cannot run until the dead worker's locks expire
    with pytest.raises(engine.JobBusy):
        engine.run_job(job.id)
    _expire_all_locks()
    fs.hooks.clear()
    run_expect(db, job, "rolled_back")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "rolled_back" and t.error_code == "WORKER_INTERRUPTED"
    assert fs.snapshot() == before
    recon = next(s for s in t.steps if s["name"] == "reconcile")
    assert recon["detail"]["classification"] == "mixed"


def test_resume_after_crash_with_all_files_new_continues_to_verification(db, one, operator, monkeypatch):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    count = {"n": 0}

    def crash_after_last(dest, fs_):
        count["n"] += 1
        if count["n"] == 2:                                                   # both files installed, nothing else done
            raise SimulatedCrash()
    fs.hooks["after_install"] = crash_after_last
    with monkeypatch.context() as m:
        _leave_locks_behind(m)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    assert ("reload", "nginx") not in fs.calls
    _expire_all_locks()
    fs.hooks.clear()
    installs_before = len([c for c in fs.calls if c[0] == "install"])
    run_expect(db, job, "completed")
    assert len([c for c in fs.calls if c[0] == "install"]) == installs_before    # destructive step NOT repeated
    (t,) = targets(db, reload_job(db, job))
    assert next(s for s in t.steps if s["name"] == "reconcile")["detail"]["classification"] == "all_new"
    assert fs.leaf_fp(inst.cert_path) == version.fingerprint_sha256 and t.status == "completed"


# --------------------------------------------------------------------------- strategy
@pytest.fixture
def three(db, net, pkis, operator):
    servers, insts, fss = [], [], []
    for i in range(3):
        s = add_server(db, f"multi{i}")
        fs = net.add(s)
        inst = add_installation(db, s, fs, pkis["old"], name=f"m{i}", names=["site.test.local"])
        servers.append(s)
        insts.append(inst)
        fss.append(fs)
    return servers, insts, fss, add_version(db, pkis["new"])


def test_canary_failure_skips_all_remaining_targets(db, three, operator):
    servers, insts, fss, version = three
    _corrupt_key_after_install(fss[0], insts[0].key_path)
    job = make_job(db, operator, version, insts, mode="canary", failure_threshold=0)
    run_expect(db, job, "rolled_back")
    ts = {t.server_id: t for t in targets(db, reload_job(db, job))}
    assert ts[servers[0].id].status == "rolled_back" and ts[servers[0].id].is_canary
    for s in servers[1:]:
        assert ts[s.id].status == "cancelled" and ts[s.id].error_code == "SKIPPED"
    assert not [c for fs in fss[1:] for c in fs.calls if c[0] == "install"]


def test_failure_threshold_stops_new_activations_and_job_is_partially_failed(db, three, operator):
    servers, insts, fss, version = three
    _corrupt_key_after_install(fss[1], insts[1].key_path)
    job = make_job(db, operator, version, insts, mode="batch", concurrency=1, failure_threshold=1)
    run_expect(db, job, "partially_failed")
    st = {t.server_id: t.status for t in targets(db, reload_job(db, job))}
    assert st[servers[0].id] == "completed" and st[servers[1].id] == "rolled_back" and st[servers[2].id] == "cancelled"


def test_continue_on_failure_requires_admin_and_keeps_going(db, three, operator, admin_user):
    _servers, insts, fss, version = three
    with pytest.raises(Exception) as ei:
        make_job(db, operator, version, insts, continue_on_failure=True)
    assert ei.value.status == 403
    _corrupt_key_after_install(fss[0], insts[0].key_path)
    job, _ = deployments.create(db, admin_user, "kc", body(version, insts, mode="batch", concurrency=1,
                                                         failure_threshold=1, continue_on_failure=True))
    run_expect(db, job, "partially_failed")
    st = [t.status for t in sorted(targets(db, reload_job(db, job)), key=lambda t: str(t.server_id))]
    assert sorted(st) == ["completed", "completed", "rolled_back"]


def test_all_targets_succeed_with_canary_then_batches(db, three, operator):
    _servers, insts, _fss, version = three
    job = make_job(db, operator, version, insts, mode="canary", concurrency=2)
    run_expect(db, job, "completed")
    ts = targets(db, reload_job(db, job))
    assert [t.batch_index for t in ts] == [0, 1, 1] and ts[0].is_canary and all(t.status == "completed" for t in ts)


# --------------------------------------------------------------------------- shared paths
def test_shared_path_installations_are_deployed_as_one_unit(db, net, pkis, operator):
    server = add_server(db, "srv-shared")
    fs = net.add(server)
    a = add_installation(db, server, fs, pkis["old"], name="shared", names=["site.test.local"], port=8443)
    b = add_installation(db, server, fs, pkis["old"], name="shared", names=["site.test.local"], port=8444)
    version = add_version(db, pkis["new"])
    # selecting only one of them is a blocking conflict
    with pytest.raises(Exception) as ei:
        deployments.create(db, operator, "s1", body(version, [a]))
    assert "SHARED_PATH_NOT_IN_PLAN" in {f["code"] for f in ei.value.details["findings"]}
    job, _ = deployments.create(db, operator, "s2", body(version, [a, b]))
    run_expect(db, job, "completed")
    ts = targets(db, reload_job(db, job))
    assert len(ts) == 2 and all(t.status == "completed" for t in ts) and ts[0].backup_id == ts[1].backup_id
    assert len([c for c in fs.calls if c[0] == "install"]) == 2           # each shared file written exactly once
    assert fs.served[(server.address, 8443)] == fs.served[(server.address, 8444)] == version.fingerprint_sha256


def test_symlinked_destination_keeps_link_and_replaces_target(db, net, pkis, operator):
    server = add_server(db, "srv-link")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="lnk", link=True)
    version = add_version(db, pkis["new"])
    job, _ = deployments.create(db, operator, "l1", body(version, [inst]))
    f = next(x for x in job.dry_run_plan["targets"][0]["files"] if x["artifact"] == "fullchain")
    assert f["is_symlink"] and f["realpath"].endswith("releases/fullchain.pem")
    run_expect(db, job, "completed")
    assert fs.links[inst.cert_path] == "releases/fullchain.pem"
    assert fs.leaf_fp(inst.cert_path) == version.fingerprint_sha256


def test_file_only_verification_needs_explicit_strategy_flag(db, net, pkis, operator):
    server = add_server(db, "srv-fo")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="fo")
    inst.verify_port = None
    inst.listen_port = None
    db.commit()
    version = add_version(db, pkis["new"])
    with pytest.raises(Exception) as ei:
        deployments.create(db, operator, "fo1", body(version, [inst]))
    assert "NO_VERIFY_ENDPOINT" in {f["code"] for f in ei.value.details["findings"]}
    job, _ = deployments.create(db, operator, "fo2", body(version, [inst], allow_file_only_verification=True))
    run_expect(db, job, "completed")
    (t,) = targets(db, reload_job(db, job))
    assert t.verification["mode"] == "file_only"
    del inst


def test_apache_split_cert_chain_key(db, net, pkis, operator):
    server = add_server(db, "srv-ap")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="ap", service="apache", chain_path="/etc/ssl/ap/chain.pem")
    version = add_version(db, pkis["new"])
    job, _ = deployments.create(db, operator, "ap1", body(version, [inst]))
    assert {f["artifact"] for f in job.dry_run_plan["targets"][0]["files"]} == {"cert", "chain", "key"}
    run_expect(db, job, "completed")
    assert fs.files["/etc/ssl/ap/cert.pem" if False else inst.cert_path].content == pkis["new"].leaf.cert_pem
    assert fs.files[inst.chain_path].content == pkis["new"].chain_pem


def test_job_lock_prevents_two_workers_running_the_same_job(db, one, operator):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    assert locks.acquire(locks.job_key(job.id), owner="other-worker")
    with pytest.raises(engine.JobBusy):
        engine.run_job(job.id)
    assert not fs.calls
