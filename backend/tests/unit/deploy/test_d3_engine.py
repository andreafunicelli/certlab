"""Stream D3 fixes: K2 finalize recovery, K3 lock-held restore, K4/K5 dispatch + sweep + cancel, K6 lost locks,
K7 cancel notice, K8 strict chain, K10 SSH limits, queued manual restore."""
from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.errors import AppError
from app.integrations.contracts import EndpointCertResult
from app.models import AuditEvent, Backup, DeploymentJob, DeploymentTarget, Environment, User
from app.models.base import utcnow
from app.services import deployment_engine as engine
from app.services import deployments, locks
from app.services import settings as settings_service
from tests.conftest import PASSWORD
from tests.fixtures.pki import make_pki
from tests.unit.deploy.conftest import FAST
from tests.unit.deploy.helpers import add_installation, add_server, add_version

pytestmark = pytest.mark.usefixtures("net", "dispatched")
API = "/api/v1"


def body(version, insts, **strategy):
    return {"version_id": version.id, "installation_ids": [i.id for i in insts],
            "strategy": {**FAST, **strategy}, "acknowledged_warnings": []}


@pytest.fixture
def one(db, net, pkis, operator):
    server = add_server(db, "d3-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="site", names=["site.test.local"])
    version = add_version(db, pkis["new"])
    return server, fs, inst, version


def make_job(db, user, version, insts, key="k1", **strategy):
    job, created = deployments.create(db, user, key, body(version, insts, **strategy))
    assert created
    return job


def target(db, job):
    db.expire_all()
    return db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)).one()


def new_fp(version):
    return version.fingerprint_sha256


# =========================================================================== K2
def test_k2_finalize_is_retried_and_idempotent(db, one, operator, monkeypatch):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    real = engine.UnitRunner._finalize_records
    calls = {"n": 0}

    def flaky(self, art, st):
        calls["n"] += 1
        real(self, art, st)                       # partially/fully written, then the database "fails"
        if calls["n"] < 3:
            raise RuntimeError("database went away")

    monkeypatch.setattr(engine.UnitRunner, "_finalize_records", flaky)
    monkeypatch.setattr(engine, "FINALIZE_RETRY_DELAY", 0)
    assert engine.run_job(job.id) == "completed"
    t = target(db, job)
    assert calls["n"] == 3 and t.status == "completed" and t.verification["mode"] == "live"
    assert fs.leaf_fp(inst.cert_path) == new_fp(version)
    assert [s["status"] for s in t.steps if s["name"] == "finalize"] == ["failed", "failed", "ok"]


def test_k2_cleanup_failure_after_verification_does_not_fail_the_target(db, one, operator, monkeypatch):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst])

    async def boom(self):
        raise RuntimeError("cleanup exploded")

    monkeypatch.setattr(engine.UnitRunner, "_cleanup_stage", boom)
    assert engine.run_job(job.id) == "completed"
    assert target(db, job).status == "completed" and fs.leaf_fp(inst.cert_path) == new_fp(version)


def test_k2_persistent_finalize_failure_with_verified_files_and_endpoint_is_completed(db, one, operator, monkeypatch):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst])

    def always(self, art, st):
        raise RuntimeError("database refuses")

    monkeypatch.setattr(engine.UnitRunner, "_finalize_records", always)
    monkeypatch.setattr(engine, "FINALIZE_RETRY_DELAY", 0)
    assert engine.run_job(job.id) == "completed"
    t = target(db, job)
    assert t.status == "completed" and t.error_code is None
    assert t.verification["mode"] == "live" and t.verification["files"]            # verification persisted first
    assert fs.leaf_fp(inst.cert_path) == new_fp(version)                           # new files stay: they are verified
    assert any("could not be finalised" in e["message"] for e in t.log)


def test_k2_persistent_finalize_failure_without_verified_endpoint_needs_a_human(db, one, operator, monkeypatch):
    _s, _fs, inst, version = one
    job = make_job(db, operator, version, [inst])

    def always(self, art, st):
        raise RuntimeError("database refuses")

    monkeypatch.setattr(engine.UnitRunner, "_finalize_records", always)
    monkeypatch.setattr(engine.UnitRunner, "_verified_ok", lambda self: False)
    monkeypatch.setattr(engine, "FINALIZE_RETRY_DELAY", 0)
    assert engine.run_job(job.id) == "manual_intervention_required"
    t = target(db, job)
    assert t.status == "manual_intervention_required" and t.error_code == "FINALIZE_FAILED"
    assert t.verification["files"]                                                  # evidence still stored


def test_k2_unexpected_error_after_files_were_replaced_is_not_a_plain_failure(db, one, operator, monkeypatch):
    _s, _fs, inst, version = one
    job = make_job(db, operator, version, [inst])

    async def broken(self, specs, art, *, skip_install):
        self.state["activated"] = [f["dest_path"] for f in specs]
        raise RuntimeError("worker logic error")

    monkeypatch.setattr(engine.UnitRunner, "_activate_and_verify", broken)
    assert engine.run_job(job.id) == "manual_intervention_required"
    assert target(db, job).error_code == "INTERNAL_ERROR"


# =========================================================================== K3
def _completed_target(db, one, operator):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    assert engine.run_job(job.id) == "completed"
    t = target(db, job)
    return job, t, db.get(Backup, t.backup_id), fs, inst


def test_k3_lock_held_during_manual_restore_changes_nothing(db, one, operator, admin_user):
    _job, t, backup, fs, _inst = _completed_target(db, one, operator)
    before = fs.snapshot()
    key = locks.file_key(backup.server_id, backup.manifest["files"][0]["realpath"])
    assert locks.acquire(key, owner="other-worker", job_id=None, ttl_seconds=60)
    result = engine.restore_backup(db, backup, admin_user, target=t)
    assert result["ok"] is False and result["error_code"] == "LOCK_HELD"
    db.expire_all()
    t, backup = db.get(DeploymentTarget, t.id), db.get(Backup, backup.id)
    assert t.status == "completed" and t.error_code is None and t.current_step is None      # not manual_intervention_required
    assert backup.restore_status == "none" and fs.snapshot() == before
    assert engine.classify(locks.LockHeld(key, "x", None))[0] == "LOCK_HELD"


def test_k3_api_returns_409_lock_held(login, db, one, operator):
    job, t, backup, _fs, _inst = _completed_target(db, one, operator)
    admin = login("admin")
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    key = locks.file_key(backup.server_id, backup.manifest["files"][0]["realpath"])
    locks.acquire(key, owner="other-worker", job_id=None, ttl_seconds=60)
    for url in (f"{API}/backups/{backup.id}/restore", f"{API}/deployments/{job.id}/targets/{t.id}/rollback"):
        r = admin.post(url)
        assert r.status_code == 409 and r.json()["error"]["code"] == "LOCK_HELD", r.text
    db.expire_all()
    assert db.get(DeploymentTarget, t.id).status == "completed" and db.get(Backup, backup.id).restore_status == "none"


# =========================================================================== queued manual restore
@pytest.fixture
def restore_queue(monkeypatch):
    sent: list[tuple] = []
    monkeypatch.setattr(deployments, "dispatch_restore", lambda *a: sent.append(a))
    return sent


def test_manual_rollback_is_queued_then_executed_by_the_worker(login, db, one, operator, restore_queue):
    job, t, backup, fs, inst = _completed_target(db, one, operator)
    old_fp = t.previous_fingerprint
    admin = login("admin")
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    r = admin.post(f"{API}/deployments/{job.id}/targets/{t.id}/rollback")
    assert r.status_code == 202 and r.json()["accepted"] and r.json()["target_id"] == str(t.id)
    assert r.json()["restore_status"] == "in_progress" and r.json()["job_id"] == str(job.id)
    assert fs.leaf_fp(inst.cert_path) == new_fp(one[3])                              # nothing ran in the request
    db.expire_all()
    assert db.get(Backup, backup.id).restore_status == "in_progress" and db.get(DeploymentTarget, t.id).current_step == "manual_rollback"
    (args,) = restore_queue
    assert args[4] == "deployments:rollback"
    result = engine.run_restore(args[0], args[1], args[2], previous_restore_status=args[3], permission=args[4])
    assert result["ok"]
    db.expire_all()
    t = db.get(DeploymentTarget, t.id)
    assert t.status == "rolled_back" and t.current_step is None and db.get(Backup, backup.id).restore_status == "restored"
    assert db.get(DeploymentJob, job.id).rollback_status == "rolled_back" and fs.leaf_fp(inst.cert_path) == old_fp
    actions = {a for (a,) in db.execute(select(AuditEvent.action))}
    assert {"DEPLOYMENT_MANUAL_ROLLBACK", "BACKUP_RESTORED"} <= actions


def test_backup_restore_api_is_queued_and_needs_reauth_and_permission(login, db, one, operator, restore_queue):
    _job, _t, backup, _fs, _inst = _completed_target(db, one, operator)
    admin, op = login("admin"), login("operator")
    assert op.post(f"{API}/backups/{backup.id}/restore").status_code == 403
    from sqlalchemy import text

    db.execute(text("UPDATE sessions SET reauth_at = NULL"))
    db.commit()
    assert admin.post(f"{API}/backups/{backup.id}/restore").json()["error"]["code"] == "REAUTH_REQUIRED"
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    r = admin.post(f"{API}/backups/{backup.id}/restore")
    assert r.status_code == 202 and r.json()["backup"]["restore_status"] == "in_progress"
    (args,) = restore_queue
    assert args[4] == "backups:restore"
    assert engine.run_restore(args[0], args[1], args[2], previous_restore_status=args[3], permission=args[4])["ok"]


def test_worker_reauthorizes_before_restoring(db, one, operator, admin_user, restore_queue):
    _job, t, backup, fs, _inst = _completed_target(db, one, operator)
    before = fs.snapshot()
    queued = deployments.queue_restore(db, admin_user, backup, t, permission="deployments:rollback")
    assert queued["accepted"]
    (args,) = restore_queue
    with SessionLocal() as s:                                                       # demoted while waiting in the queue
        s.get(User, admin_user.id).enabled = False
        s.commit()
    result = engine.run_restore(args[0], args[1], args[2], previous_restore_status=args[3], permission=args[4])
    assert result["ok"] is False and result["error_code"] == "AUTHZ"
    db.expire_all()
    assert db.get(Backup, backup.id).restore_status == "none" and db.get(DeploymentTarget, t.id).status == "completed"
    assert db.get(DeploymentTarget, t.id).current_step is None and fs.snapshot() == before


def test_restore_queue_failure_reverts_state_with_queue_unavailable(db, one, operator, admin_user, monkeypatch):
    _job, t, backup, _fs, _inst = _completed_target(db, one, operator)

    def down(*a):
        raise ConnectionError("broker down")

    monkeypatch.setattr(deployments, "dispatch_restore", down)
    with pytest.raises(AppError) as ei:
        deployments.queue_restore(db, admin_user, backup, t, permission="deployments:rollback")
    assert ei.value.code == "QUEUE_UNAVAILABLE" and ei.value.status == 503
    db.expire_all()
    assert db.get(Backup, backup.id).restore_status == "none" and db.get(DeploymentTarget, t.id).current_step is None


# =========================================================================== K4 / K5
def test_k4_dispatch_failure_on_create_fails_the_job_and_audits(db, one, operator, monkeypatch):
    _s, _fs, inst, version = one

    def down(job_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr(deployments, "dispatch", down)
    with pytest.raises(AppError) as ei:
        deployments.create(db, operator, "qfail-1", body(version, [inst]))
    assert ei.value.code == "QUEUE_UNAVAILABLE" and ei.value.status == 503
    db.expire_all()
    job = db.scalars(select(DeploymentJob)).one()
    assert job.status == "failed" and job.error_summary.startswith("QUEUE_UNAVAILABLE")
    assert target(db, job).status == "cancelled" and target(db, job).error_code == "QUEUE_UNAVAILABLE"
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "DEPLOYMENT_QUEUE_FAILED")) is not None


def test_k4_dispatch_failure_on_approve_and_retry(db, net, pkis, operator, admin_user, monkeypatch, dispatched):
    server = add_server(db, "prod-srv", env="Production")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="p")
    version = add_version(db, pkis["new"])
    job = make_job(db, operator, version, [inst], key="approve-1")
    assert job.status == "awaiting_approval" and dispatched == []
    monkeypatch.setattr(deployments, "dispatch", lambda j: (_ for _ in ()).throw(ConnectionError("down")))
    with pytest.raises(AppError) as ei:
        deployments.approve(db, admin_user, job.id)
    assert ei.value.code == "QUEUE_UNAVAILABLE"
    db.expire_all()
    assert db.get(DeploymentJob, job.id).status == "failed"


def test_k4_dispatch_failure_on_retry(db, one, operator, monkeypatch):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst], key="rt-1")
    other = make_pki(["x.test.local"]).leaf.key_pem
    done = {"once": False}

    def corrupt_once(dest, f):
        if dest == inst.key_path and not done["once"]:
            done["once"] = True
            f.files[f.resolve(dest)].content = other

    fs.hooks["after_install"] = corrupt_once
    assert engine.run_job(job.id) == "rolled_back"
    monkeypatch.setattr(deployments, "dispatch", lambda j: (_ for _ in ()).throw(ConnectionError("down")))
    db.expire_all()
    with pytest.raises(AppError) as ei:
        deployments.retry(db, operator, job.id)
    assert ei.value.code == "QUEUE_UNAVAILABLE"


def test_k5_sweep_redispatches_stuck_pending_then_fails_them(db, one, operator, dispatched):
    _s, _fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    assert dispatched == [job.id] and job.dispatch_attempts == 1 and job.status == "pending"
    # fresh: nothing to do
    assert deployments.sweep_stuck_pending(db) == {"redispatched": [], "failed": []}

    def age():
        with SessionLocal() as s:
            j = s.get(DeploymentJob, job.id)
            j.last_dispatched_at = utcnow() - timedelta(minutes=30)
            s.commit()

    age()
    assert deployments.sweep_stuck_pending(db)["redispatched"] == [str(job.id)]
    assert dispatched == [job.id, job.id]
    age()
    assert deployments.sweep_stuck_pending(db)["redispatched"] == [str(job.id)]
    assert len(dispatched) == 3
    age()
    out = deployments.sweep_stuck_pending(db)
    assert out == {"redispatched": [], "failed": [str(job.id)]} and len(dispatched) == 3
    db.expire_all()
    j = db.get(DeploymentJob, job.id)
    assert j.status == "failed" and j.error_summary.startswith("QUEUE_LOST") and target(db, j).status == "cancelled"


def test_k5_sweep_ignores_awaiting_approval_started_and_finished_jobs(db, net, pkis, one, operator):
    _s, _fs, inst, version = one
    server = add_server(db, "prod2", env="Production")
    fs = net.add(server)
    pinst = add_installation(db, server, fs, pkis["old"], name="p2")
    waiting = make_job(db, operator, version, [pinst], key="w1")
    started = make_job(db, operator, version, [inst], key="s1")
    with SessionLocal() as s:
        for jid in (waiting.id, started.id):
            j = s.get(DeploymentJob, jid)
            j.created_at = utcnow() - timedelta(hours=2)
            j.last_dispatched_at = utcnow() - timedelta(hours=2)
        s.get(DeploymentJob, started.id).started_at = utcnow()
        s.commit()
    assert waiting.status == "awaiting_approval"
    assert deployments.sweep_stuck_pending(db) == {"redispatched": [], "failed": []}


def test_k5_beat_entry_and_task_are_registered():
    from app.workers.celery_app import celery_app

    celery_app.loader.import_default_modules()
    assert celery_app.conf.beat_schedule["deployments-sweep-pending"]["task"] == "deployments.sweep_pending"
    celery_app.loader.import_default_modules()
    assert "deployments.sweep_pending" in celery_app.tasks and "backups.restore" in celery_app.tasks


def test_k5_cancel_pending_job_is_immediate_and_worker_does_nothing(db, one, operator, net):
    _s, _fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    cancelled = deployments.cancel(db, operator, job.id)
    assert cancelled.status == "cancelled" and cancelled.finished_at is not None
    t = target(db, job)
    assert t.status == "cancelled" and t.error_code == "CANCELLED"
    assert deployments.cancel_notice(db, cancelled)["effect"] == "cancelled"
    assert engine.run_job(job.id) == "cancelled" and net.all_calls() == [c for c in net.all_calls() if c[0] != "install"]
    assert deployments.sweep_stuck_pending(db) == {"redispatched": [], "failed": []}


# =========================================================================== K6
@pytest.fixture
def lock_sets(monkeypatch):
    created: list[locks.LockSet] = []
    orig = locks.LockSet.__init__

    def init(self, *a, **k):
        orig(self, *a, **k)
        created.append(self)

    monkeypatch.setattr(locks.LockSet, "__init__", init)
    return created


def test_k6_lost_lock_before_activation_stops_without_touching_the_host(db, one, operator, lock_sets):
    _s, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    before = fs.snapshot()
    fs.hooks["write_staged"] = lambda name, f: setattr(lock_sets[-1], "lost", True)
    assert engine.run_job(job.id) == "failed"
    t = target(db, job)
    assert t.error_code == "LOCK_LOST" and fs.snapshot() == before
    assert not any(c[0] == "install" for c in fs.calls)


@pytest.mark.parametrize("lose_after", [1, 3])
def test_k6_lost_lock_during_activation_or_rollback_stops_mutation(db, net, pkis, operator, lock_sets, lose_after):
    server = add_server(db, "k6-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="k6", names=["site.test.local"])
    version = add_version(db, pkis["new"])
    job = make_job(db, operator, version, [inst])
    installed = []

    def after_install(dest, f):
        installed.append(dest)
        if len(installed) == 2:
            f.current_config_broken = True       # start rollback after both forward writes
        if len(installed) == lose_after:
            lock_sets[-1].lost = True

    fs.hooks["after_install"] = after_install
    assert engine.run_job(job.id) == "manual_intervention_required"
    t = target(db, job)
    assert t.error_code == "LOCK_LOST"
    assert len(installed) == lose_after
    assert not any(c[0] == "reload" for c in fs.calls)


def test_manual_restore_stops_when_a_lock_is_lost(db, one, operator, admin_user, lock_sets):
    _job, t, backup, fs, _inst = _completed_target(db, one, operator)
    fs.calls.clear()
    fs.hooks["after_install"] = lambda dest, f: setattr(lock_sets[-1], "lost", True)
    result = engine.restore_backup(db, backup, admin_user, target=t)
    assert result["ok"] is False
    assert len([c for c in fs.calls if c[0] == "install"]) == 1
    assert not any(c[0] == "reload" for c in fs.calls)
    assert target(db, _job).status == "manual_intervention_required"


def test_manual_restore_fails_when_the_restored_endpoint_is_unreachable(db, one, operator, admin_user, monkeypatch):
    job, t, backup, _fs, _inst = _completed_target(db, one, operator)

    async def unreachable(host, port, sni, timeout, **kwargs):
        return EndpointCertResult(host, port, sni, False, None, (), None, None, "connection refused", None)

    monkeypatch.setattr("app.integrations.tls.probe.probe_endpoint", unreachable)
    result = engine.restore_backup(db, backup, admin_user, target=t)
    assert result["ok"] is False and result["error_code"] == "RESTORE_SERVED_MISMATCH"
    assert target(db, job).status == "manual_intervention_required"
    assert db.get(Backup, backup.id).restore_status == "failed"


async def test_k6_heartbeat_marks_lock_lost_when_renewal_fails(db):
    ls = locks.LockSet([f"k6:{uuid.uuid4()}"], owner="me", job_id=None, target_id=None, ttl_seconds=60)
    ls.acquire_all()
    try:
        ls.check_once()
        assert ls.lost is False
        locks.release(ls.keys[0], owner="me")                    # someone else (or expiry purge) removed it
        ls.check_once()
        assert ls.lost is True
    finally:
        ls.release_all()


# =========================================================================== K7
def test_k7_cancel_after_activation_started_returns_a_clear_notice(login, db, one, operator):
    _s, _fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    with SessionLocal() as s:
        s.get(DeploymentJob, job.id).status = "activating"
        t = s.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)).one()
        t.status = "verifying"
        s.commit()
    op = login("operator")
    r = op.post(f"{API}/deployments/{job.id}/cancel")
    assert r.status_code == 200 and r.json()["cancel_requested"] is True and r.json()["status"] == "activating"
    assert r.json()["cancel"]["effect"] == "too_late" and "activation has already started" in r.json()["cancel"]["message"]


# =========================================================================== K8
def _strict(db, name="Test"):
    env = db.scalar(select(Environment).where(Environment.name == name))
    env.require_trusted_chain = True
    db.commit()


def _trust(db, actor, pki):
    settings_service.update_section(db, actor, "security", settings_service._ensure(db, "security").version,
                                    {"trust_anchors_pem": pki.root.cert_pem.decode()})


def test_k8_preflight_blocks_untrusted_chain_only_in_strict_environments(db, one, operator):
    _s, _fs, inst, version = one
    plan = deployments.plan(db, operator, body(version, [inst]))
    assert plan["summary"]["can_proceed"]
    _strict(db)
    plan = deployments.plan(db, operator, body(version, [inst]))
    blocking = [f for f in plan["findings"] if f["code"] == "CHAIN_UNTRUSTED" and f["severity"] == "blocking"]
    assert blocking and not plan["summary"]["can_proceed"] and blocking[0]["installation_id"] == str(inst.id)
    with pytest.raises(AppError) as ei:
        deployments.create(db, operator, "strict-1", body(version, [inst]))
    assert ei.value.code == "PREFLIGHT_BLOCKED"


@pytest.mark.parametrize("chain_valid", [False, None])
def test_k8_trusted_chain_passes_preflight_and_verification_enforces_chain_valid(db, one, operator, admin_user, pkis, net, monkeypatch, chain_valid):
    _s, fs, inst, version = one
    _strict(db)
    _trust(db, admin_user, pkis["new"])
    plan = deployments.plan(db, operator, body(version, [inst]))
    assert plan["summary"]["can_proceed"], plan["findings"]
    orig = net.probe_endpoint

    async def untrusted(host, port, sni, timeout, trust_anchors_pem=None, expected_hostname=None):
        r = await orig(host, port, sni, timeout, trust_anchors_pem, expected_hostname)
        return EndpointCertResult(r.host, r.port, r.sni, r.ok, r.leaf, r.chain, chain_valid, r.hostname_matches, r.error, r.tls_version) \
            if r.ok else r

    monkeypatch.setattr("app.integrations.tls.probe.probe_endpoint", untrusted)
    before = fs.snapshot()
    job = make_job(db, operator, version, [inst], key="strict-2")
    assert engine.run_job(job.id) == "rolled_back"
    t = target(db, job)
    assert t.error_code == "VERIFY_CHAIN_UNTRUSTED" and fs.snapshot() == before


def test_k8_chain_valid_false_is_still_only_recorded_when_not_strict(db, one, operator, net, monkeypatch):
    _s, _fs, inst, version = one
    orig = net.probe_endpoint

    async def untrusted(host, port, sni, timeout, trust_anchors_pem=None, expected_hostname=None):
        r = await orig(host, port, sni, timeout, trust_anchors_pem, expected_hostname)
        return EndpointCertResult(r.host, r.port, r.sni, r.ok, r.leaf, r.chain, False, r.hostname_matches, r.error, r.tls_version) \
            if r.ok else r

    monkeypatch.setattr("app.integrations.tls.probe.probe_endpoint", untrusted)
    job = make_job(db, operator, version, [inst])
    assert engine.run_job(job.id) == "completed"
    assert target(db, job).verification["chain_valid"] is False


def test_k8_environment_api_exposes_the_flag(login, db):
    admin = login("admin")
    r = admin.post(f"{API}/environments", json={"name": "Strict", "require_trusted_chain": True})
    assert r.status_code in (200, 201), r.text
    assert r.json()["require_trusted_chain"] is True
    eid = r.json()["id"]
    r = admin.patch(f"{API}/environments/{eid}", json={"require_trusted_chain": False})
    assert r.status_code == 200 and r.json()["require_trusted_chain"] is False
    default = admin.post(f"{API}/environments", json={"name": "Loose"}).json()
    assert default["require_trusted_chain"] is False
    envs = {e["name"]: e for e in admin.get(f"{API}/environments").json()}
    assert "require_trusted_chain" in envs["Test"]


def test_k8_migration_defaults(db):
    from sqlalchemy import text

    with SessionLocal() as s:
        cols = s.execute(text("SELECT column_default, is_nullable FROM information_schema.columns "
                              "WHERE table_name='environments' AND column_name='require_trusted_chain'")).one()
    assert cols[0] == "false" and cols[1] == "NO"


# =========================================================================== K10
def test_k10_ssh_host_concurrency_setting_is_applied(db, admin_user):
    from app.integrations.ssh import connection
    from app.services import ssh_limits

    original = connection._default_limit
    try:
        sec = settings_service._ensure(db, "ssh")
        settings_service.update_section(db, admin_user, "ssh", sec.version, {"host_concurrency": 7})
        assert connection._default_limit == 7                         # applied in the saving process at once
        connection.set_host_concurrency_limit(2)
        assert ssh_limits.apply_from_db() == 7 and connection._default_limit == 7      # a worker picks it up per task
        connection._semaphores.clear()
        assert asyncio.run(_sem_value()) == 7
    finally:
        connection.set_host_concurrency_limit(original)


async def _sem_value() -> int:
    from app.integrations.ssh import connection

    sem = connection._semaphore(type("T", (), {"host": "h", "port": 22})())
    return sem._value


def test_k10_worker_tasks_and_signal_apply_limits(monkeypatch):
    from app.services import ssh_limits
    from app.workers import celery_app as celery_mod
    from app.workers import deploy_tasks

    seen = []
    monkeypatch.setattr(ssh_limits, "apply_from_db", lambda: seen.append(1))
    monkeypatch.setattr(engine, "run_job", lambda job_id: "completed")
    deploy_tasks.run_deployment.apply(args=[str(uuid.uuid4())])
    assert seen == [1]
    celery_mod._apply_ssh_limits()                                  # connected to worker_ready / worker_process_init
    assert seen == [1, 1]


# =========================================================================== K13
def test_k13_certbot_message_points_at_the_real_doc(db, net, pkis, operator):
    server = add_server(db, "cb-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="cb", certbot=True,
                            cert_path="/etc/letsencrypt/live/x/fullchain.pem", key_path="/etc/letsencrypt/live/x/privkey.pem")
    version = add_version(db, pkis["new"])
    plan = deployments.plan(db, operator, body(version, [inst]))
    [f] = [f for f in plan["findings"] if f["code"] == "CERTBOT_MANAGED"]
    assert "docs/deployment-engine.md" in f["message"] and "deploy hook" in f["message"] and "'certbot deploy hooks'" not in f["message"]
    from pathlib import Path

    text = (Path(__file__).resolve().parents[4] / "docs" / "deployment-engine.md").read_text()
    assert "## 15. Certbot policy" in text and "--deploy-hook" in text and "renewal-hooks/deploy" in text
