"""P1 regressions: (A) the initiating user is revoked while a deployment was interrupted mid-mutation - the host is
brought back to its previous state by the system, never moved forward; (B) a manual restore of a backup shared by
several services restores, reloads, verifies and records ALL of them as one unit."""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from app.core.db import SessionLocal
from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.models import AuditEvent, Backup, DeploymentJob, DeploymentTarget, User
from app.services import backups, deployments, locks
from app.services import deployment_engine as engine
from tests.conftest import PASSWORD
from tests.unit.deploy.helpers import (
    FakeFile,
    FakeHost,
    SimulatedCrash,
    add_installation,
    add_server,
    add_version,
)
from tests.unit.deploy.test_engine import (
    _expire_all_locks,
    _leave_locks_behind,
    body,
    make_job,
    reload_job,
    run_expect,
    targets,
)

pytestmark = pytest.mark.usefixtures("net", "dispatched")
API = "/api/v1"


@pytest.fixture
def one(db, net, pkis, operator):
    server = add_server(db, "rv-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="site", names=["site.test.local"])
    version = add_version(db, pkis["new"])
    return server, fs, inst, version


@pytest.fixture
def notified(monkeypatch):
    from app.services import notifications

    events: list[str] = []
    real = notifications.notify

    def spy(db, event, severity, payload, dedupe_key, **kw):
        events.append(event)
        return real(db, event, severity, payload, dedupe_key, **kw)

    monkeypatch.setattr(notifications, "notify", spy)
    return events


def _crash_after_install(monkeypatch, fs, job, nth):
    """Run the job until the worker 'dies' right after the ``nth`` install; its locks are left behind."""
    count = {"n": 0}

    def crash(dest, fs_):
        count["n"] += 1
        if count["n"] == nth:
            raise SimulatedCrash()

    fs.hooks["after_install"] = crash
    with monkeypatch.context() as m:
        _leave_locks_behind(m)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    _expire_all_locks()
    fs.hooks.clear()


def _disable(db, user):
    db.expire_all()
    db.get(User, user.id).enabled = False
    db.commit()


def _audit(db, action):
    db.expire_all()
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


# =========================================================================== P1-A
@pytest.mark.parametrize("revocation", ["disabled", "deleted"])
def test_revoked_user_after_crash_mid_installation_restores_previous_state(db, one, operator, monkeypatch, notified, revocation):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])
    _crash_after_install(monkeypatch, fs, job, 1)                    # first file replaced, second not yet
    assert fs.snapshot() != before
    if revocation == "disabled":
        _disable(db, operator)
    else:
        db.expire_all()
        db.get(DeploymentJob, job.id).initiated_by = None            # the account is gone
        db.commit()
    fs.calls.clear()
    run_expect(db, job, "rolled_back")                               # task redelivered
    j = reload_job(db, job)
    (t,) = targets(db, j)
    assert t.status == "rolled_back" and t.error_code == "AUTHZ_REVOKED"
    assert fs.snapshot() == before                                   # remote files equal the backup again
    assert fs.served[(_server.address, 8443)] == t.previous_fingerprint
    assert not any(c[0] == "reload" for c in fs.calls)               # never moved forward (no reload of new files)
    assert j.rollback_status == "rolled_back" and j.status == "rolled_back"
    assert "rollback.triggered" in notified and "rollback.failed" not in notified
    (ev,) = _audit(db, "DEPLOYMENT_AUTHZ_REVOKED_RECOVERY")
    assert ev.actor_name == engine.ACTOR and ev.after["outcome"] == "rolled_back"
    assert ev.after["classification"] == "mixed" and ev.after["revoked_user_id"] in (str(operator.id), "None")
    if revocation == "disabled":
        assert ev.after["revoked_username"] == operator.username
    assert next(s for s in t.steps if s["name"] == "reconcile")["detail"]["classification"] == "mixed"
    assert not db.scalars(select(Backup).where(Backup.restore_status == "failed")).all()


def test_revoked_user_with_all_files_new_is_restored_not_continued(db, one, operator, monkeypatch):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])
    _crash_after_install(monkeypatch, fs, job, 2)                    # a normal resume would now continue to verification
    _disable(db, operator)
    fs.calls.clear()
    run_expect(db, job, "rolled_back")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "rolled_back" and fs.snapshot() == before
    assert next(s for s in t.steps if s["name"] == "reconcile")["detail"]["classification"] == "all_new"
    assert fs.leaf_fp(inst.cert_path) != version.fingerprint_sha256
    assert not any(c[0] == "reload" for c in fs.calls)


def test_revoked_user_and_restore_failure_needs_manual_intervention(db, one, operator, monkeypatch, notified):
    _server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    _crash_after_install(monkeypatch, fs, job, 1)
    _disable(db, operator)

    def deny(dest, fs_):
        raise RemoteError(RemoteErrorCode.PERMISSION_DENIED, "cannot write destination")

    fs.hooks["before_install"] = deny
    run_expect(db, job, "manual_intervention_required")
    j = reload_job(db, job)
    (t,) = targets(db, j)
    assert t.status == "manual_intervention_required"
    assert "AUTHZ_REVOKED" in t.error_message and "ROLLBACK_RESTORE_FAILED" in t.error_code
    assert j.status == j.rollback_status == "manual_intervention_required"
    assert "rollback.triggered" in notified and "rollback.failed" in notified
    (ev,) = _audit(db, "DEPLOYMENT_AUTHZ_REVOKED_RECOVERY")
    assert ev.actor_name == engine.ACTOR and ev.after["outcome"] == "manual_intervention_required"


def test_revoked_user_restore_not_verified_needs_manual_intervention(db, one, operator, monkeypatch):
    server, fs, inst, version = one
    job = make_job(db, operator, version, [inst])
    _crash_after_install(monkeypatch, fs, job, 2)
    _disable(db, operator)
    fs.served[(server.address, 8443)] = "ff" * 32                    # the endpoint does not serve the previous certificate
    run_expect(db, job, "manual_intervention_required")
    (t,) = targets(db, reload_job(db, job))
    assert "ROLLBACK_SERVED_MISMATCH" in (t.error_code or "") + (t.error_message or "")


def test_revoked_user_when_nothing_had_mutated_is_cancelled(db, one, operator, monkeypatch, notified):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])

    def crash_before_first_install(dest, fs_):
        raise SimulatedCrash()

    fs.hooks["before_install"] = crash_before_first_install          # status 'activating', nothing replaced yet
    with monkeypatch.context() as m:
        _leave_locks_behind(m)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    _expire_all_locks()
    fs.hooks.clear()
    _disable(db, operator)
    run_expect(db, job, "cancelled")
    j = reload_job(db, job)
    (t,) = targets(db, j)
    assert t.status == "cancelled" and t.error_code == "AUTHZ" and fs.snapshot() == before
    assert j.status == "cancelled" and "rollback.triggered" not in notified
    assert not any(c[0] == "reload" for c in fs.calls)
    (ev,) = _audit(db, "DEPLOYMENT_AUTHZ_REVOKED_RECOVERY")
    assert ev.after["outcome"] == "cancelled" and ev.after["classification"] == "all_previous"


def test_revoked_user_before_any_mutation_phase_cancels_the_target(db, one, operator, monkeypatch):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    job = make_job(db, operator, version, [inst])

    def crash_staging(name, fs_):
        raise SimulatedCrash()

    fs.hooks["write_staged"] = crash_staging                         # worker dies while staging
    with monkeypatch.context() as m:
        _leave_locks_behind(m)
        with pytest.raises(SimulatedCrash):
            engine.run_job(job.id)
    _expire_all_locks()
    fs.hooks.clear()
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "staging"
    _disable(db, operator)
    fs.calls.clear()
    run_expect(db, job, "failed")
    (t,) = targets(db, reload_job(db, job))
    assert t.status == "cancelled" and t.error_code == "AUTHZ" and fs.snapshot() == before
    assert not fs.calls


def test_revoked_user_pending_targets_cancelled_while_started_unit_is_recovered(db, net, pkis, operator, monkeypatch):
    s1, s2 = add_server(db, "rv-a"), add_server(db, "rv-b")
    fs1, fs2 = net.add(s1), net.add(s2)
    i1 = add_installation(db, s1, fs1, pkis["old"], name="a", names=["site.test.local"])
    i2 = add_installation(db, s2, fs2, pkis["old"], name="b", names=["site.test.local"])
    version = add_version(db, pkis["new"])
    before1, before2 = dict(fs1.snapshot()), dict(fs2.snapshot())
    job = make_job(db, operator, version, [i1, i2])
    _crash_after_install(monkeypatch, fs1, job, 1)
    _disable(db, operator)
    got = engine.run_job(job.id)
    ts = {t.server_id: t for t in targets(db, reload_job(db, job))}
    assert ts[s1.id].status == "rolled_back" and ts[s2.id].status == "cancelled"
    assert fs1.snapshot() == before1 and fs2.snapshot() == before2 and got == "rolled_back"
    assert not fs2.calls


# =========================================================================== P1-B
@pytest.fixture
def shared(db, net, pkis, operator, monkeypatch):
    """nginx (:8443) and apache (:9443) on one server reference the SAME certificate and key files."""
    monkeypatch.setattr(engine, "RESTORE_VERIFY_DELAY", 0)
    server = add_server(db, "sh-srv")
    fs = net.add(server)
    nginx = add_installation(db, server, fs, pkis["old"], name="shared", names=["site.test.local"], port=8443)
    apache = add_installation(db, server, fs, pkis["old"], name="shared", names=["site.test.local"], port=9443,
                              service="apache")
    fs.files[nginx.cert_path] = FakeFile(pkis["old"].fullchain_pem, 0o644)       # apache helper wrote the leaf only
    fs.reload_effect()
    version = add_version(db, pkis["new"])
    return server, fs, nginx, apache, version


def _deploy_shared(db, shared, operator):
    server, fs, nginx, apache, version = shared
    before = dict(fs.snapshot())
    job, _ = deployments.create(db, operator, "shared-1", body(version, [nginx, apache]))
    run_expect(db, job, "completed")
    ts = targets(db, reload_job(db, job))
    assert len(ts) == 2 and ts[0].backup_id == ts[1].backup_id
    assert fs.served[(server.address, 8443)] == fs.served[(server.address, 9443)] == version.fingerprint_sha256
    backup = db.get(Backup, ts[0].backup_id)
    primary = next(t for t in ts if t.id == backup.deployment_target_id)
    return job, ts, backup, primary, before


def test_manual_restore_of_shared_backup_reloads_and_verifies_every_service(db, shared, operator, admin_user):
    server, fs, nginx, apache, _v = shared
    old_fp = shared[2].last_observed_fingerprint
    _job, ts, backup, primary, before = _deploy_shared(db, shared, operator)
    fs.calls.clear()
    result = engine.restore_backup(db, backup, admin_user, target=primary)
    assert result["ok"], result
    assert {c for c in fs.calls if c[0] == "reload"} == {("reload", "nginx"), ("reload", "apache")}
    assert fs.snapshot() == before
    assert fs.served[(server.address, 8443)] == fs.served[(server.address, 9443)] == old_fp
    assert sorted(s["service_type"] for s in result["served"]) == ["apache", "nginx"]
    assert sorted(result["services"]) == ["apache", "nginx"] and len(result["target_ids"]) == 2
    db.expire_all()
    assert all(db.get(DeploymentTarget, t.id).status == "rolled_back" and db.get(DeploymentTarget, t.id).current_step is None
               and db.get(DeploymentTarget, t.id).rollback_attempts == 1 for t in ts)
    for inst in (nginx, apache):
        i = db.get(type(inst), inst.id)
        assert i.last_observed_fingerprint == old_fp and i.drift_status == "in_sync"
    assert db.get(Backup, backup.id).restore_status == "restored"
    (ev,) = _audit(db, "BACKUP_RESTORED")
    assert len(ev.after["target_ids"]) == 2 and sorted(ev.after["services"]) == ["apache", "nginx"]


def test_manual_restore_failure_in_second_service_marks_both_manual_intervention(db, shared, operator, admin_user):
    server, fs, _n, _a, _v = shared
    _job, ts, backup, primary, _before = _deploy_shared(db, shared, operator)
    # apache keeps serving something else after the restore reload
    fs.hooks["after_reload"] = lambda fs_: fs_.served.__setitem__((server.address, 9443), "ff" * 32)
    result = engine.restore_backup(db, backup, admin_user, target=primary)
    assert result["ok"] is False and result["error_code"] == "RESTORE_SERVED_MISMATCH"
    assert "apache" in result["error"] and "nginx" not in result["error"] and result["failed_service"] == "apache"
    db.expire_all()
    for t in ts:
        t = db.get(DeploymentTarget, t.id)
        assert t.status == "manual_intervention_required" and t.error_code == "RESTORE_SERVED_MISMATCH"
        assert "apache" in t.error_message
    assert db.get(Backup, backup.id).restore_status == "failed"


def test_manual_restore_config_test_failure_names_the_service_and_marks_both(db, shared, operator, admin_user):
    _s, fs, _n, _a, _v = shared
    _job, ts, backup, primary, _before = _deploy_shared(db, shared, operator)
    fs.current_config_broken = True
    result = engine.restore_backup(db, backup, admin_user, target=primary)
    assert result["error_code"] == "RESTORE_CONFIG_TEST_FAILED" and "apache" in result["error"]       # alphabetical first
    db.expire_all()
    assert {db.get(DeploymentTarget, t.id).status for t in ts} == {"manual_intervention_required"}


def test_restore_locks_cover_every_affected_service_and_file(db, shared, operator, admin_user):
    server, fs, _n, _a, _v = shared
    _job, ts, backup, primary, _before = _deploy_shared(db, shared, operator)
    keys = engine.restore_lock_keys(db, backup, primary)
    assert locks.service_key(server.id, "nginx") in keys and locks.service_key(server.id, "apache") in keys
    assert locks.acquire(locks.service_key(server.id, "apache"), owner="other", job_id=None, ttl_seconds=60)
    snap = fs.snapshot()
    result = engine.restore_backup(db, backup, admin_user, target=primary)
    assert result["ok"] is False and result["error_code"] == "LOCK_HELD" and fs.snapshot() == snap
    db.expire_all()
    assert {db.get(DeploymentTarget, t.id).status for t in ts} == {"completed"}
    assert db.get(Backup, backup.id).restore_status == "none"


def test_manual_target_rollback_api_rolls_back_the_whole_shared_unit(login, db, shared, operator, monkeypatch):
    server, fs, _n, _a, _v = shared
    job, ts, _backup, primary, before = _deploy_shared(db, shared, operator)
    sent: list[tuple] = []
    monkeypatch.setattr(deployments, "dispatch_restore", lambda *a: sent.append(a))
    other = next(t for t in ts if t.id != primary.id)
    admin = login("admin")
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    r = admin.post(f"{API}/deployments/{job.id}/targets/{other.id}/rollback")        # roll back the NON-primary target
    assert r.status_code == 202, r.text
    out = r.json()
    assert sorted(out["unit_target_ids"]) == sorted(str(t.id) for t in ts) and "whole unit" in out["message"]
    assert sorted(out["services"]) == ["apache", "nginx"]
    db.expire_all()
    assert {db.get(DeploymentTarget, t.id).current_step for t in ts} == {"manual_rollback"}
    (args,) = sent
    result = engine.run_restore(args[0], args[1], args[2], previous_restore_status=args[3], permission=args[4])
    assert result["ok"], result
    db.expire_all()
    assert {db.get(DeploymentTarget, t.id).status for t in ts} == {"rolled_back"} and fs.snapshot() == before
    assert db.get(DeploymentJob, job.id).rollback_status == "rolled_back"
    assert fs.served[(server.address, 8443)] == fs.served[(server.address, 9443)]


def test_restore_after_failed_deployment_without_reload_does_not_reload(db, shared, operator, admin_user):
    server, fs, nginx, _a, _v = shared
    old_fp = nginx.last_observed_fingerprint
    _job, ts, backup, primary, _before = _deploy_shared(db, shared, operator)
    for t in ts:                                                     # as if the deployment died before the reload step
        t.status = "failed"
        t.meta = {k: v for k, v in (t.meta or {}).items() if k != "reload_started"}
    db.commit()
    for port in (8443, 9443):
        fs.served[(server.address, port)] = old_fp                   # the services never loaded the new files
    fs.calls.clear()
    result = engine.restore_backup(db, backup, admin_user, target=primary)
    assert result["ok"], result
    assert not any(c[0] == "reload" for c in fs.calls)


def test_untied_backup_resolves_every_installation_sharing_its_files(db, shared, pkis, admin_user):
    server, fs, nginx, apache, _v = shared
    old_fp = nginx.last_observed_fingerprint
    host = FakeHost(fs)
    backup = asyncio.run(backups.create_backup(db, host, server_id=server.id, installation_id=nginx.id, target_id=None,
                                               paths=[nginx.cert_path, nginx.key_path]))
    before = dict(fs.snapshot())
    fs.files[nginx.cert_path] = FakeFile(pkis["new"].fullchain_pem, 0o644)           # new files rolled out outside the engine
    fs.files[nginx.key_path] = FakeFile(pkis["new"].leaf.key_pem, 0o600)
    fs.reload_effect()
    scope = engine.resolve_restore_scope(db, backup)
    assert {i.id for i in scope.installs} == {nginx.id, apache.id}
    fs.calls.clear()
    result = engine.restore_backup(db, backup, admin_user)
    assert result["ok"], result
    assert {c for c in fs.calls if c[0] == "reload"} == {("reload", "nginx"), ("reload", "apache")}
    assert fs.snapshot() == before and fs.served[(server.address, 9443)] == fs.served[(server.address, 8443)] == old_fp
    db.expire_all()
    assert {db.get(type(nginx), i).drift_status for i in (nginx.id, apache.id)} == {"in_sync"}
    with SessionLocal() as s:
        assert s.get(Backup, backup.id).restore_status == "restored"
