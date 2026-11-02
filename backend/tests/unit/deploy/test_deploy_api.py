"""HTTP-level behaviour: idempotency, approval rules, RBAC, list/get, SSE snapshot, backups API."""
from __future__ import annotations

import io
import tarfile

import pytest

from app.services import deployment_engine as engine
from app.services import settings as settings_service
from tests.conftest import PASSWORD
from tests.unit.deploy.conftest import FAST
from tests.unit.deploy.helpers import add_installation, add_server, add_version

pytestmark = pytest.mark.usefixtures("net", "dispatched")
API = "/api/v1"


@pytest.fixture
def world(db, net, pkis):
    server = add_server(db, "api-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="api")
    return server, fs, inst, add_version(db, pkis["new"])


def _forget_reauth(db):
    from sqlalchemy import text

    db.execute(text("UPDATE sessions SET reauth_at = NULL"))
    db.commit()


def payload(version, inst, **kw):
    return {"version_id": str(version.id), "installation_ids": [str(inst.id)], "strategy": dict(FAST), **kw}


def test_plan_and_create_require_proper_roles(login, world):
    _server, _fs, inst, version = world
    viewer, operator = login("viewer"), login("operator")
    assert viewer.post(f"{API}/deployments/plan", json=payload(version, inst)).status_code == 403
    r = operator.post(f"{API}/deployments/plan", json=payload(version, inst))
    assert r.status_code == 200 and r.json()["summary"]["can_proceed"]
    assert viewer.post(f"{API}/deployments", json=payload(version, inst),
                       headers={"Idempotency-Key": "abc12345"}).status_code == 403
    assert viewer.get(f"{API}/deployments").status_code == 200                 # read-only role may list


def test_idempotency_key_semantics(login, world, dispatched):
    _server, _fs, inst, version = world
    op = login("operator")
    assert op.post(f"{API}/deployments", json=payload(version, inst)).json()["error"]["code"] == "IDEMPOTENCY_KEY_REQUIRED"
    h = {"Idempotency-Key": "key-0001"}
    r1 = op.post(f"{API}/deployments", json=payload(version, inst), headers=h)
    assert r1.status_code == 201 and r1.json()["status"] == "pending" and r1.json()["idempotent_replay"] is False
    r2 = op.post(f"{API}/deployments", json=payload(version, inst), headers=h)
    assert r2.status_code == 201 and r2.json()["id"] == r1.json()["id"] and r2.json()["idempotent_replay"] is True
    changed = payload(version, inst, acknowledged_warnings=["X"])
    r3 = op.post(f"{API}/deployments", json=changed, headers=h)
    assert r3.status_code == 409 and r3.json()["error"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"
    assert len(dispatched) == 1                                               # the replay did not enqueue a second run


def test_idempotency_keys_are_scoped_per_user(login, world):
    _server, _fs, inst, version = world
    a, b = login("operator", "opa"), login("operator", "opb")
    ja = a.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "shared-key"})
    assert ja.status_code == 201
    # b's request with the same key is NOT a replay of a's job (and is blocked by the active deployment of a)
    jb = b.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "shared-key"})
    assert jb.status_code == 409 and jb.json()["error"]["code"] == "PREFLIGHT_BLOCKED"


def test_blocking_findings_refuse_creation(login, world, db):
    _server, _fs, inst, version = world
    inst.managed_by_certbot = True
    db.commit()
    r = login("operator").post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "cb-0001"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "PREFLIGHT_BLOCKED"
    assert {f["code"] for f in r.json()["error"]["details"]["findings"]} == {"CERTBOT_MANAGED"}


def test_production_requires_approval_by_a_second_admin_with_recent_reauth(login, db, net, pkis, dispatched):
    server = add_server(db, "prod-srv", env="Production")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="prod")
    version = add_version(db, pkis["new"])
    admin1, admin2 = login("admin", "adm1"), login("admin", "adm2")
    r = admin1.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "prod-0001"})
    assert r.status_code == 201 and r.json()["status"] == "awaiting_approval" and r.json()["approval_required"]
    job_id = r.json()["id"]
    assert dispatched == []                                                   # nothing runs before approval
    _forget_reauth(db)                                                         # login itself counts as a re-auth
    assert admin2.post(f"{API}/deployments/{job_id}/approve").json()["error"]["code"] == "REAUTH_REQUIRED"
    # the initiator cannot approve their own deployment
    assert admin1.post(f"{API}/auth/reauth", json={"password": PASSWORD}).status_code == 204
    r = admin1.post(f"{API}/deployments/{job_id}/approve")
    assert r.status_code == 403 and r.json()["error"]["code"] == "SELF_APPROVAL_FORBIDDEN"
    # operators cannot approve at all
    op = login("operator")
    assert op.post(f"{API}/deployments/{job_id}/approve").status_code == 403
    assert admin2.post(f"{API}/auth/reauth", json={"password": PASSWORD}).status_code == 204
    r = admin2.post(f"{API}/deployments/{job_id}/approve")
    assert r.status_code == 200 and r.json()["status"] == "pending" and r.json()["approved_by"]
    assert dispatched == [__import__("uuid").UUID(job_id)]
    assert admin2.post(f"{API}/deployments/{job_id}/approve").status_code == 409        # not awaiting approval any more


def test_self_approval_allowed_when_security_setting_enabled(login, db, net, pkis, dispatched):
    server = add_server(db, "solo-srv", env="Production")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="solo")
    version = add_version(db, pkis["new"])
    admin = login("admin", "solo-admin")
    row = admin.get(f"{API}/settings").json()
    sec = next(s for s in (row.values() if isinstance(row, dict) else row) if isinstance(s, dict) and s.get("section") == "security") \
        if not isinstance(row.get("security"), dict) else row["security"]
    r = admin.patch(f"{API}/settings/security", json={"version": sec["version"], "data": {"allow_self_approval": True}})
    assert r.status_code == 200, r.text
    assert settings_service.get_section_data(db, "security")["allow_self_approval"] is True
    job_id = admin.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "solo-0001"}).json()["id"]
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    assert admin.post(f"{API}/deployments/{job_id}/approve").json()["status"] == "pending"


def test_list_get_events_cancel_retry_and_backups_api(login, db, world, operator, monkeypatch):
    server, fs, inst, version = world
    op, admin = login("operator"), login("admin")
    created = op.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "life-0001"}).json()
    job_id = created["id"]
    import uuid
    assert engine.run_job(uuid.UUID(job_id)) == "completed"

    page = op.get(f"{API}/deployments", params={"status": "completed", "server_id": str(server.id)}).json()
    assert page["total"] == 1 and page["items"][0]["id"] == job_id and page["items"][0]["target_counts"] == {"completed": 1}
    assert op.get(f"{API}/deployments", params={"status": "failed"}).json()["total"] == 0
    assert op.get(f"{API}/servers/{server.id}/deployments").json()["total"] == 1
    detail = op.get(f"{API}/deployments/{job_id}").json()
    (t,) = detail["targets"]
    assert t["status"] == "completed" and [s["name"] for s in t["steps"]][:3] == ["connect", "lock", "recheck"]
    assert t["server_name"] == "api-srv" and t["verification"]["mode"] == "live" and t["backup_id"]
    assert "PRIVATE KEY" not in str(detail)
    assert op.get(f"{API}/deployments/{uuid.uuid4()}").status_code == 404

    # SSE: snapshot first (works for reconnects), then end for a finished job
    r = op.get(f"{API}/deployments/{job_id}/events")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert r.text.startswith("event: snapshot\ndata: ") and '"targets"' in r.text and "event: end" in r.text

    assert op.post(f"{API}/deployments/{job_id}/cancel").status_code == 409            # already finished
    assert op.post(f"{API}/deployments/{job_id}/retry").json()["error"]["code"] == "NOTHING_TO_RETRY"

    # backups API
    b = op.get(f"{API}/backups", params={"deployment_id": job_id}).json()
    assert b["total"] == 1
    bid = b["items"][0]["id"]
    assert op.get(f"{API}/backups", params={"server_id": str(server.id)}).json()["total"] == 1
    man = op.get(f"{API}/backups/{bid}").json()
    assert man["verified"] and len(man["files"]) == 2 and "PRIVATE KEY" not in str(man)
    _forget_reauth(db)
    assert admin.get(f"{API}/backups/{bid}/download").json()["error"]["code"] == "REAUTH_REQUIRED"
    assert op.get(f"{API}/backups/{bid}/download").status_code == 403
    admin.post(f"{API}/auth/reauth", json={"password": PASSWORD})
    dl = admin.get(f"{API}/backups/{bid}/download")
    assert dl.status_code == 200 and dl.headers["content-type"] == "application/gzip"
    with tarfile.open(fileobj=io.BytesIO(dl.content), mode="r:gz") as tar:
        assert any(n.endswith("privkey.pem") for n in tar.getnames())
    # manual rollback of the completed target, then restore of the backup again is idempotent
    old_fp = detail["targets"][0]["previous_fingerprint"]
    sent = []
    from app.services import deployments as deployments_service

    monkeypatch.setattr(deployments_service, "dispatch_restore", lambda *a: sent.append(a))
    r = admin.post(f"{API}/deployments/{job_id}/targets/{t['id']}/rollback")
    assert r.status_code == 202 and r.json()["accepted"] and r.json()["restore_status"] == "in_progress"
    engine.run_restore(sent[0][0], sent[0][1], sent[0][2], previous_restore_status=sent[0][3], permission=sent[0][4])
    db.expire_all()
    r = admin.get(f"{API}/deployments/{job_id}")
    assert r.json()["targets"][0]["status"] == "rolled_back"
    assert fs.leaf_fp(inst.cert_path) == old_fp
    r = admin.post(f"{API}/backups/{bid}/restore")
    assert r.status_code == 202 and r.json()["backup"]["restore_status"] == "in_progress"
    engine.run_restore(sent[1][0], sent[1][1], sent[1][2], previous_restore_status=sent[1][3], permission=sent[1][4])
    assert admin.get(f"{API}/backups/{bid}").json()["restore_status"] == "restored"
    # operators cannot roll back / restore
    assert op.post(f"{API}/backups/{bid}/restore").status_code == 403


def test_cancel_awaiting_approval_and_retry_failed_targets(login, db, net, pkis, dispatched):
    server = add_server(db, "cr-srv", env="Production")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="cr")
    version = add_version(db, pkis["new"])
    op = login("operator")
    jid = op.post(f"{API}/deployments", json=payload(version, inst), headers={"Idempotency-Key": "cr-00001"}).json()["id"]
    r = op.post(f"{API}/deployments/{jid}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelled" and r.json()["targets"][0]["status"] == "cancelled"

    # failed job -> retry creates a NEW job for the failed targets only
    server2 = add_server(db, "cr2-srv")
    fs2 = net.add(server2)
    inst2 = add_installation(db, server2, fs2, pkis["old"], name="cr2")
    other = add_installation(db, server2, fs2, pkis["old"], name="cr3", port=8444)
    once = {"done": False}

    def corrupt_once(dest, f):
        if dest == inst2.key_path and not once["done"]:
            once["done"] = True
            f.files[f.resolve(dest)].content = b"junk"
    fs2.hooks["after_install"] = corrupt_once
    body = {"version_id": str(version.id), "installation_ids": [str(inst2.id), str(other.id)],
            "strategy": {**FAST, "mode": "batch", "concurrency": 1, "failure_threshold": 0}}
    j2 = op.post(f"{API}/deployments", json=body, headers={"Idempotency-Key": "cr-00002"}).json()["id"]
    import uuid
    status = engine.run_job(uuid.UUID(j2))
    assert status in ("partially_failed", "rolled_back")
    fs2.hooks.clear()
    new = op.post(f"{API}/deployments/{j2}/retry")
    assert new.status_code == 201 and new.json()["retry_of"] == j2 and new.json()["target_total"] == 1
    assert new.json()["id"] != j2 and new.json()["targets"][0]["installation_id"] == str(inst2.id)
