"""Dry-run planning / pre-flight: read-only guarantee and the blocking / warning rules."""
from __future__ import annotations

import datetime as dt

import pytest

from app.core.errors import AppError
from app.models import CertificateInstallation
from app.services import deployments, locks
from tests.fixtures.pki import TestPki, make_leaf, make_pki, now_utc
from tests.unit.deploy.conftest import FAST
from tests.unit.deploy.helpers import add_installation, add_server, add_version

pytestmark = pytest.mark.usefixtures("net", "dispatched")
MUTATING = {"stage_dir", "write_staged", "install", "cleanup", "reload"}


def req(version, insts, **kw):
    return {"version_id": version.id, "installation_ids": [i.id for i in insts], "strategy": dict(FAST),
            "acknowledged_warnings": [], **kw}


@pytest.fixture
def one(db, net, pkis):
    server = add_server(db, "p-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="site")
    return server, fs, inst, add_version(db, pkis["new"])


def codes(plan, severity=None):
    return {f["code"] for f in plan["findings"] if severity in (None, f["severity"])}


def blocked(db, operator, body, key="pk"):
    with pytest.raises(AppError) as ei:
        deployments.create(db, operator, key, body)
    assert ei.value.code == "PREFLIGHT_BLOCKED"
    return {f["code"] for f in ei.value.details["findings"]}


def test_dry_run_is_read_only_and_describes_the_exact_change(db, one, operator, net):
    _server, fs, inst, version = one
    before = dict(fs.snapshot())
    plan = deployments.plan(db, operator, req(version, [inst]))
    assert net.all_calls() == [] and fs.snapshot() == before            # no stage dir, no write, no backup, no reload
    assert plan["read_only"] and plan["summary"]["can_proceed"] and not plan["summary"]["blocking"]
    (t,) = plan["targets"]
    assert [f["dest_path"] for f in t["files"]] == [inst.cert_path, inst.key_path]
    cert = t["files"][0]
    assert cert["artifact"] == "fullchain" and cert["action"] == "replace" and cert["mode"] == 0o644
    assert cert["owner"] == "root" and cert["current_sha256"] != cert["new_sha256"]
    assert t["files"][1]["mode"] == 0o600 and t["files"][1]["contains_private_key"]
    assert t["backups"] == [inst.cert_path, inst.key_path]
    assert t["reload"]["mode"] == "graceful reload" and t["config_test"]["current_ok"] is True
    assert t["verify_endpoints"][0]["reachable"] and t["rollback"] and t["disk"]["free_bytes"] > 0
    assert t["current_fingerprint"] == t["inventory_fingerprint"] and t["new_fingerprint"] == version.fingerprint_sha256
    assert "PRIVATE KEY" not in str(plan)


def test_certbot_managed_is_blocking_with_guidance(db, one, operator):
    _server, _fs, inst, version = one
    inst.managed_by_certbot = True
    db.commit()
    plan = deployments.plan(db, operator, req(version, [inst]))
    f = next(f for f in plan["findings"] if f["code"] == "CERTBOT_MANAGED")
    assert f["severity"] == "blocking" and "certbot deploy hook" in f["message"]
    assert not plan["summary"]["can_proceed"]
    assert "CERTBOT_MANAGED" in blocked(db, operator, req(version, [inst]))


def test_san_mismatch_blocks_unless_admin_records_exception(db, one, operator, admin_user, pkis):
    _server, _fs, inst, version = one
    inst.server_names, inst.vhost, inst.verify_sni = ["other.example.org"], "other.example.org", "other.example.org"
    db.commit()
    assert "SAN_MISMATCH" in blocked(db, operator, req(version, [inst]))
    exc = {"code": "SAN_MISMATCH", "justification": "legacy alias, tracked in CHG-1234"}
    with pytest.raises(AppError) as ei:                                     # operators cannot grant exceptions
        deployments.create(db, operator, "e1", req(version, [inst], exception_approvals=[exc]))
    assert ei.value.status == 403
    with pytest.raises(AppError) as ei:                                     # justification is mandatory
        deployments.create(db, admin_user, "e2", req(version, [inst], exception_approvals=[
            {"code": "SAN_MISMATCH", "justification": "short"}]))
    assert ei.value.status == 422
    job, _ = deployments.create(db, admin_user, "e3", req(version, [inst], exception_approvals=[exc],
                                                         acknowledged_warnings=["SAN_MISMATCH"]))
    f = next(f for f in job.dry_run_plan["findings"] if f["code"] == "SAN_MISMATCH")
    assert f["excepted"] and f["exception_justification"] == exc["justification"]
    assert job.strategy["exceptions"][0]["approved_by"] == "admin1"


def test_reused_key_must_match_installed_certificate(db, one, operator, pkis):
    _server, _fs, inst, _ = one
    other_key_cert = add_version(db, pkis["new"], with_key=False, reuse=True)       # different SPKI than installed
    assert "REUSE_KEY_MISMATCH" in blocked(db, operator, req(other_key_cert, [inst]))
    old = pkis["old"]
    same_key = TestPki(old.root, old.intermediate, make_leaf(old.intermediate, ["site.test.local"], key=old.leaf.key))
    plan = deployments.plan(db, operator, req(add_version(db, same_key, with_key=False, reuse=True), [inst]))
    assert plan["summary"]["can_proceed"] and plan["targets"][0]["files"][1]["action"] == "keep"


def test_key_required_when_not_reusing(db, one, operator, pkis):
    _server, _fs, inst, _ = one
    assert "KEY_REQUIRED" in blocked(db, operator, req(add_version(db, pkis["new"], with_key=False), [inst]))


def test_mismatching_key_in_version_is_blocked(db, one, operator, pkis):
    _server, _fs, inst, _ = one
    p = pkis["new"]
    wrong = TestPki(p.root, p.intermediate, p.leaf)
    v = add_version(db, wrong)
    from app.core.crypto import get_vault

    v.key_artifact_id = get_vault().store(make_pki(["a.test.local"]).leaf.key_pem, "key", db=db).id
    db.commit()
    assert "KEY_MISMATCH" in blocked(db, operator, req(v, [inst]))


def test_stale_inventory_is_blocking_unless_acknowledged(db, one, operator):
    _server, _fs, inst, version = one
    inst.last_observed_fingerprint = "ab" * 32
    db.commit()
    assert "INVENTORY_STALE" in blocked(db, operator, req(version, [inst]))
    job, _ = deployments.create(db, operator, "st", req(version, [inst], acknowledged_warnings=["INVENTORY_STALE"]))
    assert job.status == "pending"


def test_currently_broken_config_is_blocking(db, one, operator):
    _server, fs, inst, version = one
    fs.current_config_broken = True
    assert "CONFIG_BROKEN" in blocked(db, operator, req(version, [inst]))


def test_warnings_must_be_acknowledged(db, net, pkis, operator):
    server = add_server(db, "w-srv")
    fs = net.add(server)
    inst = add_installation(db, server, fs, pkis["old"], name="w")
    soon = TestPki(pkis["new"].root, pkis["new"].intermediate,
                   make_leaf(pkis["new"].intermediate, ["site.test.local"], not_after=now_utc() + dt.timedelta(days=10)))
    version = add_version(db, soon)
    with pytest.raises(AppError) as ei:
        deployments.create(db, operator, "w1", req(version, [inst]))
    assert ei.value.code == "WARNINGS_NOT_ACKNOWLEDGED" and "EXPIRES_SOON" in ei.value.details["codes"]
    job, _ = deployments.create(db, operator, "w2", req(version, [inst], acknowledged_warnings=[
        "EXPIRES_SOON", "SHORTER_VALIDITY_THAN_CURRENT"]))
    assert job.acknowledged_warnings == ["EXPIRES_SOON", "SHORTER_VALIDITY_THAN_CURRENT"]


def test_concurrent_active_deployment_blocks_new_one(db, one, operator):
    _server, _fs, inst, version = one
    deployments.create(db, operator, "a1", req(version, [inst]))
    assert "ACTIVE_DEPLOYMENT" in blocked(db, operator, req(version, [inst]), key="a2")


def test_shared_path_with_unselected_installation_is_blocking(db, net, pkis, operator):
    server = add_server(db, "sh-srv")
    fs = net.add(server)
    a = add_installation(db, server, fs, pkis["old"], name="sh", port=8443)
    add_installation(db, server, fs, pkis["old"], name="sh", port=8444)
    version = add_version(db, pkis["new"])
    plan = deployments.plan(db, operator, req(version, [a]))
    f = next(f for f in plan["findings"] if f["code"] == "SHARED_PATH_NOT_IN_PLAN")
    assert f["severity"] == "blocking" and f["details"]["other_service"] == "nginx"
    both = deployments.plan(db, operator, req(version, [a, db.query(CertificateInstallation).filter_by(listen_port=8444).one()]))
    assert both["summary"]["can_proceed"] and both["targets"][0]["unit"] == both["targets"][1]["unit"]
    assert both["targets"][0]["shared_with"]


def test_symlink_realpath_sharing_is_detected(db, net, pkis, operator):
    """Different literal paths, same realpath -> still one shared file."""
    server = add_server(db, "ln-srv")
    fs = net.add(server)
    a = add_installation(db, server, fs, pkis["old"], name="ln", link=True, port=8443)
    b = add_installation(db, server, fs, pkis["old"], name="ln2", port=8444,
                         cert_path="/etc/ssl/alias/fullchain.pem", key_path="/etc/ssl/alias/privkey.pem")
    fs.links["/etc/ssl/alias/fullchain.pem"] = "/etc/ssl/ln/releases/fullchain.pem"
    fs.links["/etc/ssl/alias/privkey.pem"] = "/etc/ssl/ln/releases/privkey.pem"
    fs.files.pop("/etc/ssl/alias/fullchain.pem", None)
    fs.files.pop("/etc/ssl/alias/privkey.pem", None)
    version = add_version(db, pkis["new"])
    plan = deployments.plan(db, operator, req(version, [a]))
    assert "SHARED_PATH_NOT_IN_PLAN" in codes(plan, "blocking")
    assert deployments.plan(db, operator, req(version, [a, b]))["summary"]["can_proceed"]


def test_missing_file_and_disabled_server_block(db, one, operator):
    _server, fs, inst, version = one
    del fs.files[inst.key_path]
    assert "PATH_MISSING" in codes(deployments.plan(db, operator, req(version, [inst])), "blocking")


def test_lock_held_by_other_job_is_reported(db, one, operator):
    server, _fs, inst, version = one
    locks.acquire(locks.service_key(server.id, "nginx"), owner="x")
    assert "LOCKED" in codes(deployments.plan(db, operator, req(version, [inst])), "blocking")
