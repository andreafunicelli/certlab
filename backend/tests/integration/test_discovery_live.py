"""Discovery against the disposable local target (sshd :2222, nginx :8443, apache :9443, haproxy :10443)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import AuditEvent, Certificate, CertificateInstallation, DiscoveryJob, Server
from app.workers.celery_app import celery_app

STATE = Path("/var/lib/cdp-test")
CERTS = Path("/etc/ssl/cdp-test")


def fp_of(path: Path) -> str:
    """sha256 fingerprint of the FIRST certificate in ``path`` via openssl (independent of our parser)."""
    out = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"],
                         check=True, capture_output=True, text=True).stdout
    return out.split("=", 1)[1].strip().replace(":", "").lower()


@pytest.fixture
def eager():
    prev = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = prev


@pytest.fixture
def server_id(admin, eager):
    cred = admin.post("/api/v1/credentials", json={"name": "local-target", "private_key": (STATE / "id_ed25519").read_text()})
    assert cred.status_code == 201, cred.text
    s = admin.post("/api/v1/servers", json={
        "name": "local-target", "hostname": "127.0.0.1", "ssh_port": 2222, "ssh_username": "cdpdeploy",
        "environment": "Test", "credential_id": cred.json()["id"]})
    assert s.status_code == 201, s.text
    sid = s.json()["id"]
    scan = admin.post(f"/api/v1/servers/{sid}/host-key/scan")
    assert scan.status_code == 200, scan.text
    enr = admin.post(f"/api/v1/servers/{sid}/host-key/enroll", json={
        "public_key": scan.json()["public_key"], "fingerprint_sha256": scan.json()["fingerprint_sha256"]})
    assert enr.status_code == 200, enr.text
    tc = admin.post(f"/api/v1/servers/{sid}/test-connection")
    assert tc.status_code == 200 and tc.json()["ok"], tc.text
    return sid


def run_discovery(admin, sid) -> dict:
    r = admin.post(f"/api/v1/servers/{sid}/discover")
    assert r.status_code == 202, r.text
    job = admin.get(f"/api/v1/discovery-jobs/{r.json()['id']}")
    assert job.status_code == 200
    return job.json()


def installs(admin, sid) -> list[dict]:
    r = admin.get(f"/api/v1/installations?server_id={sid}&page_size=200")
    assert r.status_code == 200
    return r.json()["items"]


def test_discovery_finds_nginx_apache_haproxy_and_is_idempotent(admin, server_id, db):
    job = run_discovery(admin, server_id)
    assert job["status"] == "completed", (job["error"], job["stats"])
    assert set(job["stats"]["services"]) >= {"nginx", "apache", "haproxy", "filesystem"}
    items = installs(admin, server_id)
    by_path = {(i["service_type"], i["cert_path"]): i for i in items}

    nginx = by_path[("nginx", str(CERTS / "nginx/fullchain.pem"))]
    assert nginx["certificate"]["fingerprint_sha256"] == fp_of(CERTS / "nginx/cert.pem")
    assert nginx["key_path"] == str(CERTS / "nginx/privkey.pem")
    assert nginx["classification"] == "managed" and nginx["managed_by_certbot"] is False
    assert nginx["server_names"] == ["nginx.test.local"] and nginx["listen_port"] == 8443
    assert (nginx["verify_host"], nginx["verify_port"], nginx["verify_sni"]) == ("127.0.0.1", 8443, "nginx.test.local")
    assert nginx["file_metadata"]["cert_stat"]["sha256"]

    link = by_path[("nginx", str(CERTS / "nginx-link/fullchain.pem"))]
    assert link["file_metadata"]["cert_stat"]["file_type"] == "symlink"
    assert link["classification"] == "managed"

    certbot = by_path[("nginx", "/etc/letsencrypt/live/certbot.test.local/fullchain.pem")]
    assert certbot["managed_by_certbot"] is True and certbot["classification"] == "unmanaged"
    assert certbot["certificate"]["fingerprint_sha256"] == fp_of(CERTS / "certbot-src/cert.pem")

    apache = by_path[("apache", str(CERTS / "apache/cert.pem"))]
    assert apache["certificate"]["fingerprint_sha256"] == fp_of(CERTS / "apache/cert.pem")
    assert apache["chain_path"] == str(CERTS / "apache/chain.pem") and apache["classification"] == "managed"

    haproxy = by_path[("haproxy", str(CERTS / "haproxy/combined.pem"))]
    assert haproxy["is_combined_pem"] is True and haproxy["classification"] == "managed"
    assert haproxy["certificate"]["fingerprint_sha256"] == fp_of(CERTS / "haproxy-src/cert.pem")
    assert haproxy["file_metadata"]["fingerprint_source"] == "endpoint"   # key-bearing file is never read

    # certificates found only via filesystem scan are unmanaged "filesystem" installations
    fs = [i for i in items if i["service_type"] == "filesystem"]
    assert fs and all(i["classification"] == "unmanaged" for i in fs)
    # CA certificates are not treated as server certificates
    assert not any(i["cert_path"].endswith("ca/ca.pem") for i in fs)

    # findings are persisted
    findings = job["findings"]
    assert any(f["classification"] == "managed" for f in findings)
    # no key material anywhere in API output / audit trail
    assert "PRIVATE KEY" not in str(job) and "PRIVATE KEY" not in str(items)
    for ev in db.scalars(select(AuditEvent)):
        assert "PRIVATE KEY" not in str(ev.after) + str(ev.before)

    srv = db.get(Server, server_id)
    assert srv.last_discovery_status == "completed" and srv.last_discovery_at is not None
    assert srv.os_family == "debian"

    # ---- second run: identical counts (no duplicates)
    n_inst, n_cert = len(items), db.query(Certificate).count()
    job2 = run_discovery(admin, server_id)
    assert job2["status"] == "completed"
    assert len(installs(admin, server_id)) == n_inst
    db.expire_all()
    assert db.query(Certificate).count() == n_cert
    assert job2["stats"]["installations_created"] == 0 and job2["stats"]["marked_missing"] == 0
    assert db.query(DiscoveryJob).count() == 2

    # ---- jobs listing
    lst = admin.get(f"/api/v1/servers/{server_id}/discovery-jobs").json()
    assert lst["total"] == 2
    assert admin.get(f"/api/v1/discovery-jobs?server_id={server_id}&status=completed").json()["total"] == 2


def test_endpoint_verify_and_inventory_api(admin, server_id):
    run_discovery(admin, server_id)
    items = installs(admin, server_id)
    nginx = next(i for i in items if i["service_type"] == "nginx" and i["cert_path"].endswith("nginx/fullchain.pem"))
    r = admin.post(f"/api/v1/installations/{nginx['id']}/verify")
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["ok"] and v["matches_file"] is True and v["hostname_matches"] is True
    assert v["served_fingerprint"] == fp_of(CERTS / "nginx/cert.pem")
    assert v["endpoint"] == {"host": "127.0.0.1", "port": 8443, "sni": "nginx.test.local"}
    assert admin.get(f"/api/v1/installations/{nginx['id']}").json()["last_verification"]["matches_file"] is True

    haproxy = next(i for i in items if i["service_type"] == "haproxy")
    assert admin.post(f"/api/v1/installations/{haproxy['id']}/verify").json()["matches_file"] is True

    cid = nginx["certificate_id"]
    cv = admin.post(f"/api/v1/certificates/{cid}/verify")
    assert cv.status_code == 200 and cv.json()["summary"]["matching"] >= 1

    detail = admin.get(f"/api/v1/certificates/{cid}").json()
    assert detail["installation_count"] >= 1 and detail["installations"][0]["server_name"] == "local-target"
    assert detail["installations"][0]["environment"] == "Test" and "drift" in detail and detail["pem"].startswith("-----BEGIN CERT")
    assert "PRIVATE KEY" not in str(detail)

    cn = detail["common_name"]
    listing = admin.get(f"/api/v1/certificates?q={cn}").json()
    assert listing["total"] >= 1 and listing["items"][0]["installation_count"] >= 1
    assert admin.get(f"/api/v1/certificates?server_id={server_id}&status=valid").json()["total"] >= 1
    assert admin.get("/api/v1/certificates?environment=Test&expiring_within=10").json()["total"] == 0
    assert admin.get("/api/v1/certificates?sort=bogus").status_code == 422

    # operator mapping: change SNI + classification
    p = admin.patch(f"/api/v1/installations/{nginx['id']}", json={"verify_sni": "other.test.local", "owner": "web-team",
                                                                  "tags": ["edge"], "classification": "requires_mapping"})
    assert p.status_code == 200, p.text
    assert p.json()["verify_sni"] == "other.test.local" and p.json()["owner"] == "web-team"
    run_discovery(admin, server_id)             # operator choices survive re-discovery
    again = admin.get(f"/api/v1/installations/{nginx['id']}").json()
    assert again["verify_sni"] == "other.test.local" and again["classification"] == "requires_mapping"
    assert again["owner"] == "web-team"


def test_removed_certificate_is_marked_missing_and_scan_finds_extras(admin, server_id, scratch):
    src = CERTS / "nginx/cert.pem"
    extra = scratch / "extra.pem"
    extra.write_bytes(src.read_bytes())
    extra.chmod(0o644)
    run_discovery(admin, server_id)
    fs = [i for i in installs(admin, server_id) if i["service_type"] == "filesystem" and i["cert_path"] == str(extra)]
    assert len(fs) == 1 and fs[0]["classification"] == "unmanaged" and fs[0]["drift_status"] == "in_sync"
    extra.unlink()
    job = run_discovery(admin, server_id)
    assert job["stats"]["marked_missing"] >= 1
    gone = admin.get(f"/api/v1/installations/{fs[0]['id']}").json()
    assert gone["drift_status"] == "missing" and gone["missing_since"]


def test_second_concurrent_discovery_is_refused(admin, server_id, db):
    celery_app.conf.task_always_eager = False
    try:
        r1 = admin.post(f"/api/v1/servers/{server_id}/discover")        # queued, no worker: stays pending
        assert r1.status_code == 202 and r1.json()["status"] == "pending"
        r2 = admin.post(f"/api/v1/servers/{server_id}/discover")
        assert r2.status_code == 409 and r2.json()["error"]["code"] == "DISCOVERY_ALREADY_RUNNING"
        bulk = admin.post("/api/v1/discovery-jobs/bulk", json={"server_ids": [server_id]})
        assert bulk.status_code == 202 and bulk.json()["errors"][0]["code"] == "DISCOVERY_ALREADY_RUNNING"
    finally:
        # drop the queued message so a real worker never sees this job
        import redis

        from app.core.config import get_settings
        redis.Redis.from_url(get_settings().redis_url).delete("celery")


def test_host_key_mismatch_fails_job_and_flags_server(admin, server_id, db):
    srv = db.get(Server, server_id)
    srv.host_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    db.commit()
    r = admin.post(f"/api/v1/servers/{server_id}/discover")
    assert r.status_code == 202
    job = admin.get(f"/api/v1/discovery-jobs/{r.json()['id']}").json()
    assert job["status"] == "failed" and "HOST_KEY" in job["error"]
    db.expire_all()
    assert db.get(Server, server_id).connection_status in ("host_key_mismatch", "host_key_unknown", "error")
    assert db.get(Server, server_id).last_discovery_status == "failed"
    assert db.scalars(select(AuditEvent).where(AuditEvent.action == "DISCOVERY_FAILED")).first() is not None
    assert db.query(CertificateInstallation).count() == 0
