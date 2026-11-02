from __future__ import annotations

import os
import sys
import types
import uuid
from datetime import timedelta
from pathlib import Path

import asyncssh
import pytest
from sqlalchemy import select, text

from app.models import AuditEvent, Certificate, CertificateInstallation, EncryptedArtifact, Server
from app.models.base import utcnow
from app.models.certificate import make_identity_key
from app.services import dashboard
from tests.conftest import PASSWORD


def _key(comment="t") -> str:
    k = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    return k.export_private_key("openssh").decode()


def _enc_key(passphrase: str) -> str:
    k = asyncssh.generate_private_key("ssh-ed25519")
    return k.export_private_key("openssh", passphrase=passphrase).decode()


# ------------------------------------------------------------------------------- credentials
def test_credential_never_returns_secret_material(admin, db):
    pem = _key()
    assert "PRIVATE KEY" in pem
    r = admin.post("/api/v1/credentials", json={"name": "deploy-key", "private_key": pem})
    assert r.status_code == 201, r.text
    assert "PRIVATE KEY" not in r.text
    body = r.json()
    assert body["fingerprint"].startswith("SHA256:") and body["public_key"].startswith("ssh-ed25519 ")
    assert "private_key" not in body and "passphrase" not in body and body["server_count"] == 0
    listing = admin.get("/api/v1/credentials")
    assert "PRIVATE KEY" not in listing.text and listing.json()[0]["id"] == body["id"]
    # at rest: encrypted artifact, not plaintext
    art = db.scalars(select(EncryptedArtifact)).one()
    assert b"PRIVATE KEY" not in (Path(os.environ["CDP_ARTIFACT_DIR"]) / art.filename).read_bytes()
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "CREDENTIAL_CREATED")).one()
    assert "PRIVATE KEY" not in str(ev.after) and "PRIVATE KEY" not in str(ev.before)


def test_credential_validation_passphrase_and_multipart(admin):
    assert admin.post("/api/v1/credentials", json={"name": "bad", "private_key": "x" * 64}).status_code == 422
    enc = _enc_key("pw-1234")
    r = admin.post("/api/v1/credentials", json={"name": "enc", "private_key": enc})
    assert r.status_code == 422 and "PRIVATE KEY" not in r.text
    r = admin.post("/api/v1/credentials", json={"name": "enc", "private_key": enc, "passphrase": "pw-1234"})
    assert r.status_code == 201 and r.json()["has_passphrase"] is True
    r = admin.post("/api/v1/credentials", data={"name": "mp"},
                   files={"private_key_file": ("id_ed25519", _key().encode(), "text/plain")})
    assert r.status_code == 201, r.text
    assert admin.post("/api/v1/credentials", json={"name": "enc", "private_key": _key()}).status_code == 409


def test_credential_rotate_delete_and_in_use(admin, db):
    cid = admin.post("/api/v1/credentials", json={"name": "k1", "private_key": _key()}).json()
    r = admin.post(f"/api/v1/credentials/{cid['id']}/rotate", json={"private_key": _key()})
    assert r.status_code == 200 and r.json()["fingerprint"] != cid["fingerprint"] and r.json()["rotated_at"]
    assert "PRIVATE KEY" not in r.text
    s = admin.post("/api/v1/servers", json={"name": "web1", "hostname": "web1.example.com", "ssh_username": "cdp",
                                            "environment": "Test", "credential_id": cid["id"]})
    assert s.status_code == 201
    r = admin.delete(f"/api/v1/credentials/{cid['id']}")
    assert r.status_code == 409 and r.json()["error"]["code"] == "CREDENTIAL_IN_USE"
    admin.delete(f"/api/v1/servers/{s.json()['id']}")
    assert admin.delete(f"/api/v1/credentials/{cid['id']}").status_code == 204
    assert db.scalars(select(EncryptedArtifact).where(EncryptedArtifact.deleted_at.is_(None))).all() == []


def test_credential_create_requires_recent_reauth(admin, db):
    db.execute(text("UPDATE sessions SET reauth_at = now() - interval '1 hour'"))
    db.commit()
    r = admin.post("/api/v1/credentials", json={"name": "k", "private_key": _key()})
    assert r.status_code == 403 and r.json()["error"]["code"] == "REAUTH_REQUIRED"
    assert admin.post("/api/v1/auth/reauth", json={"password": PASSWORD}).status_code == 204
    assert admin.post("/api/v1/credentials", json={"name": "k", "private_key": _key()}).status_code == 201


# ------------------------------------------------------------------------------- settings
def test_settings_get_defaults(admin):
    s = admin.get("/api/v1/settings").json()
    assert set(s) == {"general", "notifications", "security", "ssh"}
    assert s["general"]["data"]["app_name"] == "Cert Deploy Pro" and s["general"]["version"] == 1
    assert s["notifications"]["data"]["thresholds"] == {"info": 60, "warning": 30, "high": 14, "critical": 7}
    assert s["ssh"]["data"]["deployment_concurrency"] == 3 and s["security"]["data"]["reauth_minutes"] == 10


def test_settings_optimistic_concurrency_and_audit(admin, db):
    admin.get("/api/v1/settings")
    r = admin.patch("/api/v1/settings/general", json={"version": 1, "data": {"backup_retention_days": 30}})
    assert r.status_code == 200 and r.json()["version"] == 2 and r.json()["data"]["backup_retention_days"] == 30
    assert r.json()["data"]["app_name"] == "Cert Deploy Pro"
    stale = admin.patch("/api/v1/settings/general", json={"version": 1, "data": {"backup_retention_days": 10}})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "SETTINGS_VERSION_CONFLICT"
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "SETTINGS_UPDATED")).one()
    assert ev.before["backup_retention_days"] == 90 and ev.after["backup_retention_days"] == 30
    assert ev.resource_id == "general" and ev.actor_name


def test_settings_validation(admin):
    admin.get("/api/v1/settings")
    r = admin.patch("/api/v1/settings/notifications",
                    json={"version": 1, "data": {"thresholds": {"critical": 90}}})
    assert r.status_code == 422
    assert admin.patch("/api/v1/settings/general", json={"version": 1, "data": {"bogus": 1}}).status_code == 422
    assert admin.patch("/api/v1/settings/nope", json={"version": 1, "data": {}}).status_code == 404


# ------------------------------------------------------------------------------- servers
def _server(**kw):
    base = {"name": "web-01", "hostname": "web-01.example.com", "ssh_username": "cdpdeploy", "environment": "Production"}
    base.update(kw)
    return base


@pytest.mark.parametrize("patch,field", [
    ({"hostname": "bad host!"}, "hostname"),
    ({"hostname": "-bad.example.com"}, "hostname"),
    ({"ssh_port": 0}, "ssh_port"),
    ({"ssh_port": 70000}, "ssh_port"),
    ({"address": "999.1.1.1"}, "address"),
    ({"ssh_username": "root; rm -rf /"}, "ssh_username"),
    ({"tags": ["ok", "bad tag"]}, "tags"),
    ({"privilege_mode": "su"}, "privilege_mode"),
])
def test_server_validation_rejects(admin, patch, field):
    r = admin.post("/api/v1/servers", json=_server(**patch))
    assert r.status_code == 422
    assert any(field in e["loc"] for e in r.json()["error"]["details"]["errors"])


def test_server_unknown_environment_and_duplicates(admin):
    r = admin.post("/api/v1/servers", json=_server(environment="Nowhere"))
    assert r.status_code == 422 and r.json()["error"]["code"] == "ENVIRONMENT_NOT_FOUND"
    ok = admin.post("/api/v1/servers", json=_server(address="10.0.0.5", tags=["web", "dmz"]))
    assert ok.status_code == 201 and ok.json()["ssh_port"] == 22 and ok.json()["connection_status"] == "unknown"
    assert admin.post("/api/v1/servers", json=_server(name="WEB-01")).status_code == 409
    sid = ok.json()["id"]
    assert admin.patch(f"/api/v1/servers/{sid}", json={"bastion_server_id": sid}).status_code == 422
    r = admin.patch(f"/api/v1/servers/{sid}", json={"ssh_port": 2222, "enabled": False})
    assert r.status_code == 200 and r.json()["ssh_port"] == 2222 and r.json()["enabled"] is False


def test_server_list_filters_pagination_and_delete(admin, db):
    for i in range(3):
        admin.post("/api/v1/servers", json=_server(name=f"s{i}", hostname=f"s{i}.example.com",
                                                   environment="Staging" if i else "Production"))
    r = admin.get("/api/v1/servers?page_size=2&page=1").json()
    assert r["total"] == 3 and len(r["items"]) == 2 and r["page"] == 1 and r["page_size"] == 2
    assert admin.get("/api/v1/servers?environment=Staging").json()["total"] == 2
    assert admin.get("/api/v1/servers?q=s0").json()["total"] == 1
    sid = r["items"][0]["id"]
    assert admin.delete(f"/api/v1/servers/{sid}").status_code == 204
    assert admin.get(f"/api/v1/servers/{sid}").status_code == 404
    assert {"SERVER_CREATED", "SERVER_DELETED"} <= {e.action for e in db.scalars(select(AuditEvent))}


def test_environment_in_use_cannot_be_deleted(admin):
    envs = admin.get("/api/v1/environments").json()
    prod = next(e for e in envs if e["name"] == "Production")
    assert prod["is_production"] and prod["requires_approval"]
    admin.post("/api/v1/servers", json=_server())
    r = admin.delete(f"/api/v1/environments/{prod['id']}")
    assert r.status_code == 409 and r.json()["error"]["code"] == "ENVIRONMENT_IN_USE"


def test_discover_returns_501_when_stream_missing(admin):
    sid = admin.post("/api/v1/servers", json=_server()).json()["id"]
    if "app.services.discovery" in sys.modules:
        pytest.skip("discovery service implemented")
    try:
        import app.services.discovery  # noqa: F401
        pytest.skip("discovery service implemented")
    except ImportError:
        pass
    r = admin.post(f"/api/v1/servers/{sid}/discover")
    assert r.status_code == 501 and r.json()["error"]["code"] == "NOT_IMPLEMENTED"


def _fake_ssh(monkeypatch, fp="SHA256:abc", key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE"):
    mod = types.ModuleType("app.integrations.ssh")

    class HostKeyInfo:
        def __init__(self, key_type, fingerprint_sha256, public_key_openssh):
            self.key_type, self.fingerprint_sha256, self.public_key_openssh = key_type, fingerprint_sha256, public_key_openssh

    state = {"fp": fp, "key": key}

    async def scan_host_key(host, port, timeout):
        return HostKeyInfo("ssh-ed25519", state["fp"], state["key"])

    mod.scan_host_key = scan_host_key
    monkeypatch.setitem(sys.modules, "app.integrations.ssh", mod)
    return state


def test_host_key_scan_enroll_and_replace(admin, monkeypatch, db):
    state = _fake_ssh(monkeypatch)
    sid = admin.post("/api/v1/servers", json=_server()).json()["id"]
    scan = admin.post(f"/api/v1/servers/{sid}/host-key/scan").json()
    assert scan == {"key_type": "ssh-ed25519", "fingerprint_sha256": "SHA256:abc", "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE"}
    bad = admin.post(f"/api/v1/servers/{sid}/host-key/enroll",
                     json={"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE", "fingerprint_sha256": "SHA256:other"})
    assert bad.status_code == 409 and bad.json()["error"]["code"] == "HOST_KEY_CHANGED_DURING_ENROLL"
    ok = admin.post(f"/api/v1/servers/{sid}/host-key/enroll",
                    json={"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5FAKE", "fingerprint_sha256": "SHA256:abc"})
    assert ok.status_code == 200 and ok.json()["host_key_fingerprint"] == "SHA256:abc"
    state.update(fp="SHA256:new", key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5NEWKEY")
    body = {"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5NEWKEY", "fingerprint_sha256": "SHA256:new"}
    r = admin.post(f"/api/v1/servers/{sid}/host-key/enroll", json=body)
    assert r.status_code == 409 and r.json()["error"]["code"] == "HOST_KEY_ALREADY_ENROLLED"
    assert admin.post(f"/api/v1/servers/{sid}/host-key/enroll", json={**body, "replace": True}).status_code == 200
    actions = [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.ts))]
    assert "HOST_KEY_ENROLLED" in actions and "HOST_KEY_REPLACED" in actions
    srv = db.scalars(select(Server)).one()
    assert srv.host_key_enrolled_by is not None


def test_host_key_enroll_is_admin_only(login):
    assert login("operator").post(f"/api/v1/servers/{uuid.uuid4()}/host-key/enroll",
                                  json={"public_key": "x" * 30, "fingerprint_sha256": "SHA256:" + "a" * 10}).status_code == 403


# ------------------------------------------------------------------------------- dashboard
def _cert(db, name, days, ctype="leaf"):
    fp = uuid.uuid4().hex + uuid.uuid4().hex
    c = Certificate(
        fingerprint_sha256=fp, common_name=name, subject=f"CN={name}", sans=[name], issuer="CN=Test CA",
        serial_number="01", public_key_algorithm="RSA", public_key_size=2048, public_key_sha256="a" * 64,
        signature_algorithm="sha256WithRSAEncryption", not_before=utcnow() - timedelta(days=100),
        not_after=utcnow() + timedelta(days=days), certificate_type=ctype, pem="PEM", status="valid")
    db.add(c)
    db.flush()
    return c


def _inst(db, cert, server, path):
    i = CertificateInstallation(
        certificate_id=cert.id, server_id=server.id, service_type="nginx", cert_path=path, vhost=None,
        identity_key=make_identity_key(server.id, "nginx", path, None), drift_status="in_sync",
        classification="managed")
    db.add(i)
    return i


def test_dashboard_counts_unique_certificates_not_installations(admin, db):
    admin.post("/api/v1/servers", json=_server(name="a", hostname="a.example.com"))
    admin.post("/api/v1/servers", json=_server(name="b", hostname="b.example.com"))
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    wildcard = _cert(db, "*.example.com", 5)          # expiring < 7d, installed 3 times
    other = _cert(db, "other.example.com", 20)        # expiring < 30d
    _cert(db, "old.example.com", -3)                  # expired, not installed anywhere
    _cert(db, "Test CA", 3000, ctype="root")          # CA certs are not deployable inventory
    _inst(db, wildcard, servers[0], "/etc/ssl/a.crt")
    _inst(db, wildcard, servers[0], "/etc/ssl/b.crt")
    _inst(db, wildcard, servers[1], "/etc/ssl/a.crt")
    gone = _inst(db, other, servers[1], "/etc/ssl/other.crt")
    gone.missing_since = utcnow()
    gone.drift_status = "missing"
    db.commit()

    s = admin.get("/api/v1/dashboard/summary").json()
    assert s["certificates_total"] == 3
    assert s["installations_total"] == 3  # missing installation excluded
    assert s["certificates_expiring_7"] == 1 and s["certificates_expiring_30"] == 2
    assert s["certificates_expired"] == 1
    assert s["servers_total"] == 2
    srv = admin.get("/api/v1/servers").json()["items"]
    assert {x["name"]: (x["installation_count"], x["certificate_count"]) for x in srv} == {"a": (2, 1), "b": (1, 1)}

    t = admin.get("/api/v1/dashboard/expiry-trend").json()
    assert {b["bucket"]: b["count"] for b in t["buckets"]} == {
        "Expired": 1, "< 7 days": 1, "7-30 days": 1, "30-90 days": 0, "> 90 days": 0}
    assert dashboard.summary(db)["certificates_total"] == 3


def test_dashboard_unreachable_and_recent_activity(admin, db):
    admin.post("/api/v1/servers", json=_server())
    db.execute(text("UPDATE servers SET connection_status='host_key_mismatch'"))
    db.commit()
    s = admin.get("/api/v1/dashboard/summary").json()
    assert s["servers_unreachable"] == 1
    assert any(a["action"] == "SERVER_CREATED" for a in s["recent_activity"])


# ------------------------------------------------------------------------------- audit listing
def test_audit_events_filters_and_pagination(admin, login):
    admin.post("/api/v1/environments", json={"name": "Lab"})
    admin.post("/api/v1/servers", json=_server())
    r = admin.get("/api/v1/audit-events?action=SERVER_CREATED").json()
    assert r["total"] == 1 and r["items"][0]["resource_type"] == "server"
    r = admin.get("/api/v1/audit-events?page_size=2").json()
    assert len(r["items"]) == 2 and r["total"] >= 3
    assert admin.get("/api/v1/audit-events?outcome=bogus").status_code == 422
    assert admin.get("/api/v1/audit-events?actor=admin&outcome=success").json()["total"] >= 2
    assert login("viewer").get("/api/v1/audit-events").status_code == 200
