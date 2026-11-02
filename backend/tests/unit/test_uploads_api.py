from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import select

from app.models import AuditEvent, Certificate, CertificateInstallation, CertificateVersion, Server
from app.models.base import utcnow
from app.models.certificate import make_identity_key
from tests.fixtures import pki as P


def _trust(admin, pem: bytes) -> None:
    cur = admin.get("/api/v1/settings").json()
    sec = cur["security"] if "security" in cur else cur["sections"]["security"]
    r = admin.patch("/api/v1/settings/security", json={"version": sec["version"], "data": {"trust_anchors_pem": pem.decode()}})
    assert r.status_code == 200, r.text


def _upload(admin, **files):
    form = {}
    data = {}
    for k, v in files.items():
        if k in ("password", "certificate_id"):
            data[k] = v
        else:
            form[k] = (f"{k}.pem", v, "application/octet-stream")
    return admin.post("/api/v1/certificate-versions", files=form, data=data)


def test_upload_with_key_validates_stores_encrypted_and_never_returns_key(admin, db):
    pki = P.make_pki(["www.example.com", "example.com"])
    _trust(admin, pki.root_pem)
    r = _upload(admin, certificate=pki.leaf.cert_pem, private_key=pki.leaf.key_pem, chain=pki.chain_pem)
    assert r.status_code == 201, r.text
    body = r.json()
    assert "PRIVATE KEY" not in r.text and "private_key" not in body
    assert body["validation_status"] in ("valid", "warnings"), body["findings"]
    assert body["has_private_key"] is True and body["reuses_existing_key"] is False
    assert body["leaf"]["common_name"] == "www.example.com" and len(body["chain"]) == 1
    assert body["leaf"]["fingerprint_sha256"] == body["fingerprint_sha256"]
    assert not any(f["severity"] == "blocking" for f in body["findings"]), body["findings"]
    got = admin.get(f"/api/v1/certificate-versions/{body['id']}")
    assert got.status_code == 200 and "PRIVATE KEY" not in got.text and "key_spki" not in got.text
    # at rest: encrypted artifacts only; audit has no PEM
    v = db.get(CertificateVersion, body["id"])
    art_dir = Path(os.environ["CDP_ARTIFACT_DIR"])
    assert v.key_artifact_id is not None
    for f in art_dir.glob("*.bin"):
        assert b"PRIVATE KEY" not in f.read_bytes() and b"BEGIN CERT" not in f.read_bytes()
    for ev in db.scalars(select(AuditEvent)):
        assert "BEGIN" not in str(ev.after) and "PRIVATE" not in str(ev.after)
    assert db.scalars(select(AuditEvent).where(AuditEvent.action == "CERTIFICATE_VERSION_UPLOADED")).one()


def test_upload_key_mismatch_untrusted_and_garbage(admin):
    pki = P.make_pki()
    other = P.make_pki()
    r = _upload(admin, certificate=pki.leaf.cert_pem, private_key=other.leaf.key_pem, chain=pki.chain_pem)
    assert r.status_code == 201
    codes = {f["code"]: f["severity"] for f in r.json()["findings"]}
    assert codes["KEY_MISMATCH"] == "blocking" and r.json()["validation_status"] == "invalid"
    assert "PRIVATE KEY" not in r.text
    bad = _upload(admin, certificate=b"definitely not a certificate")
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "UPLOAD_INVALID"
    assert _upload(admin).status_code == 422
    big = _upload(admin, certificate=b"A" * (300 * 1024))
    assert big.status_code == 413


def test_upload_pkcs12_and_encrypted_key(admin):
    pki = P.make_pki()
    _trust(admin, pki.root_pem)
    r = _upload(admin, pkcs12=P.to_pkcs12(pki.leaf, [pki.intermediate], b"s3cret"), password="s3cret")
    assert r.status_code == 201 and r.json()["has_private_key"] and "PRIVATE KEY" not in r.text
    r = _upload(admin, certificate=pki.leaf.cert_pem, private_key=pki.leaf.encrypted_key_pem(b"pw"), password="pw",
                chain=pki.chain_pem)
    assert r.status_code == 201 and any(f["code"] == "KEY_ENCRYPTED_INPUT" for f in r.json()["findings"])


def _seed_installation(db, cert_issued, names):
    from app.integrations.certificates import parse_pem_certificates
    from app.models import Credential  # noqa: F401

    info = parse_pem_certificates(cert_issued.cert_pem)[0]
    srv = Server(name="s1", hostname="s1.example.com", ssh_username="u", environment="Test")
    db.add(srv)
    db.flush()
    cert = Certificate(
        fingerprint_sha256=info.fingerprint_sha256, common_name=info.common_name, subject=info.subject,
        sans=list(info.sans), issuer=info.issuer, serial_number=info.serial_number,
        public_key_algorithm=info.public_key_algorithm, public_key_size=info.public_key_size,
        public_key_sha256=info.public_key_sha256, signature_algorithm=info.signature_algorithm,
        not_before=info.not_before, not_after=info.not_after, pem=info.pem)
    db.add(cert)
    db.flush()
    inst = CertificateInstallation(
        certificate_id=cert.id, server_id=srv.id, service_type="nginx", cert_path="/etc/x.pem", key_path="/etc/x.key",
        server_names=names, vhost="v", listen_port=443, identity_key=make_identity_key(srv.id, "nginx", "/etc/x.pem", "v"),
        classification="managed", drift_status="in_sync", last_observed_at=utcnow())
    db.add(inst)
    db.commit()
    return cert, inst


def test_key_reuse_checked_via_public_spki_and_hostnames(admin, db):
    pki = P.make_pki(["app.example.com"])
    _trust(admin, pki.root_pem)
    cert, inst = _seed_installation(db, pki.leaf, ["app.example.com"])
    # renewal that reuses the same key pair (same SPKI), no key uploaded
    renewed = P.make_leaf(pki.intermediate, ["app.example.com"], key=pki.leaf.key)
    r = _upload(admin, certificate=renewed.cert_pem, chain=pki.chain_pem, certificate_id=str(cert.id))
    assert r.status_code == 201, r.text
    j = r.json()
    codes = {f["code"]: f for f in j["findings"]}
    assert j["reuses_existing_key"] is True and j["has_private_key"] is False
    assert codes["KEY_REUSE_REQUIRED"]["severity"] == "info" and "KEY_REUSE_INCOMPATIBLE" not in codes
    assert j["validation_status"] in ("valid", "warnings")
    # renewal with a different key but no key uploaded -> blocking
    rekeyed = P.make_leaf(pki.intermediate, ["app.example.com"])
    r2 = _upload(admin, certificate=rekeyed.cert_pem, chain=pki.chain_pem, certificate_id=str(cert.id))
    codes2 = {f["code"]: f for f in r2.json()["findings"]}
    assert codes2["KEY_REUSE_INCOMPATIBLE"]["severity"] == "blocking" and r2.json()["validation_status"] == "invalid"
    # hostname coverage uses target installations' server_names
    wrong = P.make_leaf(pki.intermediate, ["other.example.com"], key=pki.leaf.key)
    r3 = _upload(admin, certificate=wrong.cert_pem, chain=pki.chain_pem, certificate_id=str(cert.id))
    assert any(f["code"] == "SAN_MISMATCH" for f in r3.json()["findings"])
    # revalidate against explicit installations recomputes findings
    vid = r.json()["id"]
    inst.server_names = ["not-covered.example.com"]
    db.commit()
    rv = admin.post(f"/api/v1/certificate-versions/{vid}/validate", json={"installation_ids": [str(inst.id)]})
    assert rv.status_code == 200, rv.text
    assert any(f["code"] == "SAN_MISMATCH" for f in rv.json()["findings"]) and rv.json()["validation_status"] == "invalid"
    assert "PRIVATE KEY" not in rv.text
    assert admin.post(f"/api/v1/certificate-versions/{vid}/validate",
                      json={"installation_ids": ["00000000-0000-0000-0000-000000000000"]}).status_code == 404


def test_upload_permissions(login):
    viewer = login("viewer")
    assert _upload(viewer, certificate=b"x").status_code == 403
    operator = login("operator")
    assert _upload(operator, certificate=b"x").status_code == 422        # allowed, but invalid input
