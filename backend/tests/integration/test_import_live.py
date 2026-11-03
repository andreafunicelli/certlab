"""CSV import against the local target: pinned host-key fingerprints are enrolled only when they match."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.integrations.ssh import host_key_info_from_openssh

HDR = "name,hostname,address,ssh_port,ssh_username,environment,credential,privilege_mode,bastion,tags,description,host_key_fingerprint"


@pytest.fixture
def fingerprint(host_pub) -> str:
    return host_key_info_from_openssh(host_pub).fingerprint_sha256


def _upload(admin, text, dry_run=False):
    return admin.post("/api/v1/servers/import", files={"file": ("s.csv", text.encode(), "text/csv")},
                      data={"dry_run": str(dry_run).lower()})


def test_import_with_correct_fingerprint_enrolls(admin, fingerprint):
    r = _upload(admin, f"{HDR}\nlive,127.0.0.1,,2222,cdpdeploy,Test,,,,,,{fingerprint}\n")
    assert r.status_code == 200, r.text
    row = r.json()["rows"][0]
    assert row["status"] == "created" and row["host_key"]["status"] == "enrolled"
    assert row["host_key"]["fingerprint_seen"] == fingerprint
    s = admin.get(f"/api/v1/servers/{row['server_id']}").json()
    assert s["host_key_fingerprint"] == fingerprint and s["host_key_enrolled_at"]


def test_import_with_wrong_fingerprint_is_not_enrolled(admin, fingerprint):
    wrong = "SHA256:" + ("A" * 43)
    assert wrong != fingerprint
    r = _upload(admin, f"{HDR}\nlive,127.0.0.1,,2222,cdpdeploy,Test,,,,,,{wrong}\nplain,127.0.0.1,,2222,cdpdeploy,Test,,,,,,\n")
    rows = {x["name"]: x for x in r.json()["rows"]}
    assert rows["live"]["status"] == "created"       # the server is created, the key is not trusted
    assert rows["live"]["host_key"] == {"status": "mismatch", "fingerprint_expected": wrong,
                                        "fingerprint_seen": fingerprint, "error": rows["live"]["host_key"]["error"]}
    assert rows["plain"]["host_key"]["status"] == "pending"
    for n in rows.values():
        s = admin.get(f"/api/v1/servers/{n['server_id']}").json()
        assert s["host_key_fingerprint"] is None and s["connection_status"] == "unknown"


def test_bulk_scan_and_enroll_live(admin, fingerprint, host_pub):
    sid = _upload(admin, f"{HDR}\nbulk,127.0.0.1,,2222,cdpdeploy,Test,,,,,,\n").json()["rows"][0]["server_id"]
    scan = admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [sid]}).json()["items"][0]
    assert scan["fingerprint_sha256"] == fingerprint and scan["endpoint"] == "127.0.0.1:2222"
    assert Path("/var/lib/cdp-test/ssh_host_ed25519_key.pub").read_text().split()[1] in scan["public_key"]
    enr = admin.post("/api/v1/servers/host-keys/enroll", json={"items": [
        {"server_id": sid, "public_key": scan["public_key"], "fingerprint_sha256": fingerprint}]}).json()["items"][0]
    assert enr["status"] == "enrolled"
    assert admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [sid]}).json()["items"][0]["matches_enrolled"] is True
