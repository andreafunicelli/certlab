"""CSV inventory import, bulk host-key scan/enroll, and host-key reset on endpoint change."""
from __future__ import annotations

import sys
import types
import uuid

import pytest
from sqlalchemy import select

from app.models import AuditEvent, Server
from app.services import server_import as si

HDR = "name,hostname,address,ssh_port,ssh_username,environment,credential,privilege_mode,bastion,tags,description,host_key_fingerprint"
FP_A = "SHA256:" + "A" * 43
FP_B = "SHA256:" + "B" * 43


def upload(admin, text: str | bytes, *, dry_run=True, on_conflict="error", filename="servers.csv"):
    data = text.encode() if isinstance(text, str) else text
    return admin.post("/api/v1/servers/import", files={"file": (filename, data, "text/csv")},
                      data={"dry_run": str(dry_run).lower(), "on_conflict": on_conflict})


def csv_of(*rows: str, header: str = HDR) -> str:
    return "\n".join([header, *rows]) + "\n"


class FakeSSH:
    """Replaces app.integrations.ssh: per-host fingerprints; hosts listed in ``down`` are unreachable."""

    def __init__(self, monkeypatch, keys: dict[str, tuple[str, str]], down=()):
        self.keys, self.down, self.calls = keys, set(down), []
        mod = types.ModuleType("app.integrations.ssh")

        class HostKeyInfo:
            def __init__(self, key_type, fp, pub):
                self.key_type, self.fingerprint_sha256, self.public_key_openssh = key_type, fp, pub

        async def scan_host_key(host, port, timeout):
            self.calls.append((host, port))
            if host in self.down:
                raise ConnectionRefusedError()
            fp, pub = self.keys[host]
            return HostKeyInfo("ssh-ed25519", fp, pub)

        mod.scan_host_key = scan_host_key
        monkeypatch.setitem(sys.modules, "app.integrations.ssh", mod)


def pub(tag: str) -> str:
    return f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5{tag.ljust(30, 'X')}"


# --------------------------------------------------------------------------------------------- template
def test_template_download_and_roundtrip(admin):
    r = admin.get("/api/v1/servers/import/template")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="cert-deploy-pro-servers-template.csv"' in r.headers["content-disposition"]
    lines = r.text.splitlines()
    assert lines[0].startswith("# ") and HDR in lines
    # The template as downloaded imports nothing: the examples are comments, so a forgotten example can't be imported.
    res = upload(admin, r.text).json()
    assert res["total"] == 0 and res["invalid"] == 0 and res["delimiter"] == ","
    # Uncommenting the examples gives rows that parse; the placeholders must still be edited before import.
    uncommented = "\n".join(ln[2:] if ln.startswith(("# bastion-01,", "# app-01,")) else ln
                             for ln in lines)
    res = upload(admin, uncommented).json()
    assert res["total"] == 2
    row2 = res["rows"][1]            # placeholder fingerprint / credential are rejected, bastion forward reference is ok
    assert {e["field"] for e in row2["errors"]} == {"credential", "host_key_fingerprint"}
    assert res["rows"][0]["status"] == "valid"


def test_import_requires_write_permission(login):
    op = login("operator")
    assert op.get("/api/v1/servers/import/template").status_code == 403
    assert upload(op, csv_of()).status_code == 403


# --------------------------------------------------------------------------------------------- parsing
def test_bom_semicolon_comments_blank_lines_and_tags(admin):
    text = "﻿# comment\n\n" + HDR.replace(",", ";") + "\n# another\n" \
        "web-01;web-01.example.com;;2222;deploy;Production;;;;a|b;web server;\n\nweb-02;10.0.0.2;;;deploy;staging;;none;;x;y;\n"
    res = upload(admin, text).json()
    assert res["delimiter"] == ";" and res["total"] == 2 and res["valid"] == 2, res
    assert [r["row"] for r in res["rows"]] == [5, 7]          # 1-based physical line numbers
    assert upload(admin, text, dry_run=False).status_code == 200
    s = admin.get("/api/v1/servers?q=web-01").json()["items"][0]
    assert s["ssh_port"] == 2222 and s["tags"] == ["a", "b"]
    w2 = admin.get("/api/v1/servers?q=web-02").json()["items"][0]
    assert w2["environment"] == "Staging" and w2["privilege_mode"] == "none" and w2["ssh_port"] == 22


def test_header_case_spaces_and_column_order(admin):
    text = " Hostname , NAME ,SSH_Username, environment\nh.example.com,srv,u,Test\n"
    res = upload(admin, text).json()
    assert res["valid"] == 1 and res["rows"][0]["name"] == "srv"


@pytest.mark.parametrize("text,code", [
    ("name,hostname\nx,y\n", "IMPORT_INVALID_FILE"),                                   # missing required columns
    (csv_of(header=HDR + ",bogus"), "IMPORT_INVALID_FILE"),                            # unknown column
    ("# only comments\n", "IMPORT_INVALID_FILE"),
    (b"\xff\xfe\x00bad", "IMPORT_INVALID_FILE"),                                       # not UTF-8
])
def test_invalid_files(admin, text, code):
    r = upload(admin, text)
    assert r.status_code == 422 and r.json()["error"]["code"] == code


def test_size_and_row_limits(admin):
    r = upload(admin, b"x" * (si.MAX_BYTES + 10))
    assert r.status_code == 413 and r.json()["error"]["code"] == "IMPORT_FILE_TOO_LARGE"
    rows = [f"s{i},h{i}.example.com,,,u,Test,,,,,," for i in range(1001)]
    r = upload(admin, csv_of(*rows))
    assert r.status_code == 422 and r.json()["error"]["code"] == "IMPORT_TOO_MANY_ROWS"
    assert upload(admin, csv_of(*rows[:1000])).json()["valid"] == 1000


def test_row_validation_errors(admin):
    cred = admin.post("/api/v1/credentials", json={"name": "k1", "private_key": _key()}).json()
    admin.post("/api/v1/servers", json={"name": "existing", "hostname": "e.example.com", "ssh_username": "u",
                                         "environment": "Test"})
    res = upload(admin, csv_of(
        ",,,,,,,,,,desc,",                                        # all required missing
        "bad port,h.example.com,,70000,u,Test,,,,,,",
        "p2,h.example.com,,abc,u,Test,,,,,,",
        "p3,bad host!,999.1.1.1,,root; rm,Nowhere,nocred,su,,bad tag,,",
        "ok1,h1.example.com,,,u,Test,k1,,,,,",
        "OK1,h2.example.com,,,u,Test,,,,,,",                      # duplicate in file (case-insensitive)
        "existing,h3.example.com,,,u,Test,,,,,,",                 # duplicate in DB
        "fp,h4.example.com,,,u,Test,,,,,,SHA256:short",
    )).json()
    by = {r["row"]: r for r in res["rows"]}
    assert res["total"] == 8
    errs = {r["row"]: {e["field"] for e in r["errors"]} for r in res["rows"]}
    assert {"name", "hostname", "ssh_username", "environment"} <= errs[2]
    assert "ssh_port" in errs[3] and "ssh_port" in errs[4]
    assert {"hostname", "address", "ssh_username", "environment", "credential", "privilege_mode", "tags"} <= errs[5]
    assert by[6]["status"] == "valid" and errs[7] == {"name"} and errs[8] == {"name"}
    assert "host_key_fingerprint" in errs[9]
    assert cred["name"] == "k1"
    assert res["invalid"] == 7 and res["valid"] == 1


def _key() -> str:
    from tests.unit.test_domain_api import _key as k
    return k()


def test_on_conflict_skip(admin):
    admin.post("/api/v1/servers", json={"name": "existing", "hostname": "e.example.com", "ssh_username": "u",
                                         "environment": "Test"})
    text = csv_of("existing,e2.example.com,,,u,Test,,,,,,", "fresh,f.example.com,,,u,Test,,,,,,")
    res = upload(admin, text, on_conflict="skip").json()
    assert (res["skipped"], res["valid"]) == (1, 1) and res["rows"][0]["status"] == "skipped"
    res = upload(admin, text, dry_run=False, on_conflict="skip").json()
    assert res["created"] == 1 and res["rows"][1]["status"] == "created" and res["rows"][1]["server_id"]
    assert admin.get("/api/v1/servers").json()["total"] == 2


def test_bastion_existing_forward_reference_and_cycles(admin):
    base = admin.post("/api/v1/servers", json={"name": "jump", "hostname": "j.example.com", "ssh_username": "u",
                                                "environment": "Test"}).json()
    text = csv_of(
        "a,a.example.com,,,u,Test,,,b,,,",           # forward reference to a row below
        "b,b.example.com,,,u,Test,,,,,,",
        "c,c.example.com,,,u,Test,,,jump,,,",        # existing server
    )
    res = upload(admin, text, dry_run=False).json()
    assert res["created"] == 3
    items = {s["name"]: s for s in admin.get("/api/v1/servers").json()["items"]}
    assert items["a"]["bastion_server_id"] == items["b"]["id"] and items["c"]["bastion_server_id"] == base["id"]
    assert items["b"]["bastion_server_id"] is None

    bad = upload(admin, csv_of(
        "x,x.example.com,,,u,Test,,,y,,,", "y,y.example.com,,,u,Test,,,x,,,",
        "z,z.example.com,,,u,Test,,,z,,,", "w,w.example.com,,,u,Test,,,nope,,,",
        "v,v.example.com,,,u,Test,,,c,,,")).json()                               # c already has a bastion
    msgs = {r["row"]: r["errors"][0]["message"] for r in bad["rows"] if r["errors"]}
    assert "cycle" in msgs[2] and "cycle" in msgs[3] and "own bastion" in msgs[4]
    assert "neither an existing server" in msgs[5] and "chained" in msgs[6]


def test_dry_run_writes_nothing_and_commit_is_all_or_nothing(admin, db, monkeypatch):
    FakeSSH(monkeypatch, {})
    good = "g1,g1.example.com,,,u,Test,,,,,,"
    res = upload(admin, csv_of(good, "g2,g2.example.com,,,u,Test,,,,,,"), dry_run=True).json()
    assert res["dry_run"] is True and res["valid"] == 2 and res["created"] == 0
    assert db.scalars(select(Server)).all() == []
    assert db.query(AuditEvent).filter(AuditEvent.action.in_(("SERVER_CREATED", "SERVERS_IMPORTED"))).count() == 0
    # one bad row -> 422 with the full report, nothing created
    r = upload(admin, csv_of(good, "g2,bad host!,,,u,Test,,,,,,"), dry_run=False)
    assert r.status_code == 422 and r.json()["error"]["code"] == "IMPORT_HAS_ERRORS"
    body = r.json()["error"]["details"]
    assert body["invalid"] == 1 and body["valid"] == 1 and body["rows"][1]["errors"][0]["field"] == "hostname"
    db.expire_all()
    assert db.scalars(select(Server)).all() == []
    # success: servers + audit trail
    ok = upload(admin, csv_of(good, "g2,g2.example.com,,,u,Test,,,,,,"), dry_run=False, filename="../etc/pass wd.csv")
    assert ok.status_code == 200 and ok.json()["created"] == 2
    db.expire_all()
    assert len(db.scalars(select(Server)).all()) == 2
    acts = [e.action for e in db.scalars(select(AuditEvent))]
    assert acts.count("SERVER_CREATED") == 2 and acts.count("SERVERS_IMPORTED") == 1
    imp = db.scalars(select(AuditEvent).where(AuditEvent.action == "SERVERS_IMPORTED")).one()
    assert imp.after["filename"] == "pass wd.csv" and imp.after["created"] == 2


def test_db_failure_rolls_back_everything(admin, db, monkeypatch):
    from app.services import audit

    def boom(*a, **k):
        if k.get("action") == "SERVERS_IMPORTED":
            raise RuntimeError("audit down")
        return orig(*a, **k)
    orig = audit.record
    monkeypatch.setattr(audit, "record", boom)
    c = admin.c
    c.raise_server_exceptions = False
    r = upload(admin, csv_of("r1,r1.example.com,,,u,Test,,,,,,", "r2,r2.example.com,,,u,Test,,,,,,"), dry_run=False)
    assert r.status_code == 500
    monkeypatch.setattr(audit, "record", orig)
    db.expire_all()
    assert db.scalars(select(Server)).all() == []


# --------------------------------------------------------------------------------------------- host keys
def test_fingerprint_pin_enroll_mismatch_unreachable_pending(admin, db, monkeypatch):
    fake = FakeSSH(monkeypatch, {"ok.example.com": (FP_A, pub("A")), "bad.example.com": (FP_B, pub("B")),
                                 "nopin.example.com": (FP_B, pub("B"))}, down={"down.example.com"})
    text = csv_of(
        f"ok,ok.example.com,,,u,Test,,,,,,{FP_A}", f"bad,bad.example.com,,,u,Test,,,,,,{FP_A}",
        f"down,down.example.com,,,u,Test,,,,,,{FP_A}", "nopin,nopin.example.com,,,u,Test,,,,,,")
    dry = upload(admin, text).json()
    assert [r["host_key"]["status"] for r in dry["rows"]] == ["pending", "pending", "pending", "not_provided"]
    assert fake.calls == []                                      # dry run never touches the network
    res = upload(admin, text, dry_run=False).json()
    hk = {r["name"]: r["host_key"] for r in res["rows"]}
    assert hk["ok"]["status"] == "enrolled" and hk["ok"]["fingerprint_seen"] == FP_A
    assert hk["bad"]["status"] == "mismatch" and hk["bad"]["fingerprint_seen"] == FP_B
    assert hk["bad"]["fingerprint_expected"] == FP_A
    assert hk["down"]["status"] == "unreachable" and hk["down"]["error"]
    assert hk["nopin"]["status"] == "pending"
    assert all(h != "nopin.example.com" for h, _ in fake.calls)  # no fingerprint -> never scanned
    servers = {s.name: s for s in db.scalars(select(Server))}
    assert servers["ok"].host_key_fingerprint == FP_A and servers["ok"].host_key_enrolled_by is not None
    for n in ("bad", "down", "nopin"):
        assert servers[n].host_public_key is None
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "HOST_KEY_ENROLLED")).all()
    assert len(ev) == 1 and ev[0].after["detail"] == "pinned via CSV import" and ev[0].actor_name


def test_bulk_scan_and_enroll(admin, db, monkeypatch):
    fake = FakeSSH(monkeypatch, {"a.example.com": (FP_A, pub("A")), "b.example.com": (FP_B, pub("B"))},
                   down={"c.example.com"})
    ids = {}
    for n in "abc":
        ids[n] = admin.post("/api/v1/servers", json={"name": n, "hostname": f"{n}.example.com", "ssh_username": "u",
                                                      "environment": "Test"}).json()["id"]
    ghost = str(uuid.uuid4())
    scan = admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [*ids.values(), ghost]}).json()["items"]
    by = {i["server_id"]: i for i in scan}
    a = by[ids["a"]]
    assert a["fingerprint_sha256"] == FP_A and a["endpoint"] == "a.example.com:22" and a["matches_enrolled"] is None
    assert by[ids["c"]]["error_code"] == "CONNECTION_REFUSED" or by[ids["c"]]["error_code"] == "UNKNOWN"
    assert by[ghost]["error_code"] == "SERVER_NOT_FOUND"

    enr = admin.post("/api/v1/servers/host-keys/enroll", json={"items": [
        {"server_id": ids["a"], "public_key": pub("A"), "fingerprint_sha256": FP_A},
        {"server_id": ids["b"], "public_key": pub("B"), "fingerprint_sha256": FP_A},      # fingerprint != fresh scan
        {"server_id": ids["c"], "public_key": pub("A"), "fingerprint_sha256": FP_A},      # unreachable
        {"server_id": ghost, "public_key": pub("A"), "fingerprint_sha256": FP_A}]}).json()["items"]
    st = {i["server_id"]: i for i in enr}
    assert st[ids["a"]]["status"] == "enrolled"
    assert st[ids["b"]]["error_code"] == "HOST_KEY_CHANGED_DURING_ENROLL"
    assert st[ids["c"]]["error_code"] == "HOST_KEY_SCAN_FAILED" and st[ghost]["error_code"] == "SERVER_NOT_FOUND"
    # rescan reports match; replacing a different key needs replace=true
    again = admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [ids["a"]]}).json()["items"][0]
    assert again["matches_enrolled"] is True and again["enrolled_fingerprint"] == FP_A
    fake.keys["a.example.com"] = (FP_B, pub("B"))
    body = {"items": [{"server_id": ids["a"], "public_key": pub("B"), "fingerprint_sha256": FP_B}]}
    assert admin.post("/api/v1/servers/host-keys/enroll", json=body).json()["items"][0]["error_code"] == "HOST_KEY_ALREADY_ENROLLED"
    assert admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [ids["a"]]}).json()["items"][0]["matches_enrolled"] is False
    assert admin.post("/api/v1/servers/host-keys/enroll", json={**body, "replace": True}).json()["items"][0]["status"] == "enrolled"
    assert "HOST_KEY_REPLACED" in {e.action for e in db.scalars(select(AuditEvent))}


def test_bulk_limits_and_permissions(admin, login):
    assert admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": [str(uuid.uuid4())] * 201}).status_code == 422
    assert admin.post("/api/v1/servers/host-keys/scan", json={"server_ids": []}).status_code == 422
    op = login("operator")
    assert op.post("/api/v1/servers/host-keys/scan", json={"server_ids": [str(uuid.uuid4())]}).status_code == 403
    assert op.post("/api/v1/servers/host-keys/enroll", json={"items": [
        {"server_id": str(uuid.uuid4()), "public_key": "x" * 30, "fingerprint_sha256": FP_A}]}).status_code == 403


# --------------------------------------------------------------------------------------------- PATCH reset
def test_endpoint_change_clears_host_key(admin, db, monkeypatch):
    FakeSSH(monkeypatch, {"h.example.com": (FP_A, pub("A")), "10.9.9.9": (FP_A, pub("A"))})
    sid = admin.post("/api/v1/servers", json={"name": "p", "hostname": "h.example.com", "ssh_username": "u",
                                               "environment": "Test"}).json()["id"]
    assert admin.post(f"/api/v1/servers/{sid}/host-key/enroll",
                      json={"public_key": pub("A"), "fingerprint_sha256": FP_A}).json()["host_key_fingerprint"] == FP_A
    # no endpoint change -> key kept
    r = admin.patch(f"/api/v1/servers/{sid}", json={"description": "x", "hostname": "h.example.com", "ssh_port": 22})
    assert r.json()["host_key_reset"] is False and r.json()["host_key_fingerprint"] == FP_A
    assert admin.get(f"/api/v1/servers/{sid}").json()["host_key_reset"] is False
    for patch in ({"ssh_port": 2200}, {"address": "10.9.9.9"}, {"hostname": "other.example.com"}):
        if patch != {"ssh_port": 2200}:
            admin.post(f"/api/v1/servers/{sid}/host-key/enroll",
                       json={"public_key": pub("A"), "fingerprint_sha256": FP_A, "replace": True})
        r = admin.patch(f"/api/v1/servers/{sid}", json=patch)
        j = r.json()
        assert r.status_code == 200 and j["host_key_reset"] is True, patch
        assert j["host_key_fingerprint"] is None and j["host_key_type"] is None and j["host_key_enrolled_at"] is None
        assert j["connection_status"] == "host_key_unknown"
        s = db.get(Server, uuid.UUID(sid))
        db.refresh(s)
        assert s.host_public_key is None and s.host_key_enrolled_by is None
        assert admin.get(f"/api/v1/servers/{sid}").json()["host_key_reset"] is False
        if patch == {"ssh_port": 2200}:
            admin.patch(f"/api/v1/servers/{sid}", json={"ssh_port": 22})
            admin.post(f"/api/v1/servers/{sid}/host-key/enroll",
                       json={"public_key": pub("A"), "fingerprint_sha256": FP_A})
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "HOST_KEY_CLEARED")).all()
    assert len(ev) >= 3 and ev[0].before["fingerprint"] == FP_A and ev[0].before["endpoint"] == "h.example.com:22"
    assert ev[0].after["endpoint"] == "h.example.com:2200" and "endpoint" in ev[0].after["reason"]
