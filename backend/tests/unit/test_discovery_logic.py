"""Discovery classification + idempotent persistence, driven by a fake RemoteHost (no network)."""
from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.integrations.contracts import (
    ConfigCertRef,
    FileKind,
    HostProbe,
    RemoteError,
    RemoteErrorCode,
    RemoteFileStat,
    ServiceProbe,
    ServiceType,
)
from app.integrations.services.adapters import HaproxyAdapter, NginxAdapter
from app.models import Certificate, CertificateInstallation, DiscoveryFinding, DiscoveryJob, Server
from app.models.base import utcnow
from app.services import discovery, inventory
from tests.conftest import make_user
from tests.fixtures import pki as P

SSH = {"connect_timeout": 5, "discovery_roots": ["/etc/ssl"], "discovery_max_depth": 4, "discovery_max_files": 100,
       "discovery_exclude": ["/etc/ssl/certs", "*/node_modules/*"]}


def _stat(path, *, exists=True, readable=True, ftype="file", real=None, broken=False, target=None):
    return RemoteFileStat(path=path, exists=exists, file_type=ftype if exists else None, realpath=real or (path if exists else None),
                          symlink_target=target, broken_symlink=broken, mode=0o644, uid=0, gid=0, owner="root", group="root",
                          size=100, sha256="ab" * 32, selinux_context=None, readable=readable)


class FakeHost:
    def __init__(self, files=None, stats=None, found=None, read_errors=None, services=("nginx",)):
        self.files, self.stats, self.found = files or {}, stats or {}, found or []
        self.read_errors = read_errors or {}
        self.services = services
        self.read_paths: list[str] = []

    async def probe(self):
        sps = tuple(ServiceProbe(ServiceType(s), True, "1", f"/usr/sbin/{s}", True, "systemd") for s in self.services)
        return HostProbe("ubuntu", "24.04", "Ubuntu", "debian", True, "6", "cdp", "helper-sudo", "1.0", sps)

    async def stat(self, path):
        if path in self.stats:
            return self.stats[path]
        return _stat(path, exists=path in self.files)

    async def read_public_file(self, path, max_bytes=1_048_576):
        self.read_paths.append(path)
        if path in self.read_errors:
            raise self.read_errors[path]
        return self.files[path]

    async def find_cert_files(self, roots, max_depth, max_files, exclude):
        assert all(e.startswith("/") for e in exclude), "relative/glob excludes must not reach the SSH layer"
        return self.found


def adapter_with(refs, base=NginxAdapter):
    class A(base):
        async def discover(self, host):
            return refs
    return lambda _svc: A()


def ref(cert="/etc/ssl/a/fullchain.pem", key="/etc/ssl/a/privkey.pem", names=("a.example.com",), port=443, **kw):
    return ConfigCertRef(service=ServiceType.NGINX, config_file="/etc/nginx/x.conf", line=3, context="server{}",
                         server_names=tuple(names), listen_ports=(port,), cert_path=cert, key_path=key, chain_path=None,
                         is_combined_pem=False, **kw)


@pytest.fixture(scope="module")
def pki():
    return P.make_pki(["a.example.com"])


async def run(host, refs, probe_fn=None, base=NginxAdapter):
    return await discovery.collect(host, endpoint_host="10.0.0.5", ssh=SSH, probe_fn=probe_fn,
                                   adapter_for=adapter_with(refs, base))


async def test_managed_reference_and_default_verify_endpoint(pki):
    host = FakeHost(files={"/etc/ssl/a/fullchain.pem": pki.fullchain_pem, "/etc/ssl/a/privkey.pem": b"KEY"})
    col = await run(host, [ref()])
    [d] = col.items
    from app.integrations.certificates import parse_pem_certificates

    assert d.classification == "managed"
    assert d.cert.fingerprint_sha256 == parse_pem_certificates(pki.leaf.cert_pem)[0].fingerprint_sha256
    assert d.cert.common_name == "a.example.com" and len(d.chain) == 1
    assert (d.verify_host, d.verify_port, d.verify_sni) == ("10.0.0.5", 443, "a.example.com")
    assert "/etc/ssl/a/privkey.pem" not in host.read_paths                 # key files are stat-ed, never read
    assert d.file_metadata["key_exists"] is True and "PRIVATE" not in str(d.file_metadata)
    assert col.probe.os_family == "debian" and col.ok_services >= {"nginx", "filesystem"}


async def test_error_and_unreadable_classes(pki):
    good = pki.fullchain_pem
    host = FakeHost(
        files={"/p/ok.pem": good, "/p/ok.key": b"k", "/p/garbage.pem": b"hello world", "/p/denied.pem": good,
               "/p/nokey.pem": good, "/p/big.pem": good, "/p/p12.pem": b"\x30\x82\x01\x00" + b"x" * 40},
        stats={"/p/broken.pem": _stat("/p/broken.pem", exists=False, broken=True, target="../gone.pem"),
               "/p/unreadable.pem": _stat("/p/unreadable.pem", readable=False)},
        read_errors={"/p/denied.pem": RemoteError(RemoteErrorCode.PERMISSION_DENIED, "denied"),
                     "/p/big.pem": RemoteError(RemoteErrorCode.COMMAND_FAILED, "too large", details={"exit_status": 11})},
    )
    refs = [ref("/p/missing.pem", "/p/ok.key", ("m.example.com",)), ref("/p/broken.pem", "/p/ok.key", ("b.example.com",)),
            ref("/p/unreadable.pem", "/p/ok.key", ("u.example.com",)), ref("/p/denied.pem", "/p/ok.key", ("d.example.com",)),
            ref("/p/garbage.pem", "/p/ok.key", ("g.example.com",)), ref("/p/nokey.pem", "/p/nokey.key", ("k.example.com",)),
            ref("/p/big.pem", "/p/ok.key", ("l.example.com",)),
            ref(None, None, ("x.example.com",), unresolved_expression="$ssl_server_name"),
            ref("/p/ok.pem", "/p/ok.key", ("ok.example.com",))]
    col = await run(host, refs)
    cls = {d.server_names[0]: d for d in col.items}
    assert cls["m.example.com"].classification == "error" and "does not exist" in cls["m.example.com"].message
    assert cls["b.example.com"].classification == "error" and "broken symlink" in cls["b.example.com"].message
    assert cls["u.example.com"].classification == "unreadable"
    assert cls["d.example.com"].classification == "unreadable"
    assert cls["g.example.com"].classification == "error"
    assert cls["k.example.com"].classification == "requires_mapping" and cls["k.example.com"].confidence <= 0.6
    assert cls["l.example.com"].classification == "unsupported"
    assert cls["x.example.com"].classification == "unsupported" and cls["x.example.com"].cert is None
    assert cls["ok.example.com"].classification == "managed"
    assert all(d.cert is None for n, d in cls.items() if n != "ok.example.com" and n != "k.example.com")


async def test_certbot_detection_symlink_and_directory_refs(pki):
    live = "/etc/letsencrypt/live/a.example.com/fullchain.pem"
    host = FakeHost(
        files={live: pki.fullchain_pem, "/etc/letsencrypt/live/a.example.com/privkey.pem": b"k"},
        stats={live: _stat(live, ftype="symlink", real="/etc/letsencrypt/archive/a.example.com/fullchain1.pem",
                           target="../../archive/a.example.com/fullchain1.pem")})
    dir_ref = ConfigCertRef(ServiceType.NGINX, "/c", 1, "ctx", (), (443,), "/etc/ssl/dir/", None, None, False,
                            is_directory=True)
    col = await run(host, [ref(live, "/etc/letsencrypt/live/a.example.com/privkey.pem"), dir_ref])
    certbot = next(d for d in col.items if d.cert_path == live)
    assert certbot.managed_by_certbot and certbot.classification == "unmanaged" and "certbot" in certbot.message
    assert certbot.file_metadata["cert_stat"]["file_type"] == "symlink"
    assert next(d for d in col.items if d.cert_path == "/etc/ssl/dir/").classification == "requires_mapping"


async def test_combined_pem_uses_live_endpoint_and_never_reads_key(pki):
    path = "/etc/ssl/h/combined.pem"
    host = FakeHost(read_errors={path: RemoteError(RemoteErrorCode.PATH_NOT_ALLOWED, "PRIVATE_KEY_REFUSED",
                                                    details={"helper_error": "PRIVATE_KEY_REFUSED"})},
                    files={path: b""}, services=("haproxy",))
    from app.integrations.certificates import parse_pem_certificates
    from app.integrations.contracts import EndpointCertResult
    leaf = parse_pem_certificates(pki.leaf.cert_pem)[0]

    async def probe_fn(h, port, sni, timeout):
        assert (h, port) == ("10.0.0.5", 10443)
        return EndpointCertResult(h, port, sni, True, leaf, (), None, None, None, "TLSv1.3")

    hp = ConfigCertRef(ServiceType.HAPROXY, "/etc/haproxy/haproxy.cfg", 3, "frontend", (), (10443,), path, None, None, True)
    col = await run(host, [hp], probe_fn, HaproxyAdapter)
    d = col.items[0]
    assert d.classification == "managed" and d.file_metadata["fingerprint_source"] == "endpoint"
    assert d.cert.fingerprint_sha256 == leaf.fingerprint_sha256 and d.confidence <= 0.7

    async def down(h, port, sni, timeout):
        return EndpointCertResult(h, port, sni, False, None, (), None, None, "refused", None)
    col2 = await run(host, [hp], down, HaproxyAdapter)
    assert col2.items[0].classification == "unreadable" and col2.items[0].cert is None


async def test_filesystem_scan_dedupes_symlinks_and_skips_cas_and_referenced(pki):
    a, other = pki.leaf.cert_pem, P.make_pki(["scan.example.com"]).leaf.cert_pem
    real, link = "/etc/ssl/store/archive/c1.pem", "/etc/ssl/store/live/cert.pem"
    host = FakeHost(
        files={"/etc/ssl/a/fullchain.pem": pki.fullchain_pem, "/etc/ssl/a/privkey.pem": b"k", real: other, link: other,
               "/etc/ssl/ca.pem": pki.root_pem, "/etc/ssl/a/copy.pem": a},
        stats={link: _stat(link, ftype="symlink", real=real), real: _stat(real),
               "/etc/ssl/a/fullchain.pem": _stat("/etc/ssl/a/fullchain.pem")},
        found=[("/etc/ssl/a/fullchain.pem", FileKind.CERT_BUNDLE), (real, FileKind.CERTIFICATE), (link, FileKind.CERTIFICATE),
               ("/etc/ssl/ca.pem", FileKind.CERTIFICATE), ("/etc/ssl/x.p12", FileKind.PKCS12),
               ("/etc/ssl/a/copy.pem", FileKind.CERTIFICATE), ("/etc/ssl/h.pem", FileKind.COMBINED_PEM),
               ("/etc/ssl/a/privkey.pem", FileKind.PRIVATE_KEY), ("/etc/ssl/a/node_modules/x.pem", FileKind.CERTIFICATE)])
    col = await run(host, [ref()])
    fs = [d for d in col.items if d.service_type == "filesystem"]
    paths = sorted(d.cert_path for d in fs)
    assert paths == sorted([link, "/etc/ssl/a/copy.pem"]), paths        # real file of symlink deduped; CA & referenced skipped
    assert all(d.classification == "unmanaged" and d.source == "filesystem" for d in fs)
    assert {n.path for n in col.notes} >= {"/etc/ssl/x.p12", "/etc/ssl/h.pem"}
    assert "/etc/ssl/a/privkey.pem" not in host.read_paths and "/etc/ssl/h.pem" not in host.read_paths


# ------------------------------------------------------------------------------ persistence
def _server(db, name="srv1"):
    s = Server(name=name, hostname=f"{name}.example.com", ssh_username="u", environment="Test")
    db.add(s)
    db.commit()
    return s


async def test_persist_is_idempotent_and_marks_missing(db, pki):
    server = _server(db)
    host = FakeHost(files={"/etc/ssl/a/fullchain.pem": pki.fullchain_pem, "/etc/ssl/a/privkey.pem": b"k",
                           "/etc/ssl/b.pem": pki.fullchain_pem, "/etc/ssl/b.key": b"k"})
    refs = [ref(), ref("/etc/ssl/b.pem", "/etc/ssl/b.key", ("b.example.com",))]
    col = await run(host, refs)
    now = utcnow()
    r1 = discovery.persist_collection(db, server, col, now)
    db.commit()
    assert r1["stats"]["installations_created"] == 2 and r1["stats"]["certificates_created"] == 1   # same cert twice
    n_inst = db.query(CertificateInstallation).count()
    n_cert = db.query(Certificate).count()
    assert (n_inst, n_cert) == (2, 1)

    col2 = await run(host, refs)
    r2 = discovery.persist_collection(db, server, col2, utcnow())
    db.commit()
    assert r2["stats"]["installations_created"] == 0 and r2["stats"]["installations_updated"] == 2
    assert (db.query(CertificateInstallation).count(), db.query(Certificate).count()) == (n_inst, n_cert)

    # one reference disappears -> missing (not deleted); reappears -> back to in_sync
    col3 = await run(host, refs[:1])
    r3 = discovery.persist_collection(db, server, col3, utcnow())
    db.commit()
    assert r3["stats"]["marked_missing"] == 1
    gone = db.scalars(select(CertificateInstallation).where(CertificateInstallation.cert_path == "/etc/ssl/b.pem")).one()
    assert gone.drift_status == "missing" and gone.missing_since is not None
    col4 = await run(host, refs)
    discovery.persist_collection(db, server, col4, utcnow())
    db.commit()
    db.refresh(gone)
    assert gone.drift_status == "in_sync" and gone.missing_since is None

    # a failed service does NOT mark its installations missing
    col5 = await run(host, [])
    col5.ok_services.discard("nginx")
    r5 = discovery.persist_collection(db, server, col5, utcnow())
    assert r5["stats"]["marked_missing"] == 0


async def test_drift_detected_when_fingerprint_differs_from_last_deployment(db, pki, monkeypatch):
    server = _server(db)
    host = FakeHost(files={"/etc/ssl/a/fullchain.pem": pki.fullchain_pem, "/etc/ssl/a/privkey.pem": b"k"})
    col = await run(host, [ref()])
    discovery.persist_collection(db, server, col, utcnow())
    db.commit()
    monkeypatch.setattr(inventory, "expected_fingerprint", lambda _db, _inst: "f" * 64)
    r = discovery.persist_collection(db, server, await run(host, [ref()]), utcnow())
    inst = db.scalars(select(CertificateInstallation)).one()
    assert inst.drift_status == "drifted" and r["events"] and r["events"][0]["type"] == "drift"
    monkeypatch.setattr(inventory, "expected_fingerprint", lambda _db, _inst: inst.last_observed_fingerprint)
    discovery.persist_collection(db, server, await run(host, [ref()]), utcnow())
    assert inst.drift_status == "in_sync"


# ------------------------------------------------------------------------------ job execution
def _patch_connect(monkeypatch, host):
    from app.services import connectivity

    monkeypatch.setattr(connectivity, "build_target", lambda *_a, **_k: SimpleNamespace())
    monkeypatch.setattr(connectivity, "load_credential", lambda *_a, **_k: SimpleNamespace())

    @contextlib.asynccontextmanager
    async def factory(_t, _c):
        yield host
    return factory


def test_execute_job_end_to_end_with_fake_host(db, pki, monkeypatch):
    server = _server(db)
    host = FakeHost(files={"/etc/ssl/a/fullchain.pem": pki.fullchain_pem, "/etc/ssl/a/privkey.pem": b"k"})
    host.services = ("nginx",)
    monkeypatch.setattr("app.integrations.services.adapters.get_adapter", adapter_with([ref()]))
    admin = make_user(db, "root1", "admin")
    job = discovery.create_job(db, server, admin)
    assert discovery.execute_job(job.id, connect_factory=_patch_connect(monkeypatch, host)) == "completed"
    db.expire_all()
    assert db.get(DiscoveryJob, job.id).stats["installations_created"] == 1
    srv = db.get(Server, server.id)
    assert srv.last_discovery_status == "completed" and srv.os_family == "debian" and srv.connection_status == "connected"
    assert db.query(DiscoveryFinding).filter_by(job_id=job.id).count() >= 1
    # a finished job is never executed twice (redelivery safe)
    assert discovery.execute_job(job.id, connect_factory=_patch_connect(monkeypatch, host)) == "skipped"
    assert discovery.execute_job("00000000-0000-0000-0000-000000000000") == "missing"


def test_execute_job_reauthorizes_user_and_rechecks_server(db, monkeypatch):
    server = _server(db)
    op = make_user(db, "op1", "operator")
    job = discovery.create_job(db, server, op)
    # rights revoked between request and execution
    from app.models import Role, UserRole
    db.query(UserRole).filter_by(user_id=op.id).delete()
    db.commit()
    assert db.query(Role).count() > 0
    assert discovery.execute_job(job.id) == "failed"
    db.expire_all()
    j = db.get(DiscoveryJob, job.id)
    assert "AUTHORIZATION_REVOKED" in j.error
    # server disabled after queueing
    admin = make_user(db, "adm1", "admin")
    j2 = discovery.create_job(db, server, admin)
    server.enabled = False
    db.commit()
    assert discovery.execute_job(j2.id) == "failed"
    db.expire_all()
    assert "SERVER_DISABLED" in db.get(DiscoveryJob, j2.id).error
    with pytest.raises(Exception) as ei:
        discovery.create_job(db, server, admin)
    assert getattr(ei.value, "code", "") == "SERVER_DISABLED"


def test_one_active_job_per_server_and_stale_cleanup(db):
    from datetime import timedelta

    server = _server(db)
    admin = make_user(db, "adm2", "admin")
    j = discovery.create_job(db, server, admin)
    with pytest.raises(Exception) as ei:
        discovery.create_job(db, server, admin)
    assert ei.value.code == "DISCOVERY_ALREADY_RUNNING"
    j.created_at = utcnow() - timedelta(hours=2)
    db.commit()
    j2 = discovery.create_job(db, server, admin)              # stale one is expired, new one allowed
    db.refresh(j)
    assert j.status == "failed" and j2.status == "pending"


def test_schedule_due_uses_system_actor_and_interval(admin, db):
    from datetime import timedelta

    from tests.unit.test_domain_api import _key

    cred = admin.post("/api/v1/credentials", json={"name": "k", "private_key": _key()}).json()["id"]
    due, fresh, off, nokey = (_server(db, n) for n in ("due", "fresh", "off", "nokey"))
    for s in (due, fresh, off):
        s.host_public_key, s.credential_id = "ssh-ed25519 AAAA", cred
    fresh.last_discovery_at = utcnow() - timedelta(minutes=5)
    off.enabled = False
    db.commit()
    ids = discovery.schedule_due(db)
    assert len(ids) == 1
    job = db.get(DiscoveryJob, ids[0])
    assert job.server_id == due.id and job.requested_by is None            # system actor
    assert discovery.schedule_due(db) == []                                   # already pending; others not due
    assert nokey.last_discovery_at is None
