from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import os
from pathlib import Path

import asyncssh
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.integrations.contracts import FileKind, RemoteError, RemoteErrorCode, ServiceType
from app.integrations.ssh import (
    SSHCredential,
    SSHTarget,
    connect,
    scan_host_key,
    set_host_concurrency_limit,
    test_connection,
)
from app.integrations.tls.probe import probe_endpoint
from tests.integration.conftest import CERTS, SSH_PORT, STATE

pytestmark = pytest.mark.integration


def _fp_hex(pem_path) -> str:
    cert = x509.load_pem_x509_certificate(Path(pem_path).read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex()


# ----------------------------------------------------------------------------- host keys / connection test
async def test_scan_host_key_returns_real_key(host_pub):
    info = await scan_host_key("127.0.0.1", SSH_PORT, 5)
    proc = await asyncio.create_subprocess_exec("ssh-keygen", "-lf", str(STATE / "ssh_host_ed25519_key.pub"),
                                                stdout=asyncio.subprocess.PIPE)
    expected = (await proc.communicate())[0].decode().split()[1]
    assert info.fingerprint_sha256 == expected and info.fingerprint_sha256.startswith("SHA256:")
    assert info.key_type == "ssh-ed25519" and info.public_key_openssh == host_pub


async def test_connection_ok(target, credential):
    rep = await test_connection(target, credential)
    assert rep.ok, rep
    assert [s.status for s in rep.steps] == ["ok"] * 7
    assert rep.steps[0].name == "DNS resolution"
    assert rep.error_code is None and rep.probe is not None
    assert rep.probe.os_id == "ubuntu" and rep.probe.supported and rep.probe.privilege_mode == "helper-sudo"
    assert rep.probe.remote_user == "cdpdeploy"


async def test_connection_host_key_unknown(target, credential):
    rep = await test_connection(dataclasses.replace(target, host_public_key=None), credential)
    assert not rep.ok and rep.error_code == RemoteErrorCode.HOST_KEY_UNKNOWN
    assert [s.status for s in rep.steps][:3] == ["ok", "ok", "failed"] and rep.steps[-1].status == "skipped"
    assert "SHA256:" in rep.steps[2].detail          # shows the fingerprint for explicit confirmation
    with pytest.raises(RemoteError) as ei:
        async with connect(dataclasses.replace(target, host_public_key=None), credential):
            pass
    assert ei.value.code == RemoteErrorCode.HOST_KEY_UNKNOWN


@pytest.mark.parametrize("algo", ["ssh-ed25519", "ssh-rsa"])
async def test_host_key_mismatch(target, credential, algo):
    wrong = asyncssh.generate_private_key(algo).export_public_key().decode().strip()
    t = dataclasses.replace(target, host_public_key=wrong)
    rep = await test_connection(t, credential)
    assert not rep.ok and rep.error_code == RemoteErrorCode.HOST_KEY_MISMATCH
    with pytest.raises(RemoteError) as ei:           # asyncssh itself enforces it as well (defence in depth)
        async with connect(t, credential):
            pass
    assert ei.value.code == RemoteErrorCode.HOST_KEY_MISMATCH


async def test_auth_rejected(target, unauthorized_credential):
    rep = await test_connection(target, unauthorized_credential)
    assert not rep.ok and rep.error_code == RemoteErrorCode.AUTH_REJECTED
    assert [s.status for s in rep.steps][3] == "failed" and rep.steps[4].status == "skipped"


async def test_connection_refused(target, credential):
    rep = await test_connection(dataclasses.replace(target, port=2299), credential)
    assert not rep.ok and rep.error_code == RemoteErrorCode.CONNECTION_REFUSED
    assert rep.steps[1].status == "failed"


async def test_timeout_blackhole(credential, host_pub):
    t = SSHTarget("10.255.255.1", 22, "cdpdeploy", host_pub, connect_timeout=2)
    rep = await test_connection(t, credential)
    assert not rep.ok and rep.error_code == RemoteErrorCode.TIMEOUT


async def test_dns_failure(credential, host_pub):
    t = SSHTarget("no-such-host.invalid", 22, "cdpdeploy", host_pub, connect_timeout=3)
    rep = await test_connection(t, credential)
    assert rep.error_code == RemoteErrorCode.DNS_FAILURE and rep.steps[0].status == "failed"


async def test_encrypted_key_credential(target, enc_credential):
    rep = await test_connection(target, enc_credential)
    assert rep.ok, rep
    bad = SSHCredential(enc_credential.private_key_pem, "wrong-passphrase")
    rep = await test_connection(target, bad)
    assert rep.error_code == RemoteErrorCode.AUTH_REJECTED
    async with connect(target, enc_credential) as h:
        assert (await h.stat("/etc/ssl/cdp-test/nginx/cert.pem")).exists


async def test_bastion_jump(target, credential):
    t = dataclasses.replace(target, jump=target)       # tunnel through the same sshd (direct-tcpip)
    rep = await test_connection(t, credential)
    assert rep.ok, rep
    async with connect(t, credential) as h:
        assert (await h.probe()).os_id == "ubuntu"
    bad = dataclasses.replace(target, jump=dataclasses.replace(target, host_public_key=None))
    with pytest.raises(RemoteError) as ei:
        async with connect(bad, credential):
            pass
    assert ei.value.code == RemoteErrorCode.HOST_KEY_UNKNOWN


async def test_privilege_missing_helper_and_sudo(target, credential, monkeypatch):
    # helper missing -> HELPER_MISSING (simulate with another path via monkeypatch of the helper location)
    from app.integrations.ssh import paths

    monkeypatch.setattr(paths, "HELPER_PATH", "/usr/local/libexec/does-not-exist")
    rep = await test_connection(target, credential)
    assert not rep.ok
    assert rep.error_code in (RemoteErrorCode.HELPER_MISSING, RemoteErrorCode.PERMISSION_DENIED)
    assert rep.steps[4].status == "ok" and rep.steps[5].status == "failed" and rep.steps[6].status == "skipped"


# ----------------------------------------------------------------------------- RemoteHost operations
async def test_probe(host):
    p = await host.probe()
    assert p.os_id == "ubuntu" and p.os_family == "debian" and p.supported
    svcs = {s.service: s for s in p.services}
    for st in (ServiceType.NGINX, ServiceType.APACHE, ServiceType.HAPROXY):
        assert svcs[st].installed and svcs[st].running is True and svcs[st].version
    assert p.helper_version == "1.0.0" and p.kernel


async def test_stat_variants(host, scratch):
    link = await host.stat(str(CERTS / "nginx-link/fullchain.pem"))
    assert link.exists and link.file_type == "symlink" and link.symlink_target == "releases/fullchain.pem"
    assert link.realpath == str(CERTS / "nginx-link/releases/fullchain.pem") and not link.broken_symlink
    assert link.sha256 == hashlib.sha256((CERTS / "nginx-link/releases/fullchain.pem").read_bytes()).hexdigest()
    assert link.mode == 0o644 and link.owner == "root" and link.uid == 0 and link.readable

    os.symlink(str(scratch / "gone.pem"), scratch / "broken.pem")
    broken = await host.stat(str(scratch / "broken.pem"))
    assert broken.exists and broken.broken_symlink and broken.file_type == "symlink" and broken.sha256 is None

    missing = await host.stat(str(scratch / "nope.pem"))
    assert not missing.exists and missing.file_type is None

    d = await host.stat(str(scratch))
    assert d.file_type == "dir"
    key = await host.stat(str(CERTS / "nginx/privkey.pem"))
    assert key.mode == 0o600 and key.sha256


async def test_read_public(host):
    data = await host.read_public_file(str(CERTS / "nginx/cert.pem"))
    assert data == (CERTS / "nginx/cert.pem").read_bytes()
    with pytest.raises(RemoteError) as ei:
        await host.read_public_file(str(CERTS / "nginx/privkey.pem"))
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED and ei.value.details["helper_error"] == "PRIVATE_KEY_REFUSED"
    with pytest.raises(RemoteError) as ei:           # combined pem contains a key too
        await host.read_public_file(str(CERTS / "haproxy/combined.pem"))
    assert ei.value.details["helper_error"] == "PRIVATE_KEY_REFUSED"
    with pytest.raises(RemoteError):                 # too large
        await host.read_public_file(str(CERTS / "nginx/fullchain.pem"), max_bytes=100)


async def test_backup_returns_key_material(host):
    content, st = await host.backup_file(str(CERTS / "nginx/privkey.pem"))
    assert content == (CERTS / "nginx/privkey.pem").read_bytes() and st.mode == 0o600 and st.exists


async def test_path_not_allowed(host, scratch):
    for bad in ("/etc/shadow", "/etc/ssl/../shadow", "/root/.bashrc", "/etc/ssl/cdp-test/../../shadow"):
        with pytest.raises(RemoteError) as ei:
            await host.stat(bad)
        assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED, bad
    # the helper itself rejects '..' components and absolute escapes even if a client skipped validation
    for raw in ("/etc/ssl/../shadow", "/etc/ssl/cdp-test/scratch/../../../shadow"):
        with pytest.raises(RemoteError) as ei:
            await host._helper("stat", raw)
        assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED
    with pytest.raises(RemoteError) as ei:           # relative path / newline are refused server side too
        await host._helper("stat", "etc/ssl")
    assert ei.value.details["helper_error"] == "BAD_ARGUMENT"
    with pytest.raises(RemoteError):
        await host._helper("stat", "/etc/ssl/a\nb")
    os.symlink("/etc/shadow", scratch / "escape.pem")  # symlink escape out of the allowed roots
    with pytest.raises(RemoteError) as ei:
        await host.stat(str(scratch / "escape.pem"))
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED
    with pytest.raises(RemoteError):
        await host.read_public_file(str(scratch / "escape.pem"))
    with pytest.raises(RemoteError) as ei:
        await host.find_cert_files(["/home"], 2, 10, [])
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED


async def test_find_cert_files(host):
    found = dict(await host.find_cert_files(["/etc/ssl/cdp-test", "/etc/letsencrypt", "/etc/pki"], 5, 500,
                                            exclude=["/etc/ssl/cdp-test/ca"]))
    assert found[str(CERTS / "nginx/fullchain.pem")] == FileKind.CERT_BUNDLE
    assert found[str(CERTS / "nginx/cert.pem")] == FileKind.CERTIFICATE
    assert found[str(CERTS / "nginx/privkey.pem")] == FileKind.PRIVATE_KEY
    assert found[str(CERTS / "haproxy/combined.pem")] == FileKind.COMBINED_PEM
    assert found["/etc/letsencrypt/live/certbot.test.local/fullchain.pem"] == FileKind.CERT_BUNDLE
    assert not any(p.startswith(str(CERTS / "ca")) for p in found)
    limited = await host.find_cert_files(["/etc/ssl/cdp-test"], 5, 3, [])
    assert len(limited) == 3


async def test_install_atomic_replace(host, scratch):
    dest = str(scratch / "deployed.pem")
    stage = await host.stage_dir()
    assert stage.startswith("/var/lib/cdp-helper/staging/")
    assert 0 < await host.free_bytes(dest)
    st = await host.write_staged(stage, "new.pem", b"first\n", 0o600)
    assert st.size == 6 and st.mode == 0o600
    res = await host.install(f"{stage}/new.pem", dest, 0o640, "root", "www-data")
    assert res.mode == 0o640 and res.group == "www-data" and res.owner == "root"
    first_inode = os.stat(dest).st_ino

    await host.write_staged(stage, "new2.pem", b"second\n", 0o600)
    res = await host.install(f"{stage}/new2.pem", dest, 0o644, "root", "root")
    assert Path(dest).read_bytes() == b"second\n" and res.mode == 0o644 and res.group == "root"
    assert os.stat(dest).st_ino != first_inode             # replaced via rename, not rewritten in place
    assert [p.name for p in scratch.iterdir()] == ["deployed.pem"]    # no .cdp-tmp leftovers

    # symlink dest that resolves to a regular file: link preserved, target replaced
    link = scratch / "link.pem"
    os.symlink(dest, link)
    await host.write_staged(stage, "new3.pem", b"third\n", 0o600)
    await host.install(f"{stage}/new3.pem", str(link), 0o644, "root", "root")
    assert link.is_symlink() and Path(dest).read_bytes() == b"third\n"

    # symlink dest that does not resolve to a regular file -> refused
    os.symlink(str(scratch), scratch / "dirlink")
    with pytest.raises(RemoteError) as ei:
        await host.install(f"{stage}/new3.pem", str(scratch / "dirlink"), 0o644, "root", "root")
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED and ei.value.details["helper_error"] == "SYMLINK_DEST"
    os.symlink(str(scratch / "dangling"), scratch / "dangle")
    with pytest.raises(RemoteError):
        await host.install(f"{stage}/new3.pem", str(scratch / "dangle"), 0o644, "root", "root")
    # outside allowed roots / unknown owner / bad staged path / bad name
    with pytest.raises(RemoteError) as ei:
        await host.install(f"{stage}/new3.pem", "/etc/passwd", 0o644, "root", "root")
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED
    with pytest.raises(RemoteError) as ei:
        await host.install("/etc/hostname", dest, 0o644, "root", "root")
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED
    with pytest.raises(RemoteError) as ei:
        await host.install(f"{stage}/new3.pem", dest, 0o644, "no-such-user", "root")
    assert ei.value.code == RemoteErrorCode.PERMISSION_DENIED
    with pytest.raises(RemoteError):
        await host.write_staged(stage, "../evil", b"x", 0o600)
    with pytest.raises(RemoteError):
        await host.write_staged("/etc/ssl", "x.pem", b"x", 0o600)
    assert [p.name for p in scratch.iterdir() if ".cdp-tmp" in p.name] == []

    await host.cleanup(stage)
    assert not os.path.exists(stage)
    with pytest.raises(RemoteError):
        await host.cleanup("/etc/ssl")


async def test_config_test_and_reload_nginx_apache_haproxy(host, target, credential):
    for svc, port, sni in ((ServiceType.NGINX, 8443, "nginx.test.local"), (ServiceType.APACHE, 9443, "apache.test.local"),
                           (ServiceType.HAPROXY, 10443, None)):
        ct = await host.config_test(svc)
        assert ct.exit_status == 0, ct
        rl = await host.reload(svc)
        assert rl.exit_status == 0, rl
        await asyncio.sleep(1)
        res = await probe_endpoint("127.0.0.1", port, sni, 5)
        assert res.ok, (svc, res.error)


async def test_config_test_failure_reported(host):
    bad = "/etc/nginx/conf.d/zz-bad.conf"
    Path(bad).write_text("this_is_not_a_directive on;\n")
    try:
        ct = await host.config_test(ServiceType.NGINX)
        assert ct.exit_status != 0 and "unknown directive" in ct.stdout
    finally:
        os.unlink(bad)
    assert (await host.config_test(ServiceType.NGINX)).exit_status == 0


async def test_dump_config(host):
    ng = await host.dump_config(ServiceType.NGINX)
    assert "# configuration file /etc/nginx/conf.d/cdp-test.conf:" in ng and "nginx.test.local" in ng
    ap = await host.dump_config(ServiceType.APACHE)
    assert "# configuration file /etc/apache2/sites-enabled/cdp-test.conf:" in ap and "SSLCertificateChainFile" in ap
    hp = await host.dump_config(ServiceType.HAPROXY)
    assert "# configuration file /etc/haproxy/haproxy.cfg:" in hp and "combined.pem" in hp
    assert "PRIVATE KEY" not in ng + ap + hp


# ----------------------------------------------------------------------------- operational properties
async def test_cancel_event(target, credential):
    ev = asyncio.Event()
    async with connect(target, credential, cancel_event=ev) as h:
        loop = asyncio.get_running_loop()
        loop.call_later(0.5, ev.set)
        t0 = loop.time()
        with pytest.raises(RemoteError) as ei:
            await h.run_fixed("sleep", "20")
        assert ei.value.code == RemoteErrorCode.CANCELLED and loop.time() - t0 < 5
        with pytest.raises(RemoteError) as ei:       # stays cancelled
            await h.stat("/etc/ssl")
        assert ei.value.code == RemoteErrorCode.CANCELLED


async def test_asyncio_cancellation_and_command_timeout(target, credential):
    async with connect(dataclasses.replace(target, command_timeout=1), credential) as h:
        with pytest.raises(RemoteError) as ei:
            await h.run_fixed("sleep", "20", idempotent=False)
        assert ei.value.code == RemoteErrorCode.TIMEOUT and not ei.value.retryable
        task = asyncio.ensure_future(h.run_fixed("sleep", "20", idempotent=False))
        await asyncio.sleep(0.3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_output_cap(host):
    with pytest.raises(RemoteError) as ei:
        await host.run_fixed("head", "-c", "3000000", "/dev/zero")
    assert ei.value.code == RemoteErrorCode.COMMAND_FAILED and "size limit" in ei.value.message


async def test_hostile_argument_is_not_interpreted(host, scratch):
    marker = scratch / "pwned"
    arg = f"/etc/ssl/cdp-test/x; touch {marker}; $(touch {marker}) `touch {marker}`"
    st = await host.stat(arg)
    assert not st.exists and not marker.exists()
    res = await host.run_fixed("echo", f"a b; touch {marker} $(id)")
    assert res.stdout.strip() == f"a b; touch {marker} $(id)" and not marker.exists()


async def test_retry_only_for_idempotent(host, monkeypatch):
    real = host._run
    calls = {"n": 0}

    async def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RemoteError(RemoteErrorCode.UNKNOWN, "connection lost", retryable=True)
        return await real(*a, **kw)

    monkeypatch.setattr(host, "_run", flaky)
    host._backoff = 0.01
    st = await host.stat("/etc/ssl/cdp-test/nginx/cert.pem")      # idempotent: retried on a fresh connection
    assert st.exists and calls["n"] == 2

    calls["n"] = 0
    with pytest.raises(RemoteError):                               # stage_dir is NOT idempotent: no retry
        await host.stage_dir()
    assert calls["n"] == 1


async def test_per_host_concurrency_limit(target, credential):
    set_host_concurrency_limit(1, target.host, target.port)
    try:
        async with connect(target, credential):
            with pytest.raises(RemoteError) as ei:
                async with connect(target, credential, queue_timeout=0.5):
                    pass
            assert ei.value.code == RemoteErrorCode.TIMEOUT
        async with connect(target, credential, queue_timeout=2):   # slot released
            pass
    finally:
        set_host_concurrency_limit(4, target.host, target.port)


# ----------------------------------------------------------------------------- TLS probe
async def test_probe_endpoints_and_sni():
    ca = (CERTS / "ca/ca.pem").read_bytes()
    expect = {
        (8443, "nginx.test.local"): CERTS / "nginx/cert.pem",
        (8443, "nginx-link.test.local"): CERTS / "nginx-link/releases/cert.pem",
        (8443, "certbot.test.local"): CERTS / "certbot-src/cert.pem",
        (9443, "apache.test.local"): CERTS / "apache/cert.pem",
        (10443, "haproxy.test.local"): CERTS / "haproxy-src/cert.pem",
    }
    seen = set()
    for (port, sni), pem in expect.items():
        res = await probe_endpoint("127.0.0.1", port, sni, 5, trust_anchors_pem=ca)
        assert res.ok and res.leaf is not None, (port, sni, res.error)
        assert res.leaf.fingerprint_sha256 == _fp_hex(pem), (port, sni)
        assert res.chain_valid is True and res.hostname_matches is True and res.tls_version
        assert len(res.chain) == 1 and res.chain[0].subject.endswith("CDP Test Intermediate CA")
        seen.add(res.leaf.fingerprint_sha256)
    assert len(seen) == 5                                          # SNI really selects different certs

    res = await probe_endpoint("127.0.0.1", 9443, "apache.test.local", 5)            # system store: untrusted CA
    assert res.ok and res.chain_valid is False and res.hostname_matches is True
    res = await probe_endpoint("127.0.0.1", 9443, "apache.test.local", 5, ca, expected_hostname="other.test.local")
    assert res.chain_valid is True and res.hostname_matches is False
    res = await probe_endpoint("127.0.0.1", 8443, "nonexistent.test.local", 5, ca)    # falls to default server
    assert res.ok and res.leaf.common_name == "nginx.test.local" and res.hostname_matches is False
    res = await probe_endpoint("127.0.0.1", 1, None, 2)
    assert not res.ok and res.error and res.leaf is None


# ----------------------------------------------------------------------------- adapters (need stream B parsers)
@pytest.mark.parametrize("stype,names", [
    ("nginx", {"nginx.test.local", "nginx-link.test.local", "certbot.test.local"}),
    ("apache", {"apache.test.local"}),
    ("haproxy", set()),
])
async def test_adapter_discovery(host, stype, names):
    from app.integrations.services.adapters import get_adapter

    modname = {"nginx": "nginx", "apache": "apache", "haproxy": "haproxy"}[stype]
    pytest.importorskip(f"app.integrations.services.parsers.{modname}")
    refs = await get_adapter(stype).discover(host)
    paths = {r.cert_path for r in refs}
    expected = {
        "nginx": {str(CERTS / "nginx/fullchain.pem"), str(CERTS / "nginx-link/fullchain.pem"),
                  "/etc/letsencrypt/live/certbot.test.local/fullchain.pem"},
        "apache": {str(CERTS / "apache/cert.pem")},
        "haproxy": {str(CERTS / "haproxy/combined.pem")},
    }[stype]
    assert expected <= paths
    if names:
        assert names <= {n for r in refs for n in r.server_names}
