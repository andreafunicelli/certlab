from __future__ import annotations

import shlex
import socket

import asyncssh
import pytest

from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.integrations.ssh import classify_exception, parsing, paths, sanitize_output
from app.integrations.ssh.hostkeys import known_hosts_for


# ---------------------------------------------------------------- argv quoting
def test_build_command_quotes_every_element():
    hostile = "/etc/ssl/a b; rm -rf / $(id) `id` 'q' \"d\" *"
    argv = paths.helper_argv("stat", hostile)
    cmd = paths.build_command(argv)
    assert shlex.split(cmd) == list(argv)           # round-trips: no re-interpretation by a shell
    assert argv[:4] == ("sudo", "-n", paths.HELPER_PATH, "stat")
    assert ";" not in cmd.replace(shlex.quote(hostile), "")


def test_helper_argv_rejects_unknown_subcommand_and_nul():
    with pytest.raises(ValueError):
        paths.helper_argv("rm", "/x")
    with pytest.raises(RemoteError):
        paths.helper_argv("stat", "/etc/ssl/\x00x")


def test_helper_direct_mode_has_no_sudo():
    assert paths.helper_argv("version", privilege_mode="helper-direct")[0] == paths.HELPER_PATH


# ---------------------------------------------------------------- path validation
@pytest.mark.parametrize("bad", ["", "relative/path", "etc/ssl", "/etc/ssl/a\nb", "/etc/ssl/a\x00b", "/etc/\x07x"])
def test_validate_path_rejects(bad):
    with pytest.raises(RemoteError) as ei:
        paths.validate_path(bad)
    assert ei.value.code == RemoteErrorCode.PATH_NOT_ALLOWED


def test_validate_path_normalises():
    assert paths.validate_path("/etc/ssl/../shadow") == "/etc/shadow"
    assert paths.validate_path("/etc//ssl/./certs/") == "/etc/ssl/certs"
    assert paths.validate_path("//etc/ssl") == "/etc/ssl"


@pytest.mark.parametrize("bad", ["", "a/b", "..", ".", "a b", "a;b", "a\nb", "$(x)"])
def test_validate_name_rejects(bad):
    with pytest.raises(RemoteError):
        paths.validate_name(bad)


def test_mode_and_account():
    assert paths.mode_str(0o640) == "0640"
    with pytest.raises(RemoteError):
        paths.mode_str(0o17777)
    with pytest.raises(RemoteError):
        paths.validate_account("root; id")
    assert paths.validate_account("www-data") == "www-data"


# ---------------------------------------------------------------- error classification
def test_classify_exceptions():
    cases = [
        (socket.gaierror(-2, "Name or service not known"), RemoteErrorCode.DNS_FAILURE),
        (ConnectionRefusedError(), RemoteErrorCode.CONNECTION_REFUSED),
        (TimeoutError(), RemoteErrorCode.TIMEOUT),
        (TimeoutError(), RemoteErrorCode.TIMEOUT),
        (asyncssh.HostKeyNotVerifiable("x"), RemoteErrorCode.HOST_KEY_MISMATCH),
        (asyncssh.PermissionDenied("x"), RemoteErrorCode.AUTH_REJECTED),
        (asyncssh.DisconnectError(asyncssh.DISC_HOST_KEY_NOT_VERIFIABLE, "x"), RemoteErrorCode.HOST_KEY_MISMATCH),
        (asyncssh.DisconnectError(asyncssh.DISC_NO_MORE_AUTH_METHODS_AVAILABLE, "x"), RemoteErrorCode.AUTH_REJECTED),
        (asyncssh.DisconnectError(asyncssh.DISC_BY_APPLICATION, "x"), RemoteErrorCode.UNKNOWN),
        (asyncssh.KeyExchangeFailed("No matching host key type found"), RemoteErrorCode.HOST_KEY_MISMATCH),
        (OSError(113, "No route to host"), RemoteErrorCode.TIMEOUT),
        (ValueError("boom"), RemoteErrorCode.UNKNOWN),
    ]
    for exc, code in cases:
        assert classify_exception(exc).code == code, exc
    assert classify_exception(TimeoutError()).retryable
    assert not classify_exception(ConnectionRefusedError()).retryable
    err = RemoteError(RemoteErrorCode.CANCELLED, "x")
    assert classify_exception(err) is err


def test_classification_never_leaks_pem():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    err = classify_exception(ValueError(pem))
    assert "PRIVATE KEY" not in err.message


# ---------------------------------------------------------------- sanitizer
def test_sanitize_strips_pem_and_base64():
    text = "ok\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\ntail " + "A" * 120
    out = sanitize_output(text)
    assert "MIIE" not in out and "BEGIN" not in out and "Qz" * 40 not in out
    assert out.startswith("ok") and "tail" in out


def test_sanitize_truncated_pem_and_hex_kept():
    out = sanitize_output("x -----BEGIN PRIVATE KEY-----\nMIIabc")
    assert "MIIabc" not in out
    digest = "a" * 64
    assert digest in sanitize_output(f"sha256 {digest}")
    assert "0" * 128 in sanitize_output("0" * 128)                 # sha512-length hex digest kept
    assert "0" * 200 not in sanitize_output("0" * 200)             # longer hex-looking run is redacted
    assert sanitize_output("hello world " * 10, max_len=10).endswith("[truncated]")


# ---------------------------------------------------------------- helper output parsing
def test_map_failure_uses_helper_json():
    e = parsing.map_failure(3, '{"ok":false,"error":"PATH_NOT_ALLOWED","message":"outside"}\n')
    assert e.code == RemoteErrorCode.PATH_NOT_ALLOWED and e.details["helper_error"] == "PATH_NOT_ALLOWED"
    assert parsing.map_failure(5, '{"ok":false,"error":"PRIVATE_KEY_REFUSED","message":"x"}').code == RemoteErrorCode.PATH_NOT_ALLOWED
    assert parsing.map_failure(6, '{"ok":false,"error":"DISK_FULL","message":"x"}').code == RemoteErrorCode.DISK_FULL
    assert parsing.map_failure(4, '{"ok":false,"error":"PERMISSION_DENIED","message":"x"}').code == RemoteErrorCode.PERMISSION_DENIED
    assert parsing.map_failure(9, '{"ok":false,"error":"COMMAND_FAILED","message":"x"}').code == RemoteErrorCode.COMMAND_FAILED


def test_map_failure_sudo_and_missing_helper():
    assert parsing.map_failure(1, "sudo: a password is required").code == RemoteErrorCode.PERMISSION_DENIED
    assert parsing.map_failure(1, "sudo: sorry, user x is not allowed to execute '/y' as root").code == RemoteErrorCode.PERMISSION_DENIED
    assert parsing.map_failure(1, "sudo: /usr/local/libexec/cdp-helper: command not found").code == RemoteErrorCode.HELPER_MISSING
    assert parsing.map_failure(127, "").code == RemoteErrorCode.HELPER_MISSING
    assert parsing.map_failure(1, "cat: x: No space left on device").code == RemoteErrorCode.DISK_FULL
    assert parsing.map_failure(1, "weird").code == RemoteErrorCode.COMMAND_FAILED


def test_parse_stat_and_probe():
    st = parsing.parse_stat({"path": "/a", "exists": True, "file_type": "file", "realpath": "/a", "symlink_target": None,
                             "broken_symlink": False, "mode": 420, "uid": 0, "gid": 0, "owner": "root", "group": "root",
                             "size": 3, "sha256": "ab", "selinux_context": None, "readable": True})
    assert st.mode == 0o644 and st.exists and st.owner == "root"
    p = parsing.parse_probe({"helper_version": "1.0.0", "os_id": "rocky", "os_version": "9.3", "os_pretty": "Rocky",
                             "os_id_like": "rhel centos fedora", "kernel": "5", "service_manager": "systemd",
                             "services": [{"name": "nginx", "installed": True, "binary": "/usr/sbin/nginx",
                                           "version": "1.2", "running": False},
                                          {"name": "apache", "installed": False, "binary": None, "version": None, "running": None}]},
                            "cdpdeploy", "helper-sudo")
    assert p.os_family == "rhel" and p.supported and p.services[0].running is False
    assert p.services[1].installed is False and p.helper_version == "1.0.0"


@pytest.mark.parametrize("oid,like,family,supported", [
    ("ubuntu", "debian", "debian", True), ("debian", "", "debian", True), ("rhel", "fedora", "rhel", True),
    ("almalinux", "rhel centos fedora", "rhel", True), ("ol", "fedora", "rhel", True),
    ("centos", "rhel fedora", "rhel", False), ("alpine", "", "other", False), ("linuxmint", "ubuntu debian", "debian", False),
])
def test_classify_os(oid, like, family, supported):
    assert parsing.classify_os(oid, like) == (family, supported)


def test_parse_find_output():
    out = ('{"path":"/etc/ssl/a.pem","kind":"certificate"}\n{"path":"/etc/ssl/k.key","kind":"private_key"}\n'
           '{"path":"/x","kind":"bogus"}\n{"done":true,"count":3,"truncated":true}\n')
    entries, trunc = parsing.parse_find_output(out)
    assert [k.value for _, k in entries] == ["certificate", "private_key", "unknown"] and trunc


def test_parse_json_line_rejects_garbage():
    with pytest.raises(RemoteError):
        parsing.parse_json_line("not json")
    with pytest.raises(RemoteError):
        parsing.parse_json_line("")


# ---------------------------------------------------------------- strict host keys
def test_known_hosts_requires_enrolled_key():
    with pytest.raises(RemoteError) as ei:
        known_hosts_for("h", 22, None)
    assert ei.value.code == RemoteErrorCode.HOST_KEY_UNKNOWN
    with pytest.raises(RemoteError) as ei:
        known_hosts_for("h", 22, "garbage")
    assert ei.value.code == RemoteErrorCode.HOST_KEY_UNKNOWN
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    assert known_hosts_for("h", 2222, key) is not None


# ---------------------------------------------------------------- adapters / tls helpers
def test_adapter_plans():
    from types import SimpleNamespace as NS

    from app.integrations.services.adapters import ArtifactKind, PlanError, get_adapter

    ng = get_adapter("nginx").plan_files(NS(cert_path="/c", key_path="/k", chain_path=None, is_combined_pem=False))
    assert [(f.dest_path, f.artifact) for f in ng] == [("/c", ArtifactKind.FULLCHAIN), ("/k", ArtifactKind.KEY)]
    ap = get_adapter("apache").plan_files(NS(cert_path="/c", key_path="/k", chain_path="/ch", is_combined_pem=False))
    assert [f.artifact for f in ap] == [ArtifactKind.CERT, ArtifactKind.CHAIN, ArtifactKind.KEY]
    ap2 = get_adapter("apache").plan_files(NS(cert_path="/c", key_path="/k", chain_path=None, is_combined_pem=False))
    assert ap2[0].artifact == ArtifactKind.FULLCHAIN
    hp = get_adapter("haproxy").plan_files(NS(cert_path="/p.pem", key_path=None, chain_path=None, is_combined_pem=True))
    assert hp[0].artifact == ArtifactKind.COMBINED and hp[0].mode == 0o600 and hp[0].contains_private_key
    with pytest.raises(PlanError):
        get_adapter("nginx").plan_files(NS(cert_path="/c", key_path=None, chain_path=None, is_combined_pem=False))
    with pytest.raises(KeyError):
        get_adapter("tomcat")


def test_default_verify_endpoints():
    from app.integrations.contracts import ConfigCertRef, ServiceType
    from app.integrations.services.adapters import get_adapter

    ref = ConfigCertRef(ServiceType.NGINX, "/f", 1, "ctx", ("a.example.com", "*.example.com", "_"), (443, 8443),
                        "/c", "/k", None, False)
    eps = get_adapter("nginx").default_verify_endpoints(ref)
    assert ("a.example.com", 443, "a.example.com") in eps and ("", 8443, None) in eps and len(eps) == 4


def test_hostname_matches():
    from types import SimpleNamespace as NS

    from app.integrations.tls.probe import hostname_matches

    c = NS(sans=("a.example.com", "*.wild.example.com", "10.0.0.1"), common_name="cn.example.com")
    assert hostname_matches(c, "a.example.com") and hostname_matches(c, "X.wild.example.com")
    assert not hostname_matches(c, "a.b.wild.example.com") and not hostname_matches(c, "wild.example.com")
    assert hostname_matches(c, "10.0.0.1") and not hostname_matches(c, "cn.example.com")
    assert hostname_matches(NS(sans=(), common_name="cn.example.com"), "cn.example.com")
