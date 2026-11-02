"""Test doubles and builders for the deployment engine unit tests (in-memory RemoteHost, fake TLS endpoints)."""
from __future__ import annotations

import hashlib
import posixpath
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from app.core.crypto import get_vault
from app.integrations.certificates import key_matches_cert, parse_pem_certificates
from app.integrations.certificates.errors import CertificateError
from app.integrations.contracts import (
    CommandResult,
    EndpointCertResult,
    HostProbe,
    RemoteError,
    RemoteErrorCode,
    RemoteFileStat,
    ServiceProbe,
    ServiceType,
)
from app.integrations.tls.probe import hostname_matches
from app.models import CertificateInstallation, CertificateVersion, Server
from app.models.certificate import make_identity_key


class SimulatedCrash(BaseException):
    """Stands in for a killed worker: not an Exception, so no engine error handling may swallow it."""


@dataclass
class FakeFile:
    content: bytes
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"


@dataclass
class VHost:
    service: str
    cert_path: str
    key_path: str
    host: str
    port: int


@dataclass
class FakeFS:
    """A fake server: files, symlinks, staging, vhosts. ``calls`` records every mutating operation."""
    files: dict[str, FakeFile] = field(default_factory=dict)
    links: dict[str, str] = field(default_factory=dict)
    staged: dict[str, bytes] = field(default_factory=dict)
    vhosts: list[VHost] = field(default_factory=list)
    served: dict[tuple[str, int], str | None] = field(default_factory=dict)   # (host, port) -> leaf fingerprint
    calls: list[tuple] = field(default_factory=list)
    hooks: dict[str, Callable] = field(default_factory=dict)
    stage_counter: int = 0
    current_config_broken: bool = False

    def resolve(self, path: str) -> str:
        seen = 0
        while path in self.links and seen < 10:
            t = self.links[path]
            path = t if t.startswith("/") else posixpath.normpath(posixpath.join(posixpath.dirname(path), t))
            seen += 1
        return path

    def snapshot(self) -> dict[str, bytes]:
        return {p: f.content for p, f in self.files.items()}

    def leaf_fp(self, path: str) -> str | None:
        f = self.files.get(self.resolve(path))
        if f is None:
            return None
        certs = parse_pem_certificates(f.content)
        return certs[0].fingerprint_sha256 if certs else None

    def reload_effect(self) -> None:
        for v in self.vhosts:
            self.served[(v.host, v.port)] = self.leaf_fp(v.cert_path)

    def config_problem(self) -> str | None:
        if self.current_config_broken:
            return "emerg: unexpected end of file"
        for v in self.vhosts:
            c, k = self.files.get(self.resolve(v.cert_path)), self.files.get(self.resolve(v.key_path))
            if c is None or k is None:
                return f"cannot load {v.cert_path}"
            certs = parse_pem_certificates(c.content)
            if not certs:
                return f"no certificate in {v.cert_path}"
            try:
                if not key_matches_cert(k.content if b"PRIVATE KEY" in k.content else c.content, None, certs[0]):
                    return "SSL_CTX_use_PrivateKey_file failed (key values mismatch)"
            except CertificateError:
                return "bad key"
        return None


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class FakeHost:
    def __init__(self, fs: FakeFS):
        self.fs = fs

    def _hook(self, name: str, *a):
        h = self.fs.hooks.get(name)
        if h:
            return h(*a)
        return None

    async def probe(self) -> HostProbe:
        return HostProbe("ubuntu", "24.04", "Ubuntu 24.04", "debian", True, "6", "cdpdeploy", "helper-sudo", "1.0",
                         tuple(ServiceProbe(s, True, "1", "/bin/x", True, "systemd") for s in
                               (ServiceType.NGINX, ServiceType.APACHE, ServiceType.HAPROXY)))

    def _stat(self, path: str) -> RemoteFileStat:
        real = self.fs.resolve(path)
        f = self.fs.files.get(real)
        if f is None:
            return RemoteFileStat(path, False, None, None, None, path in self.fs.links, None, None, None, None, None,
                                  None, None, None, False)
        link = self.fs.links.get(path)
        return RemoteFileStat(path, True, "symlink" if link else "file", real, link, False, f.mode, 0, 0, f.owner,
                              f.group, len(f.content), _sha(f.content), None, True)

    async def stat(self, path: str) -> RemoteFileStat:
        return self._stat(path)

    async def read_public_file(self, path: str, max_bytes: int = 1_048_576) -> bytes:
        f = self.fs.files.get(self.fs.resolve(path))
        if f is None:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "not found")
        if b"PRIVATE KEY" in f.content:
            raise RemoteError(RemoteErrorCode.PATH_NOT_ALLOWED, "refusing private key")
        return f.content

    async def backup_file(self, path: str):
        f = self.fs.files.get(self.fs.resolve(path))
        if f is None:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "not found")
        return f.content, self._stat(path)

    async def find_cert_files(self, *a, **k):  # pragma: no cover
        return []

    async def dump_config(self, service):  # pragma: no cover
        return ""

    async def free_bytes(self, path: str) -> int:
        return 10**9

    async def stage_dir(self) -> str:
        self.fs.calls.append(("stage_dir",))
        self.fs.stage_counter += 1
        return f"/var/lib/cdp-helper/staging/s{self.fs.stage_counter}"

    async def write_staged(self, stage_dir: str, name: str, content: bytes, mode: int) -> RemoteFileStat:
        self.fs.calls.append(("write_staged", name))
        self._hook("write_staged", name, self.fs)
        self.fs.staged[posixpath.join(stage_dir, name)] = content
        return RemoteFileStat(posixpath.join(stage_dir, name), True, "file", None, None, False, mode, 0, 0, "root",
                              "root", len(content), _sha(content), None, True)

    async def install(self, staged_path: str, dest: str, mode: int, owner: str, group: str) -> RemoteFileStat:
        self.fs.calls.append(("install", dest))
        self._hook("before_install", dest, self.fs)
        content = self.fs.staged[staged_path]
        real = self.fs.resolve(dest)
        self.fs.files[real] = FakeFile(content, mode, owner, group)
        res = self._stat(dest)
        self._hook("after_install", dest, self.fs)
        return res

    async def config_test(self, service: ServiceType) -> CommandResult:
        problem = self.fs.config_problem()
        return CommandResult(("configtest",), 0 if problem is None else 1, problem or "syntax is ok", "", 1)

    async def reload(self, service: ServiceType, allow_restart: bool = False) -> CommandResult:
        self.fs.calls.append(("reload", service.value))
        self._hook("on_reload", self.fs)
        self.fs.reload_effect()
        self._hook("after_reload", self.fs)
        return CommandResult(("reload",), 0, "reloaded", "", 1)

    async def cleanup(self, stage_dir: str) -> None:
        self.fs.calls.append(("cleanup", stage_dir))
        for k in [k for k in self.fs.staged if k.startswith(stage_dir + "/")]:
            del self.fs.staged[k]

    async def close(self) -> None:  # pragma: no cover
        pass


class FakeNetwork:
    """host_factory + TLS probe stand-in over several fake servers."""

    def __init__(self) -> None:
        self.by_server: dict[uuid.UUID, FakeFS] = {}

    def add(self, server: Server, fs: FakeFS | None = None) -> FakeFS:
        self.by_server[server.id] = fs or FakeFS()
        return self.by_server[server.id]

    def factory(self, server: Server):
        fs = self.by_server[server.id]

        @asynccontextmanager
        async def cm():
            yield FakeHost(fs)

        return cm()

    def all_calls(self) -> list[tuple]:
        return [c for fs in self.by_server.values() for c in fs.calls]

    async def probe_endpoint(self, host, port, sni, timeout, trust_anchors_pem=None, expected_hostname=None):
        for fs in self.by_server.values():
            if (host, port) in fs.served or any(v.host == host and v.port == port for v in fs.vhosts):
                fp = fs.served.get((host, port))
                if fp is None:
                    return EndpointCertResult(host, port, sni, False, None, (), None, None, "connection refused", None)
                leaf = next((c for p in fs.files for c in parse_pem_certificates(fs.files[p].content)[:1]
                             if c.fingerprint_sha256 == fp), None)
                ok_host = hostname_matches(leaf, expected_hostname or sni or host) if leaf else None
                return EndpointCertResult(host, port, sni, True, leaf, (), True, ok_host, None, "TLSv1.3")
        return EndpointCertResult(host, port, sni, False, None, (), None, None, "connection refused", None)


# --------------------------------------------------------------------------- DB builders
def pem_key(issued) -> bytes:
    return issued.key_pem


def add_server(db, name: str, *, env: str = "Test", address: str | None = None) -> Server:
    s = Server(name=name, hostname=f"{name}.example.test", address=address or f"10.9.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
               ssh_username="cdpdeploy", environment=env, host_public_key="ssh-ed25519 AAAAFAKE", host_key_type="ssh-ed25519",
               connection_status="connected")
    db.add(s)
    db.commit()
    return s


def add_installation(db, server: Server, fs: FakeFS, pki, *, name: str = "site", port: int = 8443, service: str = "nginx",
                     cert_path: str | None = None, key_path: str | None = None, chain_path: str | None = None,
                     certbot: bool = False, link: bool = False, observed: bool = True,
                     names: list[str] | None = None) -> CertificateInstallation:
    """Install ``pki`` (the CURRENT cert) on the fake server and create the inventory row."""
    cert_path = cert_path or f"/etc/ssl/{name}/fullchain.pem"
    key_path = key_path or f"/etc/ssl/{name}/privkey.pem"
    leaf = pki.leaf
    if service == "nginx":
        fs.files[cert_path if not link else f"/etc/ssl/{name}/releases/fullchain.pem"] = FakeFile(pki.fullchain_pem, 0o644)
        fs.files[key_path if not link else f"/etc/ssl/{name}/releases/privkey.pem"] = FakeFile(leaf.key_pem, 0o600)
        if link:
            fs.links[cert_path] = f"releases/{posixpath.basename(cert_path)}"
            fs.links[key_path] = f"releases/{posixpath.basename(key_path)}"
    elif service == "apache":
        fs.files[cert_path] = FakeFile(pki.leaf.cert_pem, 0o644)
        fs.files[key_path] = FakeFile(leaf.key_pem, 0o600)
        if chain_path:
            fs.files[chain_path] = FakeFile(pki.chain_pem, 0o644)
    fs.vhosts.append(VHost(service, cert_path, key_path, server.address, port))
    fs.reload_effect()
    fp = parse_pem_certificates(pki.leaf.cert_pem)[0].fingerprint_sha256
    names = names or ["site.test.local"]
    inst = CertificateInstallation(
        server_id=server.id, service_type=service, cert_path=cert_path, key_path=key_path, chain_path=chain_path,
        listen_port=port, vhost=names[0], server_names=names, last_observed_fingerprint=fp if observed else None,
        classification="managed", managed_by_certbot=certbot, verify_host=server.address, verify_port=port,
        verify_sni=names[0], identity_key=make_identity_key(server.id, service, cert_path, f"{names[0]}:{port}"))
    db.add(inst)
    db.commit()
    return inst


def add_version(db, pki, *, with_key: bool = True, reuse: bool = False, status: str = "validated") -> CertificateVersion:
    vault = get_vault()
    leaf = parse_pem_certificates(pki.leaf.cert_pem)[0]
    cert = vault.store(pki.leaf.cert_pem, "cert", db=db)
    chain = vault.store(pki.chain_pem, "chain", db=db)
    key = vault.store(pki.leaf.key_pem, "key", db=db) if with_key else None
    v = CertificateVersion(
        fingerprint_sha256=leaf.fingerprint_sha256, cert_artifact_id=cert.id, chain_artifact_id=chain.id,
        key_artifact_id=key.id if key else None, validation_status="valid", status=status, reuses_existing_key=reuse,
        leaf_metadata={"subject": leaf.subject})
    db.add(v)
    db.commit()
    return v
