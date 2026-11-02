"""Shared contracts between integration layers (certificates, ssh, services, tls)
and the domain services. Pure data + Protocols: no I/O, no DB.

Every layer imports from here; do not redefine these types elsewhere.
"""
from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


# --------------------------------------------------------------------------- certificates
class Severity(str, enum.Enum):
    BLOCKING = "blocking"   # deployment must not proceed
    WARNING = "warning"     # requires explicit acknowledgement
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    code: str               # stable machine code e.g. "KEY_MISMATCH", "SAN_MISMATCH"
    severity: Severity
    message: str            # human readable, MUST NOT contain secret material
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CertInfo:
    """Metadata extracted from ONE X.509 certificate (never contains key material)."""
    subject: str                    # RFC4514
    issuer: str                     # RFC4514
    common_name: str | None
    sans: tuple[str, ...]           # DNS + IP SANs, as strings, DNS lower-cased
    serial_number: str              # hex, upper-case, no colons
    fingerprint_sha256: str         # hex, lower-case, no colons
    public_key_algorithm: str       # "RSA" | "EC" | "Ed25519" | "Ed448" | "DSA"
    public_key_size: int | None     # bits (curve size for EC)
    public_key_sha256: str          # sha256 of SubjectPublicKeyInfo DER — used for key matching
    signature_algorithm: str        # e.g. "sha256WithRSAEncryption"
    not_before: datetime            # tz-aware UTC
    not_after: datetime             # tz-aware UTC
    is_ca: bool
    is_self_signed: bool
    authority_key_id: str | None
    subject_key_id: str | None
    pem: str                        # public certificate PEM (safe to store)


@dataclass(frozen=True)
class ParsedBundle:
    """Result of parsing a user upload or a remote file."""
    leaf: CertInfo | None
    chain: tuple[CertInfo, ...]             # intermediates/roots in order leaf->root (excluding leaf)
    private_key_pem: bytes | None           # unencrypted PKCS8 PEM, ONLY in memory; caller encrypts at rest
    private_key_public_sha256: str | None   # SPKI sha256 of the private key's public half
    private_key_encrypted: bool             # input key was passphrase protected
    findings: tuple[Finding, ...] = ()


class FileKind(str, enum.Enum):
    CERTIFICATE = "certificate"
    CERT_BUNDLE = "cert_bundle"           # multiple certs (fullchain)
    PRIVATE_KEY = "private_key"
    COMBINED_PEM = "combined_pem"         # cert(s) + key (HAProxy style)
    PKCS12 = "pkcs12"
    JKS = "jks"
    CSR = "csr"
    UNRELATED_PEM = "unrelated_pem"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- service config
class ServiceType(str, enum.Enum):
    NGINX = "nginx"
    APACHE = "apache"
    HAPROXY = "haproxy"
    FILESYSTEM = "filesystem"             # found by filesystem scan only, no service association


@dataclass(frozen=True)
class ConfigCertRef:
    """One certificate reference found in a service's effective configuration."""
    service: ServiceType
    config_file: str                      # file the directive was found in
    line: int | None
    context: str                          # e.g. "server{server_name=a.example.com; listen=443}" / "<VirtualHost *:443>"
    server_names: tuple[str, ...]         # server_name / ServerName+ServerAlias / haproxy bind (may be empty)
    listen_ports: tuple[int, ...]
    cert_path: str | None                 # resolved absolute path (None if unresolved)
    key_path: str | None
    chain_path: str | None                # apache SSLCertificateChainFile / haproxy n/a
    is_combined_pem: bool                 # haproxy: cert+key in one file; or crt dir
    is_directory: bool = False            # haproxy "crt /dir/"
    unresolved_expression: str | None = None   # e.g. nginx "$ssl_server_name" variables -> unsupported
    confidence: float = 1.0               # 0..1


# --------------------------------------------------------------------------- remote
@dataclass(frozen=True)
class RemoteFileStat:
    path: str
    exists: bool
    file_type: str | None                 # "file" | "dir" | "symlink" | "other"
    realpath: str | None                  # fully resolved target
    symlink_target: str | None            # raw readlink value
    broken_symlink: bool
    mode: int | None                      # e.g. 0o644
    uid: int | None
    gid: int | None
    owner: str | None
    group: str | None
    size: int | None
    sha256: str | None                    # of content (realpath)
    selinux_context: str | None
    readable: bool
    error: str | None = None


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_status: int
    stdout: str
    stderr: str
    duration_ms: int


class RemoteErrorCode(str, enum.Enum):
    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TIMEOUT = "TIMEOUT"
    HOST_KEY_UNKNOWN = "HOST_KEY_UNKNOWN"
    HOST_KEY_MISMATCH = "HOST_KEY_MISMATCH"
    AUTH_REJECTED = "AUTH_REJECTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    HELPER_MISSING = "HELPER_MISSING"
    UNSUPPORTED_OS = "UNSUPPORTED_OS"
    COMMAND_FAILED = "COMMAND_FAILED"
    PATH_NOT_ALLOWED = "PATH_NOT_ALLOWED"
    DISK_FULL = "DISK_FULL"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class RemoteError(Exception):
    def __init__(self, code: RemoteErrorCode, message: str, *, retryable: bool = False, details: dict | None = None):
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details or {}


@dataclass(frozen=True)
class ServiceProbe:
    service: ServiceType
    installed: bool
    version: str | None
    binary: str | None
    running: bool | None
    service_manager: str | None           # "systemd" | "sysv" | "none"


@dataclass(frozen=True)
class HostProbe:
    os_id: str                            # /etc/os-release ID
    os_version: str
    os_pretty: str
    os_family: str                        # "debian" | "rhel" | "other"
    supported: bool
    kernel: str
    remote_user: str
    privilege_mode: str                   # "helper-sudo" | "none"
    helper_version: str | None
    services: tuple[ServiceProbe, ...]


@dataclass(frozen=True)
class EndpointCertResult:
    host: str
    port: int
    sni: str | None
    ok: bool                              # handshake completed and a cert was presented
    leaf: CertInfo | None
    chain: tuple[CertInfo, ...]
    chain_valid: bool | None              # verified against configured trust anchors (None = not checked)
    hostname_matches: bool | None
    error: str | None
    tls_version: str | None


class RemoteHost(Protocol):
    """Implemented by integrations.ssh. All privileged ops go through the remote helper
    (fixed subcommands, argv only — never a shell string)."""

    async def probe(self) -> HostProbe: ...
    async def stat(self, path: str) -> RemoteFileStat: ...
    async def read_public_file(self, path: str, max_bytes: int = 1_048_576) -> bytes: ...   # refuses private keys
    async def backup_file(self, path: str) -> tuple[bytes, RemoteFileStat]: ...           # may include key material
    async def find_cert_files(self, roots: Sequence[str], max_depth: int, max_files: int,
                              exclude: Sequence[str]) -> list[tuple[str, FileKind]]: ...
    async def dump_config(self, service: ServiceType) -> str: ...
    async def free_bytes(self, path: str) -> int: ...
    async def stage_dir(self) -> str: ...
    async def write_staged(self, stage_dir: str, name: str, content: bytes, mode: int) -> RemoteFileStat: ...
    async def install(self, staged_path: str, dest: str, mode: int, owner: str, group: str) -> RemoteFileStat: ...
    async def config_test(self, service: ServiceType) -> CommandResult: ...
    async def reload(self, service: ServiceType, allow_restart: bool = False) -> CommandResult: ...
    async def cleanup(self, stage_dir: str) -> None: ...
    async def close(self) -> None: ...
