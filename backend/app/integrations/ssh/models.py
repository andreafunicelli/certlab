"""Data types for the SSH layer. RemoteHost-level types live in app.integrations.contracts."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.integrations.contracts import HostProbe, RemoteErrorCode


@dataclass(frozen=True)
class SSHTarget:
    host: str
    port: int
    username: str
    host_public_key: str | None          # enrolled OpenSSH public key line; None => HOST_KEY_UNKNOWN
    connect_timeout: float = 10
    command_timeout: float = 60
    jump: SSHTarget | None = None      # bastion; same credential is used, host key is also strict
    privilege_mode: str = "helper-sudo"  # "helper-sudo" (sudo -n helper) | "helper-direct" (already root)


@dataclass(frozen=True)
class SSHCredential:
    private_key_pem: bytes = field(repr=False)
    passphrase: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class HostKeyInfo:
    key_type: str
    fingerprint_sha256: str              # "SHA256:<base64>" exactly like ssh-keygen -lf
    public_key_openssh: str              # "ssh-ed25519 AAAA..." (no comment)


@dataclass(frozen=True)
class ConnectionStep:
    name: str
    status: str                          # "ok" | "failed" | "skipped"
    detail: str
    duration_ms: int


@dataclass(frozen=True)
class ConnectionTestReport:
    ok: bool
    steps: list[ConnectionStep]
    probe: HostProbe | None
    error_code: RemoteErrorCode | None
    error_message: str | None
