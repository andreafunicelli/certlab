"""Host key discovery and strict known-hosts construction."""
from __future__ import annotations

import asyncio
from typing import Any

import asyncssh

from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.integrations.ssh.errors import classify_exception
from app.integrations.ssh.models import HostKeyInfo


def _host_info(key: asyncssh.SSHKey) -> HostKeyInfo:
    openssh = key.export_public_key("openssh").decode().strip()
    openssh = " ".join(openssh.split()[:2])        # drop comment
    return HostKeyInfo(
        key_type=key.get_algorithm(),
        fingerprint_sha256=key.get_fingerprint("sha256"),
        public_key_openssh=openssh,
    )


def host_key_info_from_openssh(public_key_openssh: str) -> HostKeyInfo:
    try:
        return _host_info(asyncssh.import_public_key(public_key_openssh.strip()))
    except Exception as exc:
        raise RemoteError(RemoteErrorCode.HOST_KEY_UNKNOWN, "enrolled host key is not a valid OpenSSH public key") from exc


async def scan_host_key(host: str, port: int, timeout: float, *, tunnel: Any = None) -> HostKeyInfo:
    """Fetch the server's host key WITHOUT authenticating (used for enrollment; the admin must confirm
    the fingerprint out of band). Never use the result to connect automatically."""
    kwargs: dict[str, Any] = {}
    if tunnel is not None:
        kwargs["tunnel"] = tunnel
    try:
        key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port, **kwargs), timeout=timeout)
    except BaseException as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise classify_exception(exc) from exc
    if key is None:
        raise RemoteError(RemoteErrorCode.UNKNOWN, "server did not present a host key")
    return _host_info(key)


def known_hosts_for(host: str, port: int, public_key_openssh: str | None) -> Any:
    """Build an asyncssh known_hosts object trusting exactly the enrolled key for host:port."""
    if not public_key_openssh or not public_key_openssh.strip():
        raise RemoteError(RemoteErrorCode.HOST_KEY_UNKNOWN,
                          "no host key enrolled for this server; scan and confirm the fingerprint first")
    info = host_key_info_from_openssh(public_key_openssh)
    pattern = f"[{host}]:{port}" if (port != 22 or ":" in host) else host
    return asyncssh.import_known_hosts(f"{pattern} {info.public_key_openssh}\n")


def same_key(a_openssh: str, b_openssh: str) -> bool:
    return host_key_info_from_openssh(a_openssh).fingerprint_sha256 == host_key_info_from_openssh(b_openssh).fingerprint_sha256
