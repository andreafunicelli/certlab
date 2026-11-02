"""Step-by-step connection test used by "Test connection" in the UI and by server enrollment."""
from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Awaitable, Callable
from typing import Any

from app.integrations.contracts import HostProbe, RemoteError, RemoteErrorCode
from app.integrations.ssh import hostkeys
from app.integrations.ssh.connection import SSHRemoteHost, _load_key, _open_single
from app.integrations.ssh.errors import classify_exception
from app.integrations.ssh.models import ConnectionStep, ConnectionTestReport, SSHCredential, SSHTarget
from app.integrations.ssh.sanitize import sanitize_output

STEP_NAMES = (
    "DNS resolution",
    "TCP reachability",
    "SSH handshake and host key",
    "Authentication",
    "Remote command execution",
    "Privilege assessment",
    "OS identification",
)


async def test_connection(target: SSHTarget, credential: SSHCredential) -> ConnectionTestReport:
    steps: list[ConnectionStep] = []
    state: dict[str, Any] = {"jump_conn": None, "conn": None, "probe": None}
    first_hop = target.jump or target
    hop_note = f" (bastion {first_hop.host}:{first_hop.port})" if target.jump else ""
    error: RemoteError | None = None

    async def step(name: str, fn: Callable[[], Awaitable[str]], timeout: float) -> bool:
        nonlocal error
        t0 = time.monotonic()
        try:
            detail = await asyncio.wait_for(fn(), timeout=timeout)
            status, ok = "ok", True
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001
            error = classify_exception(exc)
            detail, status, ok = sanitize_output(error.message, 500), "failed", False
        steps.append(ConnectionStep(name, status, detail, int((time.monotonic() - t0) * 1000)))
        return ok

    async def dns() -> str:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(first_hop.host, first_hop.port, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        return f"{first_hop.host} -> {', '.join(addrs)}{hop_note}"

    async def tcp() -> str:
        _, writer = await asyncio.open_connection(first_hop.host, first_hop.port)
        writer.close()
        return f"connected to {first_hop.host}:{first_hop.port}"

    async def handshake() -> str:
        key = _load_key(credential)
        if target.jump is not None:
            state["jump_conn"] = await _open_single(target.jump, key)
        tunnel = state["jump_conn"]
        seen = await hostkeys.scan_host_key(target.host, target.port, target.connect_timeout, tunnel=tunnel)
        if not target.host_public_key:
            raise RemoteError(RemoteErrorCode.HOST_KEY_UNKNOWN,
                              f"no host key enrolled; server presents {seen.key_type} {seen.fingerprint_sha256}")
        enrolled = hostkeys.host_key_info_from_openssh(target.host_public_key)
        if enrolled.fingerprint_sha256 != seen.fingerprint_sha256:
            raise RemoteError(RemoteErrorCode.HOST_KEY_MISMATCH,
                              f"host key changed: enrolled {enrolled.fingerprint_sha256}, "
                              f"server presents {seen.fingerprint_sha256}")
        return f"host key verified ({seen.key_type} {seen.fingerprint_sha256})"

    async def auth() -> str:
        key = _load_key(credential)
        state["conn"] = await _open_single(target, key, tunnel=state["jump_conn"])
        return f"authenticated as {target.username} with public key"

    host = SSHRemoteHost(target, credential)

    async def remote_exec() -> str:
        host._adopt(state["conn"], state["jump_conn"])
        res = await host.run_fixed("id", "-un", idempotent=False)
        if res.exit_status != 0:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "remote command execution failed")
        return f"remote user: {res.stdout.strip()}"

    async def privilege() -> str:
        ver = await host.helper_version()
        return f"{target.privilege_mode}: cdp-helper {ver} available"

    async def os_ident() -> str:
        probe: HostProbe = await host.probe()
        state["probe"] = probe
        if not probe.supported:
            raise RemoteError(RemoteErrorCode.UNSUPPORTED_OS, f"unsupported operating system: {probe.os_pretty or probe.os_id}")
        found = ", ".join(f"{s.service.value} {s.version or ''}".strip() for s in probe.services if s.installed) or "none"
        return f"{probe.os_pretty} (kernel {probe.kernel}); services: {found}"

    plan: list[tuple[str, Callable[[], Awaitable[str]], float]] = [
        (STEP_NAMES[0], dns, target.connect_timeout),
        (STEP_NAMES[1], tcp, target.connect_timeout),
        (STEP_NAMES[2], handshake, target.connect_timeout * (3 if target.jump else 2) + 5),
        (STEP_NAMES[3], auth, target.connect_timeout * 2 + 5),
        (STEP_NAMES[4], remote_exec, target.command_timeout),
        (STEP_NAMES[5], privilege, target.command_timeout),
        (STEP_NAMES[6], os_ident, target.command_timeout),
    ]
    try:
        failed = False
        for name, fn, timeout in plan:
            if failed:
                steps.append(ConnectionStep(name, "skipped", "skipped: a previous step failed", 0))
                continue
            failed = not await step(name, fn, timeout)
    finally:
        await host.close()
        if state["conn"] is not None and host._conn is None:
            state["conn"].close()
        if state["jump_conn"] is not None and host._jump is None:
            state["jump_conn"].close()
    return ConnectionTestReport(
        ok=error is None,
        steps=steps,
        probe=state["probe"],
        error_code=error.code if error else None,
        error_message=sanitize_output(error.message, 500) if error else None,
    )
