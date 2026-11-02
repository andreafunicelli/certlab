"""asyncssh based RemoteHost implementation.

Security properties:
* strict host key verification (known_hosts built from the enrolled key; never ``known_hosts=None``)
* public-key auth only (no password, no kbd-interactive, no agent, no ~/.ssh/config)
* every remote invocation is ``sudo -n /usr/local/libexec/cdp-helper <sub> <args...>`` with each argv
  element passed through ``shlex.quote``; paths are validated client side and again by the helper
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import random
import time
import weakref
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import asyncssh

from app.integrations.contracts import (
    CommandResult,
    FileKind,
    HostProbe,
    RemoteError,
    RemoteErrorCode,
    RemoteFileStat,
    ServiceType,
)
from app.integrations.ssh import parsing
from app.integrations.ssh import paths as P
from app.integrations.ssh.errors import classify_exception
from app.integrations.ssh.hostkeys import host_key_info_from_openssh, known_hosts_for, scan_host_key
from app.integrations.ssh.models import SSHCredential, SSHTarget
from app.integrations.ssh.sanitize import sanitize_output

DEFAULT_MAX_OUTPUT = 16 * 1024 * 1024
DEFAULT_MAX_STDERR = 64 * 1024
MAX_STAGED_BYTES = 10 * 1024 * 1024

# ----------------------------------------------------------------------------- per-host concurrency
_default_limit = 4
_host_limits: dict[str, int] = {}
_semaphores: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]] = (
    weakref.WeakKeyDictionary()
)


def set_host_concurrency_limit(limit: int, host: str | None = None, port: int | None = None) -> None:
    """Configure max concurrent SSH sessions per host:port (default for all, or one specific host)."""
    global _default_limit
    if limit < 1:
        raise ValueError("limit must be >= 1")
    if host is None:
        _default_limit = limit
    else:
        _host_limits[f"{host}:{port if port is not None else 22}"] = limit
    _semaphores.clear()


def _semaphore(target: SSHTarget) -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()   # semaphores must not be shared across event loops (celery asyncio.run)
    per_loop = _semaphores.setdefault(loop, {})
    key = f"{target.host}:{target.port}"
    if key not in per_loop:
        per_loop[key] = asyncio.Semaphore(_host_limits.get(key, _default_limit))
    return per_loop[key]


# ----------------------------------------------------------------------------- connection setup
def _load_key(credential: SSHCredential) -> asyncssh.SSHKey:
    try:
        return asyncssh.import_private_key(credential.private_key_pem, credential.passphrase)
    except Exception as exc:
        raise RemoteError(RemoteErrorCode.AUTH_REJECTED,
                          "private key could not be loaded (wrong passphrase or malformed key)") from exc


async def _open_single(target: SSHTarget, key: asyncssh.SSHKey, tunnel: Any = None) -> asyncssh.SSHClientConnection:
    known_hosts = known_hosts_for(target.host, target.port, target.host_public_key)
    kwargs: dict[str, Any] = {}
    if tunnel is not None:
        kwargs["tunnel"] = tunnel
    try:
        return await asyncssh.connect(
            target.host, target.port,
            username=target.username,
            client_keys=[key],
            known_hosts=known_hosts,
            config=[],                      # ignore ~/.ssh/config
            agent_path=None,
            password=None,
            password_auth=False,
            kbdint_auth=False,
            public_key_auth=True,
            connect_timeout=target.connect_timeout,
            login_timeout=max(target.connect_timeout, 10),
            keepalive_interval=15,
            keepalive_count_max=3,
            **kwargs,
        )
    except BaseException as exc:
        if isinstance(exc, asyncio.CancelledError):
            raise
        err = classify_exception(exc)
        # asyncssh only offers host key algorithms of the enrolled key; a server that has a different key
        # type just drops the connection. Distinguish that from a network flake by looking at the real key.
        if err.code == RemoteErrorCode.UNKNOWN and await _host_key_differs(target, tunnel):
            err = RemoteError(RemoteErrorCode.HOST_KEY_MISMATCH, "server host key does not match the enrolled key")
        raise err from exc


async def _host_key_differs(target: SSHTarget, tunnel: Any) -> bool:
    try:
        seen = await scan_host_key(target.host, target.port, min(target.connect_timeout, 5), tunnel=tunnel)
        return seen.fingerprint_sha256 != host_key_info_from_openssh(target.host_public_key or "").fingerprint_sha256
    except Exception:  # noqa: BLE001 - cannot tell; keep the original classification
        return False


async def open_connection(target: SSHTarget, credential: SSHCredential) -> tuple[asyncssh.SSHClientConnection, Any]:
    """Open (jump +) target connections, both with strict host-key checking. Returns (conn, jump_conn|None)."""
    key = _load_key(credential)
    jump_conn = None
    try:
        if target.jump is not None:
            jump_conn = await _open_single(target.jump, key)
        conn = await _open_single(target, key, tunnel=jump_conn)
    except BaseException:
        if jump_conn is not None:
            jump_conn.close()
        raise
    return conn, jump_conn


class _OutputTooLarge(Exception):
    pass


async def _read_capped(reader: asyncssh.SSHReader, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise _OutputTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


# ----------------------------------------------------------------------------- RemoteHost
class SSHRemoteHost:
    """Implements contracts.RemoteHost over SSH + cdp-helper."""

    def __init__(self, target: SSHTarget, credential: SSHCredential, *, cancel_event: asyncio.Event | None = None,
                 retry_attempts: int = 3, retry_backoff: float = 0.5) -> None:
        self.target = target
        self._credential = credential
        self._cancel_event = cancel_event
        self._attempts = max(1, retry_attempts)
        self._backoff = retry_backoff
        self._conn: asyncssh.SSHClientConnection | None = None
        self._jump: Any = None

    # ---- connection management
    def _adopt(self, conn: asyncssh.SSHClientConnection, jump: Any) -> None:
        self._conn, self._jump = conn, jump

    async def _ensure(self) -> asyncssh.SSHClientConnection:
        self._check_cancel()
        if self._conn is None:
            self._conn, self._jump = await open_connection(self.target, self._credential)
        return self._conn

    def _check_cancel(self) -> None:
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise RemoteError(RemoteErrorCode.CANCELLED, "operation cancelled")

    async def close(self) -> None:
        conns, self._conn, self._jump = [self._conn, self._jump], None, None
        for c in conns:
            if c is not None:
                c.close()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(c.wait_closed(), timeout=5)

    # ---- raw execution
    async def _run(self, argv: tuple[str, ...], stdin: bytes | None, timeout: float,
                   max_out: int, max_err: int) -> CommandResult:
        conn = await self._ensure()
        cmd = P.build_command(argv)
        started = time.monotonic()

        async def work() -> tuple[bytes, bytes, int]:
            proc = await conn.create_process(cmd, encoding=None)
            try:
                if stdin:
                    proc.stdin.write(stdin)
                    await proc.stdin.drain()
                proc.stdin.write_eof()
                out, err = await asyncio.gather(_read_capped(proc.stdout, max_out), _read_capped(proc.stderr, max_err))
                await proc.wait(check=False)
                return out, err, proc.exit_status if proc.exit_status is not None else -1
            finally:
                proc.close()

        task = asyncio.ensure_future(work())
        waiters: set[asyncio.Future[Any]] = {task}
        cancel_task = None
        if self._cancel_event is not None:
            cancel_task = asyncio.ensure_future(self._cancel_event.wait())
            waiters.add(cancel_task)
        try:
            done, _ = await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            task.cancel()
            raise
        finally:
            if cancel_task is not None:
                cancel_task.cancel()
        if task not in done:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
            if cancel_task is not None and cancel_task in done:
                raise RemoteError(RemoteErrorCode.CANCELLED, "operation cancelled")
            raise RemoteError(RemoteErrorCode.TIMEOUT, f"command timed out after {timeout:g}s", retryable=False)
        try:
            out, err, status = task.result()
        except _OutputTooLarge:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "remote output exceeded the size limit") from None
        except BaseException as exc:
            raise classify_exception(exc) from exc
        return CommandResult(
            argv=argv, exit_status=status,
            stdout=out.decode("utf-8", errors="replace"), stderr=err.decode("utf-8", errors="replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    async def _with_retry(self, idempotent: bool, fn: Any) -> Any:
        attempts = self._attempts if idempotent else 1
        for i in range(attempts):
            try:
                return await fn()
            except RemoteError as err:
                if not (idempotent and err.retryable) or i == attempts - 1:
                    raise
                await self.close()      # force a fresh connection on the next attempt
                delay = self._backoff * (2 ** i) * (0.5 + random.random())
                await self._sleep(delay)
        raise AssertionError("unreachable")

    async def _sleep(self, delay: float) -> None:
        if self._cancel_event is None:
            await asyncio.sleep(delay)
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._cancel_event.wait(), timeout=delay)
        self._check_cancel()

    async def _helper(self, sub: str, *args: str, stdin: bytes | None = None, idempotent: bool = False,
                      timeout: float | None = None, max_out: int = DEFAULT_MAX_OUTPUT,
                      allow_exit: tuple[int, ...] = ()) -> CommandResult:
        """Run a helper subcommand; raise RemoteError on failure (except exit codes in allow_exit)."""
        argv = P.helper_argv(sub, *args, privilege_mode=self.target.privilege_mode)

        async def once() -> CommandResult:
            res = await self._run(argv, stdin, timeout or self.target.command_timeout, max_out, DEFAULT_MAX_STDERR)
            if res.exit_status != 0 and res.exit_status not in allow_exit:
                raise parsing.map_failure(res.exit_status, res.stderr)
            return res

        return await self._with_retry(idempotent, once)

    async def _helper_json(self, sub: str, *args: str, **kw: Any) -> dict[str, Any]:
        res = await self._helper(sub, *args, **kw)
        return parsing.parse_json_line(res.stdout)

    async def run_fixed(self, *argv: str, idempotent: bool = True) -> CommandResult:
        """Run an arbitrary but fixed argv (each element quoted). Used only for e.g. ``id -un``."""
        async def once() -> CommandResult:
            return await self._run(tuple(argv), None, self.target.command_timeout, 1024 * 1024, DEFAULT_MAX_STDERR)
        return await self._with_retry(idempotent, once)

    # ---- RemoteHost API
    async def helper_version(self) -> str:
        obj = await self._helper_json("version", idempotent=True)
        return str(obj.get("version", ""))

    async def probe(self) -> HostProbe:
        obj = await self._helper_json("probe", idempotent=True)
        who = await self.run_fixed("id", "-un")
        user = who.stdout.strip() or self.target.username
        return parsing.parse_probe(obj, user, self.target.privilege_mode)

    async def stat(self, path: str) -> RemoteFileStat:
        p = P.validate_path(path)
        return parsing.parse_stat(await self._helper_json("stat", p, idempotent=True))

    async def read_public_file(self, path: str, max_bytes: int = 1_048_576) -> bytes:
        p = P.validate_path(path)
        obj = await self._helper_json("read-public", p, str(int(max_bytes)), idempotent=True,
                                      max_out=int(max_bytes) * 2 + 4096)
        return _b64(obj)

    async def backup_file(self, path: str) -> tuple[bytes, RemoteFileStat]:
        p = P.validate_path(path)
        obj = await self._helper_json("backup", p, idempotent=True, max_out=MAX_STAGED_BYTES * 2 + 8192)
        return _b64(obj), parsing.parse_stat(obj.get("stat") or {})

    async def find_cert_files(self, roots: Sequence[str], max_depth: int, max_files: int,
                              exclude: Sequence[str] = ()) -> list[tuple[str, FileKind]]:
        excl = [P.validate_path(e) for e in exclude]
        found: dict[str, FileKind] = {}
        for root in roots:
            if len(found) >= max_files:
                break
            r = P.validate_path(root)
            try:
                res = await self._helper("find", r, str(int(max_depth)), str(int(max_files) - len(found)),
                                         idempotent=True)
            except RemoteError as err:
                if err.details.get("exit_status") == 12:   # root does not exist on this host
                    continue
                raise
            entries, _ = parsing.parse_find_output(res.stdout)
            for path, kind in entries:
                if any(path == e or path.startswith(e.rstrip("/") + "/") for e in excl):
                    continue
                found.setdefault(path, kind)
        return list(found.items())[:max_files]

    async def dump_config(self, service: ServiceType) -> str:
        res = await self._helper("dump", _svc(service), idempotent=True)
        return res.stdout

    async def free_bytes(self, path: str) -> int:
        obj = await self._helper_json("df", P.validate_path(path), idempotent=True)
        return int(obj["available_bytes"])

    async def stage_dir(self) -> str:
        obj = await self._helper_json("stage-dir")
        return str(obj["stage_dir"])

    async def write_staged(self, stage_dir: str, name: str, content: bytes, mode: int) -> RemoteFileStat:
        if len(content) > MAX_STAGED_BYTES:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "content too large to stage")
        obj = await self._helper_json("write-staged", P.validate_path(stage_dir), P.validate_name(name),
                                      P.mode_str(mode), stdin=base64.b64encode(content) + b"\n")
        return parsing.parse_stat(obj.get("stat") or {})

    async def install(self, staged_path: str, dest: str, mode: int, owner: str, group: str) -> RemoteFileStat:
        obj = await self._helper_json("install", P.validate_path(staged_path), P.validate_path(dest),
                                      P.mode_str(mode), P.validate_account(owner), P.validate_account(group))
        return parsing.parse_stat(obj.get("stat") or {})

    async def config_test(self, service: ServiceType) -> CommandResult:
        return await self._service_action("configtest", _svc(service))

    async def reload(self, service: ServiceType, allow_restart: bool = False) -> CommandResult:
        args = [_svc(service)] + (["--allow-restart"] if allow_restart else [])
        return await self._service_action("reload", *args)

    async def _service_action(self, sub: str, *args: str) -> CommandResult:
        argv = P.helper_argv(sub, *args, privilege_mode=self.target.privilege_mode)
        res = await self._run(argv, None, self.target.command_timeout, 1024 * 1024, DEFAULT_MAX_STDERR)
        if res.exit_status not in (0, 9):
            raise parsing.map_failure(res.exit_status, res.stderr)
        try:
            obj = parsing.parse_json_line(res.stdout)
            output = sanitize_output(str(obj.get("output", "")))
            status = int(obj.get("exit", res.exit_status))
        except RemoteError:
            output, status = sanitize_output(res.stdout + res.stderr), res.exit_status
        return CommandResult(argv=argv, exit_status=status, stdout=output, stderr="", duration_ms=res.duration_ms)

    async def cleanup(self, stage_dir: str) -> None:
        await self._helper_json("cleanup", P.validate_path(stage_dir))


def _svc(service: ServiceType) -> str:
    if service not in (ServiceType.NGINX, ServiceType.APACHE, ServiceType.HAPROXY):
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, f"unsupported service {service!s}")
    return service.value


def _b64(obj: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(str(obj.get("base64", "")), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "helper returned invalid base64") from exc


@asynccontextmanager
async def connect(target: SSHTarget, credential: SSHCredential, *, cancel_event: asyncio.Event | None = None,
                  queue_timeout: float | None = 300, retry_attempts: int = 3) -> AsyncIterator[SSHRemoteHost]:
    """Open a strictly host-key-verified session to ``target`` (via ``target.jump`` if set).

    Holds one slot of the per-host concurrency semaphore for the lifetime of the context.
    """
    sem = _semaphore(target)
    try:
        await asyncio.wait_for(sem.acquire(), timeout=queue_timeout)
    except TimeoutError:
        raise RemoteError(RemoteErrorCode.TIMEOUT, "timed out waiting for a free slot on this host") from None
    host = SSHRemoteHost(target, credential, cancel_event=cancel_event, retry_attempts=retry_attempts)
    try:
        await host._with_retry(True, host._ensure)
        yield host
    finally:
        try:
            await host.close()
        finally:
            sem.release()


