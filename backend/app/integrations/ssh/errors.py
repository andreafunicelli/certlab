"""Exception -> RemoteError classification."""
from __future__ import annotations

import asyncio
import errno
import socket

import asyncssh

from app.integrations.contracts import RemoteError, RemoteErrorCode
from app.integrations.ssh.sanitize import sanitize_output

_TIMEOUT_ERRNOS = {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}
_TRANSIENT_ERRNOS = {errno.ECONNRESET, errno.EPIPE, errno.ECONNABORTED}


def classify_exception(exc: BaseException) -> RemoteError:
    """Map low level exceptions to a RemoteError. Never includes secrets (messages are sanitised)."""
    if isinstance(exc, RemoteError):
        return exc
    msg = sanitize_output(str(exc), 300)
    if isinstance(exc, socket.gaierror):
        return RemoteError(RemoteErrorCode.DNS_FAILURE, f"cannot resolve host: {msg}")
    if isinstance(exc, ConnectionRefusedError):
        return RemoteError(RemoteErrorCode.CONNECTION_REFUSED, "connection refused")
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return RemoteError(RemoteErrorCode.TIMEOUT, "operation timed out", retryable=True)
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return RemoteError(RemoteErrorCode.HOST_KEY_MISMATCH, "server host key does not match the enrolled key")
    if isinstance(exc, asyncssh.PermissionDenied):
        return RemoteError(RemoteErrorCode.AUTH_REJECTED, "authentication rejected by server")
    if isinstance(exc, asyncssh.KeyImportError | asyncssh.KeyEncryptionError):
        return RemoteError(RemoteErrorCode.AUTH_REJECTED,
                           "private key could not be loaded (wrong passphrase or malformed key)")
    if isinstance(exc, asyncssh.KeyExchangeFailed):
        if "host key" in str(exc).lower():
            return RemoteError(RemoteErrorCode.HOST_KEY_MISMATCH,
                               "server offers no host key matching the enrolled key")
        return RemoteError(RemoteErrorCode.UNKNOWN, f"key exchange failed: {msg}")
    if isinstance(exc, asyncssh.DisconnectError):
        reason = getattr(exc, "code", None)
        if reason == getattr(asyncssh, "DISC_HOST_KEY_NOT_VERIFIABLE", 9):
            return RemoteError(RemoteErrorCode.HOST_KEY_MISMATCH, "server host key not verifiable")
        if reason in (getattr(asyncssh, "DISC_NO_MORE_AUTH_METHODS_AVAILABLE", 14),
                      getattr(asyncssh, "DISC_ILLEGAL_USER_NAME", 15)):
            return RemoteError(RemoteErrorCode.AUTH_REJECTED, "authentication rejected by server")
        return RemoteError(RemoteErrorCode.UNKNOWN, f"SSH disconnect: {msg}", retryable=True)
    if isinstance(exc, asyncssh.ConnectionLost):
        return RemoteError(RemoteErrorCode.UNKNOWN, "connection lost", retryable=True)
    if isinstance(exc, asyncssh.ChannelOpenError):
        return RemoteError(RemoteErrorCode.UNKNOWN, f"channel open failed: {msg}", retryable=True)
    if isinstance(exc, OSError):
        if exc.errno == errno.ECONNREFUSED:
            return RemoteError(RemoteErrorCode.CONNECTION_REFUSED, "connection refused")
        if exc.errno in _TIMEOUT_ERRNOS:
            return RemoteError(RemoteErrorCode.TIMEOUT, "host unreachable or timed out", retryable=True)
        if exc.errno in _TRANSIENT_ERRNOS:
            return RemoteError(RemoteErrorCode.UNKNOWN, "connection reset", retryable=True)
    return RemoteError(RemoteErrorCode.UNKNOWN, f"{type(exc).__name__}: {msg}")
