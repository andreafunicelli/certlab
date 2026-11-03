"""Client-side argument validation and helper command construction (never builds shell from user input)."""
from __future__ import annotations

import posixpath
import re
import shlex

from app.integrations.contracts import RemoteError, RemoteErrorCode

HELPER_PATH = "/usr/local/libexec/cdp-helper"

SUBCOMMANDS = frozenset({
    "version", "probe", "stat", "read-public", "backup", "find", "dump", "df", "stage-dir",
    "write-staged", "install", "configtest", "reload", "cleanup",
})
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _bad(msg: str) -> RemoteError:
    return RemoteError(RemoteErrorCode.PATH_NOT_ALLOWED, msg)


def validate_path(path: str) -> str:
    """Absolute, no NUL/newline/control chars; returns the normalised path (collapses ./ and ../)."""
    if not isinstance(path, str) or not path:
        raise _bad("path must be a non-empty string")
    if not path.startswith("/"):
        raise _bad("path must be absolute")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise _bad("path contains control characters")
    norm = posixpath.normpath(path)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def validate_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name) or name in (".", ".."):
        raise RemoteError(RemoteErrorCode.PATH_NOT_ALLOWED, "invalid staged file name")
    return name


def validate_account(value: str) -> str:
    if not _ACCOUNT_RE.fullmatch(value):
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "invalid owner/group name")
    return value


def mode_str(mode: int) -> str:
    if not 0 <= mode <= 0o777:
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "invalid mode")
    return format(mode, "04o")


def helper_argv(subcommand: str, *args: str, privilege_mode: str = "helper-sudo") -> tuple[str, ...]:
    if subcommand not in SUBCOMMANDS:
        raise ValueError(f"unknown helper subcommand {subcommand!r}")
    for a in args:
        if "\x00" in a:
            raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "NUL in argument")
    prefix = ("sudo", "-n", HELPER_PATH) if privilege_mode == "helper-sudo" else (HELPER_PATH,)
    return (*prefix, subcommand, *args)


def build_command(argv: tuple[str, ...] | list[str]) -> str:
    """The one place a command string is made: every element is shlex.quote'd."""
    return " ".join(shlex.quote(a) for a in argv)
