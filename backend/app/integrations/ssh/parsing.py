"""Pure parsing of cdp-helper output and mapping of helper failures to RemoteError (unit-testable)."""
from __future__ import annotations

import json
from typing import Any

from app.integrations.contracts import (
    FileKind,
    HostProbe,
    RemoteError,
    RemoteErrorCode,
    RemoteFileStat,
    ServiceProbe,
    ServiceType,
)
from app.integrations.ssh.sanitize import sanitize_output

SUPPORTED_OS_IDS = frozenset({"ubuntu", "debian", "rhel", "rocky", "almalinux", "ol"})
_DEBIAN_IDS = {"debian", "ubuntu"}
_RHEL_IDS = {"rhel", "rocky", "almalinux", "ol", "centos", "fedora", "amzn"}

# helper "error" codes -> RemoteErrorCode
_HELPER_CODE_MAP = {
    "PATH_NOT_ALLOWED": RemoteErrorCode.PATH_NOT_ALLOWED,
    "PRIVATE_KEY_REFUSED": RemoteErrorCode.PATH_NOT_ALLOWED,
    "SYMLINK_DEST": RemoteErrorCode.PATH_NOT_ALLOWED,
    "PERMISSION_DENIED": RemoteErrorCode.PERMISSION_DENIED,
    "DISK_FULL": RemoteErrorCode.DISK_FULL,
}
_HELPER_EXIT_MAP = {3: "PATH_NOT_ALLOWED", 4: "PERMISSION_DENIED", 5: "PRIVATE_KEY_REFUSED", 6: "DISK_FULL",
                    7: "SYMLINK_DEST"}
_KIND_MAP = {k.value: k for k in FileKind}


def classify_os(os_id: str, os_id_like: str = "") -> tuple[str, bool]:
    oid = (os_id or "").lower()
    likes = set((os_id_like or "").lower().split())
    if oid in _DEBIAN_IDS or "debian" in likes or "ubuntu" in likes:
        family = "debian"
    elif oid in _RHEL_IDS or likes & {"rhel", "fedora", "centos"}:
        family = "rhel"
    else:
        family = "other"
    return family, oid in SUPPORTED_OS_IDS


def parse_helper_error(stderr: str) -> tuple[str | None, str]:
    """Return (helper error code, message) from the last JSON line on stderr, if any."""
    for line in reversed(stderr.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("ok") is False:
                return str(obj.get("error") or ""), str(obj.get("message") or "")
    return None, ""


def map_failure(exit_status: int, stderr: str, argv_desc: str = "") -> RemoteError:
    """Classify a failed `sudo -n cdp-helper ...` invocation."""
    code, message = parse_helper_error(stderr)
    safe = sanitize_output(stderr.strip(), 300)
    if code:
        rc = _HELPER_CODE_MAP.get(code, RemoteErrorCode.COMMAND_FAILED)
        return RemoteError(rc, f"{argv_desc}{message}".strip() or code,
                           details={"helper_error": code, "exit_status": exit_status})
    if exit_status in _HELPER_EXIT_MAP and not safe:
        code = _HELPER_EXIT_MAP[exit_status]
        return RemoteError(_HELPER_CODE_MAP[code], code, details={"helper_error": code, "exit_status": exit_status})
    low = stderr.lower()
    if "no space left" in low:
        return RemoteError(RemoteErrorCode.DISK_FULL, "no space left on device", details={"exit_status": exit_status})
    if ("password is required" in low or "not allowed to execute" in low or "not in the sudoers" in low
            or "may not run sudo" in low or "not allowed to run sudo" in low):
        return RemoteError(RemoteErrorCode.PERMISSION_DENIED,
                           "sudo denied: the account may not run cdp-helper without a password",
                           details={"exit_status": exit_status})
    if exit_status == 127 or "command not found" in low or "no such file or directory" in low:
        return RemoteError(RemoteErrorCode.HELPER_MISSING,
                           "cdp-helper is not installed at /usr/local/libexec/cdp-helper",
                           details={"exit_status": exit_status})
    if "permission denied" in low:
        return RemoteError(RemoteErrorCode.PERMISSION_DENIED, safe or "permission denied",
                           details={"exit_status": exit_status})
    return RemoteError(RemoteErrorCode.COMMAND_FAILED, safe or f"helper exited with status {exit_status}",
                       details={"exit_status": exit_status})


def parse_json_line(stdout: str) -> dict[str, Any]:
    text = stdout.strip()
    if not text:
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "empty helper response")
    try:
        # helper prints exactly one JSON document; tolerate leading noise lines (e.g. sudo/login banners)
        line = text.splitlines()[-1]
        obj = json.loads(line)
    except ValueError as exc:
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "helper returned invalid JSON") from exc
    if not isinstance(obj, dict):
        raise RemoteError(RemoteErrorCode.COMMAND_FAILED, "helper returned unexpected JSON")
    return obj


def parse_stat(obj: dict[str, Any]) -> RemoteFileStat:
    def _i(key: str) -> int | None:
        v = obj.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    return RemoteFileStat(
        path=str(obj.get("path", "")),
        exists=bool(obj.get("exists")),
        file_type=obj.get("file_type"),
        realpath=obj.get("realpath"),
        symlink_target=obj.get("symlink_target"),
        broken_symlink=bool(obj.get("broken_symlink")),
        mode=_i("mode"),
        uid=_i("uid"),
        gid=_i("gid"),
        owner=obj.get("owner"),
        group=obj.get("group"),
        size=_i("size"),
        sha256=obj.get("sha256"),
        selinux_context=obj.get("selinux_context"),
        readable=bool(obj.get("readable")),
        error=obj.get("error"),
    )


_SERVICE_NAMES = {"nginx": ServiceType.NGINX, "apache": ServiceType.APACHE, "haproxy": ServiceType.HAPROXY}


def parse_probe(obj: dict[str, Any], remote_user: str, privilege_mode: str) -> HostProbe:
    os_id = str(obj.get("os_id") or "")
    family, supported = classify_os(os_id, str(obj.get("os_id_like") or ""))
    manager = obj.get("service_manager")
    services: list[ServiceProbe] = []
    for s in obj.get("services", []):
        st = _SERVICE_NAMES.get(str(s.get("name")))
        if st is None:
            continue
        services.append(ServiceProbe(
            service=st,
            installed=bool(s.get("installed")),
            version=s.get("version") or None,
            binary=s.get("binary") or None,
            running=s.get("running") if isinstance(s.get("running"), bool) else None,
            service_manager=manager if isinstance(manager, str) else None,
        ))
    return HostProbe(
        os_id=os_id,
        os_version=str(obj.get("os_version") or ""),
        os_pretty=str(obj.get("os_pretty") or ""),
        os_family=family,
        supported=supported,
        kernel=str(obj.get("kernel") or ""),
        remote_user=remote_user,
        privilege_mode="helper-sudo" if privilege_mode == "helper-sudo" else "none",
        helper_version=obj.get("helper_version"),
        services=tuple(services),
    )


def parse_find_output(stdout: str) -> tuple[list[tuple[str, FileKind]], bool]:
    """Parse JSON-lines from `find`; returns (entries, truncated)."""
    entries: list[tuple[str, FileKind]] = []
    truncated = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("done"):
            truncated = bool(obj.get("truncated"))
        elif "path" in obj:
            entries.append((str(obj["path"]), _KIND_MAP.get(str(obj.get("kind")), FileKind.UNKNOWN)))
    return entries, truncated
