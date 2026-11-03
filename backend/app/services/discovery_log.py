"""Discovery job timeline: ordered steps + a capped, sanitized log, persisted progressively.

``JobRecorder`` is deliberately independent of the database: the caller supplies a ``sink(steps, log)`` that persists
a snapshot (``execute_job`` commits it on the job row) so a page reload shows progress. Every string that enters the
recorder is passed through the SSH output sanitizer (no PEM blocks, no long base64 runs).
"""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from app.core.logging import get_logger
from app.integrations.ssh.sanitize import sanitize_output
from app.models.base import utcnow

log = get_logger(__name__)

STEP_STATUSES = ("pending", "running", "ok", "warning", "failed", "skipped")
LOG_HEAD, LOG_TAIL = 450, 49          # + 1 truncation marker = 500 entries at most
MAX_MESSAGE, MAX_DETAIL_STR, MAX_DETAIL_ITEMS = 600, 300, 50

STEP_LABELS = {
    "connect": "Connect over SSH", "probe": "Probe host", "service:nginx": "Read nginx configuration",
    "service:apache": "Read Apache configuration", "service:haproxy": "Read HAProxy configuration",
    "resolve": "Resolve referenced files", "filesystem_scan": "Scan filesystem", "parse": "Parse certificates",
    "inventory": "Update inventory", "finalize": "Finalize",
}

_GENERIC_HINT = "Check the job log for details; if it keeps failing, test the connection from the server page"
HINTS: dict[str, str] = {
    "HOST_KEY_UNKNOWN": "Enroll the host key on the server page",
    "HOST_KEY_MISMATCH": "The server's host key changed. Verify it out-of-band, then re-enroll",
    "AUTH_REJECTED": "Check the SSH username and credential, and authorized_keys on the server",
    "CONNECTION_REFUSED": "Check that sshd is running and that the hostname/address and SSH port are correct",
    "TIMEOUT": "Check network reachability, firewalls and the SSH port; raise the connect timeout in settings if needed",
    "DNS_FAILURE": "Check that the hostname resolves from the Cert Deploy Pro host, or set the server address",
    "HELPER_MISSING": "Install the helper on the target: run install.sh and the sudoers drop-in (see docs/ssh-permissions.md)",
    "PERMISSION_DENIED": "The service account may not run the helper: check the sudoers rule (see docs/ssh-permissions.md)",
    "UNSUPPORTED_OS": "This operating system is not supported by the helper (see docs/ssh-permissions.md)",
    "PATH_NOT_ALLOWED": "Add the path to ALLOWED_ROOTS in /etc/cdp-helper.conf on the server",
    "DISCOVERY_SERVER_HAS_NO_CREDENTIAL": "Assign an SSH credential to the server",
    "DISCOVERY_AUTHORIZATION_REVOKED": "The requesting user lost the discovery permission; run it again with an authorized account",
    "DISCOVERY_SERVER_DISABLED": "Enable the server and run discovery again",
    "DISCOVERY_TIMEOUT": "Discovery exceeded its time limit; reduce the discovery roots or max files in settings",
    "DISCOVERY_ABANDONED": "The worker stopped reporting progress; run discovery again",
    "DISCOVERY_QUEUE_UNAVAILABLE": "The job queue is unavailable; check Redis and the worker, then retry",
}


def hint_for(code: str | None) -> str | None:
    if not code:
        return None
    return HINTS.get(code, _GENERIC_HINT)


def clean(obj: Any, _depth: int = 0) -> Any:
    """Sanitize arbitrary detail structures (strings stripped of PEM/base64, containers bounded)."""
    if _depth > 5:
        return "[truncated]"
    if isinstance(obj, str):
        return sanitize_output(obj, MAX_DETAIL_STR)
    if isinstance(obj, bool) or obj is None or isinstance(obj, int | float):
        return obj
    if isinstance(obj, dict):
        return {str(k)[:64]: clean(v, _depth + 1) for k, v in list(obj.items())[:MAX_DETAIL_ITEMS]}
    if isinstance(obj, list | tuple | set | frozenset):
        items = list(obj)
        out = [clean(v, _depth + 1) for v in items[:MAX_DETAIL_ITEMS]]
        if len(items) > MAX_DETAIL_ITEMS:
            out.append(f"... {len(items) - MAX_DETAIL_ITEMS} more")
        return out
    return sanitize_output(str(obj), MAX_DETAIL_STR)


class JobRecorder:
    def __init__(self, job_id: Any = None, sink: Callable[[list[dict], list[dict]], None] | None = None,
                 publish: Callable[[dict[str, Any]], None] | None = None):
        self.job_id = job_id
        self.sink = sink
        self.publish = publish
        self.autoflush = True
        self.steps: list[dict[str, Any]] = []
        self._t0: dict[str, float] = {}
        self._head: list[dict[str, Any]] = []
        self._tail: list[dict[str, Any]] = []
        self._dropped = 0

    # ------------------------------------------------------------------------------------------ steps
    def _find(self, name: str) -> dict[str, Any] | None:
        return next((s for s in self.steps if s["name"] == name), None)

    def add_step(self, name: str, label: str | None = None, *, status: str = "pending", before: str | None = None,
                 detail: dict[str, Any] | None = None) -> dict[str, Any]:
        existing = self._find(name)
        if existing is not None:
            return existing
        step = {"name": name, "label": label or STEP_LABELS.get(name, name), "status": status, "started_at": None,
                "finished_at": None, "duration_ms": None, "detail": clean(detail or {}), "error_code": None}
        idx = next((i for i, s in enumerate(self.steps) if s["name"] == before), len(self.steps)) if before else len(self.steps)
        self.steps.insert(idx, step)
        return step

    def plan(self, *names: str) -> None:
        for n in names:
            self.add_step(n)

    def start(self, name: str, label: str | None = None, **detail: Any) -> None:
        step = self.add_step(name, label)
        step["status"], step["started_at"] = "running", utcnow().isoformat()
        step["detail"].update(clean(detail))
        self._t0[name] = time.monotonic()
        self._changed(step)

    def finish(self, name: str, status: str = "ok", *, error_code: str | None = None, **detail: Any) -> None:
        step = self.add_step(name)
        t0 = self._t0.pop(name, None)
        now = utcnow()
        if step["started_at"] is None:
            step["started_at"] = now.isoformat()
        step["status"], step["finished_at"], step["error_code"] = status, now.isoformat(), error_code
        step["duration_ms"] = int((time.monotonic() - t0) * 1000) if t0 is not None else 0
        step["detail"].update(clean(detail))
        if status in ("failed", "warning") and error_code:
            step["detail"].setdefault("hint", hint_for(error_code))
        self._changed(step)

    def skip(self, name: str, reason: str, label: str | None = None, before: str | None = None) -> None:
        step = self.add_step(name, label, before=before)
        step["status"], step["detail"]["reason"] = "skipped", clean(reason)
        self._changed(step)

    def detail(self, name: str, **detail: Any) -> None:
        self.add_step(name)["detail"].update(clean(detail))

    def running(self) -> str | None:
        return next((s["name"] for s in self.steps if s["status"] == "running"), None)

    def fail_current(self, code: str, message: str) -> None:
        """Mark the running step (or the first pending one) failed, and skip everything after it."""
        name = self.running() or next((s["name"] for s in self.steps if s["status"] == "pending"), None) or "finalize"
        self.finish(name, "failed", error_code=code, message=message)
        self.error(name, message, {"error_code": code, "hint": hint_for(code)})
        for s in self.steps:
            if s["status"] == "pending":
                s["status"], s["detail"]["reason"] = "skipped", "not reached: an earlier step failed"
        self.flush()

    # ------------------------------------------------------------------------------------------ log
    def add_log(self, level: str, step: str | None, message: str, details: dict[str, Any] | None = None) -> None:
        entry = {"ts": utcnow().isoformat(), "level": level, "step": step,
                 "message": sanitize_output(str(message), MAX_MESSAGE), "details": clean(details) if details else {}}
        if len(self._head) < LOG_HEAD:
            self._head.append(entry)
        else:
            self._tail.append(entry)
            if len(self._tail) > LOG_TAIL:
                self._tail.pop(0)
                self._dropped += 1
        if self.publish is not None:
            self.publish({"type": "log", "entry": entry})

    def info(self, step: str | None, message: str, details: dict[str, Any] | None = None) -> None:
        self.add_log("info", step, message, details)

    def warning(self, step: str | None, message: str, details: dict[str, Any] | None = None) -> None:
        self.add_log("warning", step, message, details)

    def error(self, step: str | None, message: str, details: dict[str, Any] | None = None) -> None:
        self.add_log("error", step, message, details)

    @property
    def entries(self) -> list[dict[str, Any]]:
        if not self._dropped:
            return list(self._head) + list(self._tail)
        marker = {"ts": self._tail[0]["ts"] if self._tail else utcnow().isoformat(), "level": "warning", "step": None,
                  "message": f"log truncated: {self._dropped} entries omitted", "details": {"omitted": self._dropped}}
        return [*self._head, marker, *self._tail]

    @property
    def warnings_count(self) -> int:
        return sum(1 for s in self.steps if s["status"] == "warning")

    # ------------------------------------------------------------------------------------------ persistence
    def _changed(self, step: dict[str, Any]) -> None:
        if self.publish is not None:
            self.publish({"type": "step", "step": step})
        if self.autoflush:
            self.flush()

    def flush(self) -> None:
        if self.sink is None:
            return
        try:
            self.sink([dict(s, detail=dict(s["detail"])) for s in self.steps], self.entries)
        except Exception as exc:  # noqa: BLE001 - progress persistence must never break the job
            log.warning("discovery_progress_flush_failed", error=type(exc).__name__)
