"""Deployment engine: per-target state machine, strategy scheduler, verified rollback, crash reconciliation.

Safety invariants
-----------------
* Nothing on a remote host is modified before a *verified* central backup of every file to change exists.
* The persisted target status is committed BEFORE the first mutating call (``activating``) so a worker that dies
  mid-flight is reconciled on resume: the remote fingerprints are compared with the backup ("previous") and the
  staged ("new") content; all-new -> continue with config test / reload / verification, anything else -> verified
  rollback. Destructive steps are never repeated blindly.
* A rollback only counts when the restored files hash to the backup, the config test passes and (when the endpoint
  was reachable before) the previously served certificate is served again - otherwise the target becomes
  ``manual_intervention_required`` and ``rollback.failed`` is notified.
* Locks (``locks.py``) are held for the whole target lifecycle and released in ``finally``.

Job status while running is ``activating`` (the schema has no generic "running"); targets move through
backing_up -> staging -> validating -> activating -> reloading -> verifying -> completed (or rolling_back ->
rolled_back / manual_intervention_required, failed, cancelled).
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import posixpath
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.core.errors import AppError
from app.core.logging import get_logger, redact
from app.core.permissions import authorize
from app.integrations.certificates import key_matches_cert, parse_pem_certificates
from app.integrations.certificates.errors import CertificateError
from app.integrations.contracts import RemoteError
from app.integrations.services.adapters import ArtifactKind, get_adapter
from app.models import (
    Backup,
    Certificate,
    CertificateInstallation,
    CertificateVersion,
    DeploymentJob,
    DeploymentTarget,
    Environment,
    Server,
    User,
)
from app.models.base import utcnow
from app.services import audit, backups, locks
from app.services import deployment_planner as planner
from app.services import settings as settings_service
from app.services.cert_status import compute_status

log = get_logger(__name__)

FINAL_TARGET = planner.FINAL_TARGET_STATUSES
MUTATING_STATES = frozenset({"activating", "reloading", "verifying", "rolling_back"})
PRE_MUTATION_STATES = frozenset({"pending", "preflight", "backing_up", "staging", "validating"})
ACTOR = "deployment-engine"
FINALIZE_ATTEMPTS = 3
FINALIZE_RETRY_DELAY = 0.5
STATE_KEYS = ("stage_dir", "staged", "expected", "activated", "reload_started")
RESTORABLE_TARGET_STATES = frozenset({"completed", "manual_intervention_required", "failed"})
RESTORE_VERIFY_ATTEMPTS = 5
RESTORE_VERIFY_DELAY = 1.0

# Test seam: replaced by tests to inject a fault-injecting host wrapper.
HOST_FACTORY: planner.HostFactory | None = None


class DeployError(Exception):
    def __init__(self, code: str, message: str, **details: Any):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.details = code, message, details


class Cancelled(Exception):
    pass


class JobBusy(Exception):
    """Another live worker is running this job."""


def _ensure_locks(held: locks.LockSet) -> None:
    if held.lost:
        raise DeployError("LOCK_LOST", "a deployment lock was lost (heartbeat failed); stopping before the next change")


def classify(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, DeployError):
        return exc.code, exc.message
    if isinstance(exc, AppError):
        return exc.code, exc.message
    if isinstance(exc, RemoteError):
        return exc.code.value, exc.message
    if isinstance(exc, locks.LockHeld):
        return "LOCK_HELD", f"another deployment or restore holds a lock on this target ({exc.resource_key.split(':', 1)[-1]})"
    return "INTERNAL_ERROR", f"unexpected error ({type(exc).__name__})"


def _clip(text: str, n: int = 500) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


def _now() -> str:
    return utcnow().isoformat()


def check_staged(art: planner.ArtifactSet, contents: dict[str, tuple[ArtifactKind, bytes]]) -> None:
    """Local validation of the exact bytes about to be installed (module-level so tests can stub it)."""
    for path, (kind, data) in contents.items():
        if kind in (ArtifactKind.CERT, ArtifactKind.FULLCHAIN, ArtifactKind.COMBINED):
            certs = parse_pem_certificates(data)
            if not certs or certs[0].fingerprint_sha256 != art.leaf.fingerprint_sha256:
                raise DeployError("STAGED_CERT_MISMATCH", f"staged content for {path} does not start with the new leaf")
        if kind in (ArtifactKind.KEY, ArtifactKind.COMBINED) and b"PRIVATE KEY" in data:
            try:
                if not key_matches_cert(data, None, art.leaf):
                    raise DeployError("STAGED_KEY_MISMATCH", f"the staged private key for {path} does not match the new certificate")
            except CertificateError as exc:
                raise DeployError("STAGED_KEY_INVALID", f"the staged private key for {path} is unusable") from exc


# =========================================================================== unit runner
class UnitRunner:
    """Runs one deployment unit: a primary target plus targets that share files with it (same server)."""

    def __init__(self, job_id: uuid.UUID, target_ids: list[uuid.UUID], factory: planner.HostFactory, owner: str,
                 revoked: dict[str, Any] | None = None):
        self.job_id, self.target_ids, self.factory, self.owner = job_id, target_ids, factory, owner
        # Set when the initiating user lost the right to continue: the unit may only be brought back to its previous
        # state (safety recovery) and never moves forward.
        self.revoked = revoked
        self.db: Session = SessionLocal()
        self.job = self.db.get(DeploymentJob, job_id)
        self.targets = [self.db.get(DeploymentTarget, i) for i in target_ids]
        self.primary = self.targets[0]
        self.server = self.db.get(Server, self.primary.server_id)
        self.installs = {t.id: (self.db.get(CertificateInstallation, t.installation_id) if t.installation_id else None)
                         for t in self.targets}
        self.strategy = self.job.strategy or {}
        self.host = None
        self.steps: list[dict[str, Any]] = copy.deepcopy(self.primary.steps or [])
        self.state: dict[str, Any] = {k: copy.deepcopy(v) for k, v in (self.primary.meta or {}).items() if k in STATE_KEYS}
        self.anchors = (settings_service.get_section_data(self.db, "security").get("trust_anchors_pem") or "").encode() or None
        self.locks: locks.LockSet | None = None
        env = self.db.scalar(select(Environment).where(Environment.name == self.server.environment))
        self.strict_chain = bool(env is not None and env.require_trusted_chain)      # K8
        self.verification: dict[str, Any] | None = None

    # ------------------------------------------------------------------ persistence helpers
    def _flush(self) -> None:
        for t in self.targets:
            t.steps = copy.deepcopy(self.steps)
            tm = dict(t.meta or {})
            for k in STATE_KEYS:
                if k in self.state:
                    tm[k] = self.state[k]
                else:
                    tm.pop(k, None)
            t.meta = tm
        self.db.commit()

    def _publish(self, type_: str, **payload: Any) -> None:
        try:
            from app.services.events import publish_job_event

            publish_job_event("deployment", self.job_id, {"type": type_, "target_id": str(self.primary.id),
                                                          "target_ids": [str(t.id) for t in self.targets], **payload})
        except Exception:  # noqa: BLE001, S110 - progress events are advisory
            pass

    def note(self, message: str, level: str = "info") -> None:
        entry = {"ts": _now(), "level": level, "message": _clip(str(redact(message)), 400)}
        for t in self.targets:
            t.log = [*(t.log or [])[-499:], entry]

    def set_status(self, status: str, step: str | None = None, *, error: tuple[str, str] | None = None) -> None:
        for t in self.targets:
            before = t.status
            t.status = status
            t.current_step = step
            if error is not None:
                t.error_code, t.error_message = error[0], _clip(str(redact(error[1])), 1000)
            audit.record(self.db, action="DEPLOYMENT_TARGET_STATE", resource_type="deployment_target", resource_id=t.id,
                         actor_name=ACTOR, before={"status": before},
                         after={"status": status, "step": step, "job_id": str(self.job_id), **(
                             {"error_code": error[0]} if error else {})},
                         outcome="failure" if status in ("failed", "manual_intervention_required") else "success")
        self._flush()
        self._publish("target.status", status=status, step=step, error_code=error[0] if error else None)

    @contextlib.asynccontextmanager
    async def step(self, name: str, status: str | None = None):
        st: dict[str, Any] = {"name": name, "status": "running", "started_at": _now(), "finished_at": None,
                              "detail": {}, "error_code": None}
        self.steps.append(st)
        if status:
            self.set_status(status, name)
        else:
            for t in self.targets:
                t.current_step = name
            self._flush()
        self._publish("target.step", step=name, step_status="running")
        try:
            yield st
        except BaseException as exc:
            st["status"] = "failed"
            st["finished_at"] = _now()
            if isinstance(exc, Exception):
                code, msg = classify(exc)
                st["error_code"], st["detail"]["error"] = code, _clip(str(redact(msg)))
                self.note(f"step {name} failed: {code}: {msg}", "error")
            else:
                st["detail"]["error"] = f"interrupted ({type(exc).__name__})"
            st["detail"] = redact(st["detail"])
            with contextlib.suppress(Exception):
                self._flush()
                self._publish("target.step", step=name, step_status="failed", error_code=st["error_code"])
            raise
        else:
            st["status"] = "ok"
            st["finished_at"] = _now()
            st["detail"] = redact(st["detail"])
            self._flush()
            self._publish("target.step", step=name, step_status="ok")

    # ------------------------------------------------------------------ checkpoints
    def checkpoint(self, name: str) -> None:
        self.db.refresh(self.job)
        if self.job.cancel_requested:
            self.note(f"cancellation honoured at checkpoint '{name}'")
            raise Cancelled()
        self.authorize()
        self.ensure_locks()

    def ensure_locks(self) -> None:
        """K6: a lost lock (heartbeat renewal failed) means another worker may now touch the same files."""
        if self.locks is not None:
            _ensure_locks(self.locks)

    def authorize(self) -> None:
        user = self.db.get(User, self.job.initiated_by) if self.job.initiated_by else None
        if user is None or not user.enabled:
            raise DeployError("AUTHZ", "the initiating user no longer exists or is disabled")
        try:
            authorize(user, "deployments:create")
        except AppError as exc:
            raise DeployError("AUTHZ", exc.message) from exc

    # ------------------------------------------------------------------ plan data
    def file_specs(self) -> list[dict[str, Any]]:
        """Union (by realpath) of the files to write for all targets of the unit, key files first."""
        seen: dict[str, dict[str, Any]] = {}
        for t in self.targets:
            for f in (t.meta or {}).get("files", []):
                if f.get("action") == "replace":
                    seen.setdefault(f["realpath"], f)
        return sorted(seen.values(), key=lambda f: (f["artifact"] != "key", f["dest_path"]))

    def service_types(self) -> list[str]:
        return sorted({i.service_type for i in self.installs.values() if i is not None})

    def lock_keys(self) -> list[str]:
        sid = self.server.id
        return [locks.file_key(sid, f["realpath"]) for f in self.file_specs()] + [
            locks.service_key(sid, s) for s in self.service_types()]

    def endpoints(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in self.targets:
            for ep in (t.meta or {}).get("verify_endpoints", []):
                if ep not in out:
                    out.append(ep)
        return out

    # ------------------------------------------------------------------ main entry
    async def run(self) -> str:
        try:
            return await self._run()
        finally:
            with contextlib.suppress(Exception):
                self.db.close()

    async def _run(self) -> str:
        if self.primary.status in FINAL_TARGET:
            return self.primary.status
        resume = self.primary.status in MUTATING_STATES or bool(self.revoked and self.state.get("activated"))
        if self.revoked and not resume:
            # never started mutating: nothing to recover, and a revoked user must not start it now
            self.set_status("cancelled", None, error=("AUTHZ", self.revoked["message"]))
            return "cancelled"
        stack = AsyncExitStack()
        try:
            try:
                if not resume:
                    self.checkpoint("start")
                async with self.step("connect"):
                    self.host = await stack.enter_async_context(self.factory(self.server))
                async with self.step("lock") as st:
                    ls = locks.LockSet(self.lock_keys(), owner=self.owner, job_id=self.job_id,
                                       target_id=self.primary.id)
                    try:
                        await stack.enter_async_context(ls)
                        self.locks = ls
                    except locks.LockHeld as exc:
                        raise DeployError("LOCK_HELD", f"another deployment holds a lock on this target ({exc.resource_key.split(':', 1)[-1]})") from exc
                    st["detail"]["keys"] = len(ls.keys)
                if resume:
                    return await self._resume()
                return await self._fresh()
            except Cancelled:
                await self._cleanup_stage()
                self.set_status("cancelled", None, error=("CANCELLED", "cancelled by user before any change was made"))
                return "cancelled"
            except Exception as exc:  # noqa: BLE001
                code, msg = classify(exc)
                if resume:
                    # remote state of an interrupted mutation cannot be established: a human must look
                    self.set_status("manual_intervention_required", None,
                                    error=("RECONCILE_FAILED", f"interrupted deployment could not be reconciled: {code}: {msg}"))
                    self._notify("rollback.failed", "critical", {"reason": "RECONCILE_FAILED", "message": _clip(msg, 300)})
                    self._after_final("manual_intervention_required")
                    return "manual_intervention_required"
                # pre-mutation failure: nothing was changed on the host
                await self._cleanup_stage()
                if self.state.get("activated"):
                    # files were replaced and neither verification nor rollback ran to a result: a human must look (K2)
                    self.set_status("manual_intervention_required", None, error=(
                        code, f"unexpected error after files were replaced: {msg}"))
                    self._notify("rollback.failed", "critical", {"reason": code, "message": _clip(msg, 300)})
                    self._after_final("manual_intervention_required")
                    return "manual_intervention_required"
                self.set_status("failed", None, error=(code, msg))
                self._after_final("failed")
                return "failed"
        finally:
            with contextlib.suppress(Exception):
                await stack.aclose()

    # ------------------------------------------------------------------ fresh run
    async def _fresh(self) -> str:
        host = self.host
        art = planner.load_artifacts(self.db, self.db.get(CertificateVersion, self.job.version_id))
        specs = self.file_specs()
        if not specs:
            raise DeployError("NOTHING_TO_DEPLOY", "no files to write for this target")

        # ----- current state must equal what was planned
        async with self.step("recheck") as st:
            for f in specs:
                cur = await host.stat(f["dest_path"])
                if not cur.exists or cur.sha256 != f["current_sha256"]:
                    raise DeployError("FILE_CHANGED_SINCE_PREFLIGHT", f"{f['dest_path']} changed since the pre-flight check")
            st["detail"]["files"] = len(specs)

        self.checkpoint("before_backup")
        async with self.step("backup", "backing_up") as st:
            backup = await backups.create_backup(
                self.db, host, server_id=self.server.id, installation_id=self.primary.installation_id,
                target_id=self.primary.id, paths=[f["dest_path"] for f in specs])
            for t in self.targets:
                t.backup_id = backup.id
            by_path = {e["path"]: e for e in backup.manifest["files"]}
            for f in specs:
                if by_path[f["dest_path"]]["sha256"] != f["current_sha256"]:
                    raise DeployError("FILE_CHANGED_SINCE_PREFLIGHT", f"{f['dest_path']} changed while it was backed up")
            st["detail"].update({"backup_id": str(backup.id), "files": len(specs), "verified": backup.verified})
            if not backup.verified:
                raise DeployError("BACKUP_FAILED", "backup could not be verified")

        # ----- stage
        async with self.step("stage", "staging") as st:
            existing_key = None
            if any(f["artifact"] == "combined" for f in specs) and art.reuses_existing_key:
                for e in backup.manifest["files"]:
                    if any(f["dest_path"] == e["path"] and f["artifact"] == "combined" for f in specs):
                        from app.integrations.certificates import load_private_key

                        existing_key = load_private_key(backups.load_file_content(e, self.db), None)[0]
                        break
            contents: dict[str, tuple[ArtifactKind, bytes]] = {}
            for f in specs:
                kind = ArtifactKind(f["artifact"])
                data = planner.render(kind, art, existing_key)
                if planner.sha256(data) != f["new_sha256"]:
                    raise DeployError("PLAN_CONTENT_MISMATCH", f"content for {f['dest_path']} differs from the plan")
                contents[f["dest_path"]] = (kind, data)
            stage = await host.stage_dir()
            self.state["stage_dir"] = stage
            self.state["expected"] = {f["dest_path"]: f["new_sha256"] for f in specs}
            self.state["staged"] = {}
            self._flush()
            for i, f in enumerate(specs):
                name = f"{i:02d}-{f['artifact']}.pem"
                stat = await host.write_staged(stage, name, contents[f["dest_path"]][1], 0o600)
                if stat.sha256 != f["new_sha256"]:
                    raise DeployError("STAGED_HASH_MISMATCH", f"staged copy of {f['dest_path']} does not match the expected hash")
                self.state["staged"][f["dest_path"]] = posixpath.join(stage, name)
            st["detail"]["files"] = len(specs)
            self._flush()

        async with self.step("validate", "validating") as st:
            check_staged(art, contents)
            st["detail"]["checks"] = ["leaf fingerprint", "key matches certificate", "staged sha256"]

        self.checkpoint("before_activation")
        return await self._activate_and_verify(specs, art, skip_install=False)

    # ------------------------------------------------------------------ activation .. verification
    async def _activate_and_verify(self, specs: list[dict[str, Any]], art: planner.ArtifactSet, *, skip_install: bool) -> str:
        host = self.host
        if self.revoked:
            raise DeployError("AUTHZ_REVOKED", "the initiating user was revoked: the deployment must not continue forward")
        try:
            if not skip_install:
                self.set_status("activating", "activate")
                async with self.step("activate") as st:
                    done = []
                    for f in specs:
                        self.ensure_locks()
                        res = await host.install(self.state["staged"][f["dest_path"]], f["dest_path"], int(f["mode"]),
                                                 f["owner"], f["group"])
                        if res.sha256 != f["new_sha256"]:
                            raise DeployError("INSTALL_HASH_MISMATCH", f"{f['dest_path']} does not hash to the new content after install")
                        done.append(f["dest_path"])
                        self.state["activated"] = list(done)
                        self._flush()
                    st["detail"]["installed"] = done
            async with self.step("config_test", "activating") as st:
                for svc in self.service_types():
                    res = await get_adapter(svc).config_test(host)
                    st["detail"][svc] = _clip(res.stdout or "", 300)
                    if res.exit_status != 0:
                        raise DeployError("CONFIG_TEST_FAILED", f"{svc} rejected the new configuration: {_clip(res.stdout or '', 300)}")
            self.ensure_locks()
            async with self.step("reload", "reloading") as st:
                self.state["reload_started"] = True
                self._flush()
                for svc in self.service_types():
                    self.ensure_locks()
                    res = await get_adapter(svc).reload(host, bool(self.strategy.get("allow_restart")))
                    st["detail"][svc] = _clip(res.stdout or "", 300)
                    if res.exit_status != 0:
                        raise DeployError("RELOAD_FAILED", f"{svc} reload failed: {_clip(res.stdout or '', 300)}")
            async with self.step("verify", "verifying") as st:
                verification = await self._verify_new(specs, art)
                st["detail"].update({"mode": verification["mode"]})
                self.verification = verification
                for t in self.targets:
                    t.verification = verification
        except Exception as exc:  # noqa: BLE001 - from here on files may have been replaced: roll back
            code, msg = classify(exc)
            return await self._rollback(DeployError(code, msg))
        return await self._complete(art)

    async def _probe(self, ep: dict[str, Any]):
        from app.integrations.tls.probe import probe_endpoint

        return await probe_endpoint(ep["host"], ep["port"], ep.get("sni"), 5.0, trust_anchors_pem=self.anchors,
                                    expected_hostname=ep.get("sni"))

    async def _verify_new(self, specs: list[dict[str, Any]], art: planner.ArtifactSet) -> dict[str, Any]:
        expected_fp = art.leaf.fingerprint_sha256
        retries = int(self.strategy.get("verify_retries", 5))
        delay = float(self.strategy.get("verify_delay_seconds", 1.5))
        allow_file_only = bool(self.strategy.get("allow_file_only_verification"))
        rows: list[dict[str, Any]] = []
        for ep in self.endpoints():
            row: dict[str, Any] = {"host": ep["host"], "port": ep["port"], "sni": ep.get("sni"), "attempts": 0}
            for attempt in range(1, retries + 1):
                row["attempts"] = attempt
                res = await self._probe(ep)
                row.update({"reachable": res.ok, "error": res.error, "chain_valid": res.chain_valid,
                            "hostname_matches": res.hostname_matches,
                            "served_fingerprint": res.leaf.fingerprint_sha256 if res.leaf else None})
                if res.ok and res.leaf.fingerprint_sha256 == expected_fp:
                    break
                if attempt < retries:
                    await asyncio.sleep(delay)
            rows.append(row)
        mode = "live"
        for row in rows:
            if not row.get("reachable"):
                if not allow_file_only:
                    raise DeployError("VERIFY_UNREACHABLE", f"verification endpoint {row['host']}:{row['port']} is unreachable: {row.get('error')}")
                mode = "file_only"
                row["file_only"] = True
            elif row["served_fingerprint"] != expected_fp:
                raise DeployError("VERIFY_FINGERPRINT_MISMATCH",
                                  f"{row['host']}:{row['port']} serves {row['served_fingerprint']} instead of the new certificate")
            elif row.get("sni") and row.get("hostname_matches") is False:
                raise DeployError("VERIFY_HOSTNAME_MISMATCH", f"the served certificate does not cover {row['sni']}")
        if self.strict_chain:
            for row in rows:
                if row.get("reachable") and row.get("chain_valid") is not True:
                    raise DeployError("VERIFY_CHAIN_UNTRUSTED",
                                      f"{row['host']}:{row['port']} serves a certificate chain that does not validate against "
                                      "the trust anchors, and this environment requires a trusted chain")
        if not rows:
            if not allow_file_only:
                raise DeployError("VERIFY_NO_ENDPOINT", "no verification endpoint configured and file-only verification is not allowed")
            mode = "file_only"
        files = []
        for f in specs:
            cur = await self.host.stat(f["dest_path"])
            if cur.sha256 != f["new_sha256"]:
                raise DeployError("VERIFY_FILE_MISMATCH", f"{f['dest_path']} no longer matches the deployed content")
            files.append({"path": f["dest_path"], "sha256": cur.sha256, "mode": cur.mode, "owner": cur.owner})
        return {"mode": mode, "expected_fingerprint": expected_fp, "endpoints": rows, "files": files,
                "chain_valid": all(r.get("chain_valid") is not False for r in rows) if rows else None,
                "verified_at": _now()}

    # ------------------------------------------------------------------ success
    async def _complete(self, art: planner.ArtifactSet) -> str:
        """Success path after a verified deployment (K2).

        Everything here runs after the new files were verified on the host, so a failure must never roll the target
        into a state that hides that: cleanup is best effort, ``finalize`` is idempotent and retried, and if the
        database still refuses, the verified outcome is persisted through a fresh session (``completed`` when the files
        and the endpoint were verified, otherwise ``manual_intervention_required``).
        """
        self._persist_verification()
        try:
            async with self.step("cleanup") as st:
                await self._cleanup_stage()
                st["detail"]["stage_dir_removed"] = True
        except Exception as exc:  # noqa: BLE001 - the stage directory is garbage, not state
            self._recover_session()
            log.warning("deployment_cleanup_failed", error=type(exc).__name__)
        last: Exception | None = None
        for attempt in range(1, FINALIZE_ATTEMPTS + 1):
            try:
                async with self.step("finalize") as st:
                    self._finalize_records(art, st)
                    st["detail"]["attempt"] = attempt
                self.set_status("completed", None)
                self._after_final("completed")
                return "completed"
            except Exception as exc:  # noqa: BLE001
                last = exc
                self._recover_session()
                log.warning("deployment_finalize_failed", attempt=attempt, error=type(exc).__name__)
                if attempt < FINALIZE_ATTEMPTS:
                    await asyncio.sleep(FINALIZE_RETRY_DELAY)
        return self._finalize_degraded(last)

    def _recover_session(self) -> None:
        """Drop a broken transaction and reload the rows this runner works on."""
        with contextlib.suppress(Exception):
            self.db.rollback()
        with contextlib.suppress(Exception):
            self.db.expire_all()

    def _persist_verification(self) -> None:
        """The verification result is the evidence for everything that follows: store it before anything else."""
        if self.verification is None:
            return
        try:
            for t in self.targets:
                t.verification = self.verification
            self._flush()
        except Exception as exc:  # noqa: BLE001
            self._recover_session()
            log.warning("deployment_verification_persist_failed", error=type(exc).__name__)

    def _verified_ok(self) -> bool:
        """Files verified (``_verify_new`` raises otherwise) and the endpoint verified, or file-only verification was
        explicitly allowed by the strategy."""
        v = self.verification
        if not v or not v.get("files"):
            return False
        if v.get("mode") == "live":
            return True
        return v.get("mode") == "file_only" and bool(self.strategy.get("allow_file_only_verification"))

    def _finalize_records(self, art: planner.ArtifactSet, st: dict[str, Any]) -> None:
        cert = self._ensure_certificate(art)
        now = utcnow()
        for t in self.targets:
            inst = self.installs.get(t.id)
            t.new_fingerprint = art.leaf.fingerprint_sha256
            if self.verification is not None:
                t.verification = self.verification
            if inst is not None:
                inst.last_observed_fingerprint = art.leaf.fingerprint_sha256
                inst.last_observed_at = now
                inst.last_deployment_id = self.job_id
                inst.drift_status = "in_sync"
                inst.certificate_id = cert.id
                inst.last_verification = {"at": now.isoformat(), "ok": True, "source": "deployment",
                                          "mode": (t.verification or {}).get("mode")}
        version = self.db.get(CertificateVersion, self.job.version_id)
        version.status = "deployed"
        if version.certificate_id is None:
            version.certificate_id = cert.id
        st["detail"]["certificate_id"] = str(cert.id)

    def _finalize_degraded(self, exc: Exception | None) -> str:
        """The database refused ``finalize`` repeatedly. Persist the verified outcome through a fresh session."""
        code, msg = classify(exc) if exc is not None else ("INTERNAL_ERROR", "finalize failed")
        ok = self._verified_ok()
        status = "completed" if ok else "manual_intervention_required"
        text = ("the new certificate is deployed and verified on the host, but its records could not be finalised "
                f"({code}); inventory will refresh on the next discovery" if ok else
                f"the new files are in place but could not be recorded as verified ({code}: {msg}); check the host")
        try:
            with SessionLocal() as db:
                for tid in self.target_ids:
                    t = db.get(DeploymentTarget, tid)
                    if t is None:
                        continue
                    before = t.status
                    t.status, t.current_step = status, None
                    t.verification = self.verification or t.verification
                    t.new_fingerprint = (self.verification or {}).get("expected_fingerprint") or t.new_fingerprint
                    if ok:
                        t.error_code, t.error_message = None, None
                    else:
                        t.error_code, t.error_message = "FINALIZE_FAILED", _clip(str(redact(text)), 1000)
                    t.log = [*(t.log or [])[-499:], {"ts": _now(), "level": "warning" if ok else "error", "message": _clip(text, 400)}]
                    audit.record(db, action="DEPLOYMENT_TARGET_STATE", resource_type="deployment_target", resource_id=t.id,
                                 actor_name=ACTOR, before={"status": before},
                                 after={"status": status, "job_id": str(self.job_id), "degraded_finalize": True},
                                 outcome="success" if ok else "failure")
                db.commit()
        except Exception as exc2:
            log.critical("deployment_finalize_unrecoverable", error=type(exc2).__name__, target_id=str(self.primary.id))
            raise
        if not ok:
            self._notify("rollback.failed", "critical", {"reason": "FINALIZE_FAILED", "message": _clip(text, 300)})
        self._after_final(status)
        return status

    def _ensure_certificate(self, art: planner.ArtifactSet) -> Certificate:
        fp = art.leaf.fingerprint_sha256
        cert = self.db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == fp))
        if cert is not None:
            return cert
        c = art.leaf
        cert = Certificate(
            fingerprint_sha256=fp, common_name=c.common_name, subject=c.subject, sans=list(c.sans), issuer=c.issuer,
            serial_number=c.serial_number, public_key_algorithm=c.public_key_algorithm, public_key_size=c.public_key_size,
            public_key_sha256=c.public_key_sha256, signature_algorithm=c.signature_algorithm, not_before=c.not_before,
            not_after=c.not_after, is_ca=False, certificate_type="self_signed" if c.is_self_signed else "leaf",
            chain_info={"chain": [{"subject": x.subject, "fingerprint_sha256": x.fingerprint_sha256} for x in art.chain]},
            discovery_source="deployment", status=compute_status(c.not_after, utcnow()), pem=c.pem)
        try:
            with self.db.begin_nested():
                self.db.add(cert)
        except Exception:
            cert = self.db.scalar(select(Certificate).where(Certificate.fingerprint_sha256 == fp))
            if cert is None:
                raise
        return cert

    # ------------------------------------------------------------------ rollback
    async def _rollback(self, reason: DeployError) -> str:
        host = self.host
        for t in self.targets:
            t.rollback_attempts = (t.rollback_attempts or 0) + 1
        self.note(f"rolling back: {reason.code}", "warning")
        self.set_status("rolling_back", "rollback", error=(reason.code, reason.message))
        self._notify("rollback.triggered", "warning", {"reason": reason.code, "message": reason.message})
        backup = self.db.get(Backup, self.primary.backup_id) if self.primary.backup_id else None
        try:
            self.ensure_locks()
            if backup is None:
                raise DeployError("ROLLBACK_NO_BACKUP", "no backup is recorded for this target")
            async with self.step("rollback") as st:
                outcome = await backups.restore_files(self.db, host, backup, before_change=self.ensure_locks)
                st["detail"]["files"] = [{"path": r.path, "action": r.action, "detail": r.detail} for r in outcome.files]
                if not outcome.ok:
                    raise DeployError("ROLLBACK_RESTORE_FAILED", outcome.error or "one or more files could not be restored: " + "; ".join(
                        f"{r.path}: {r.detail}" for r in outcome.files if r.action == "failed"))
                for svc in self.service_types():
                    self.ensure_locks()
                    res = await get_adapter(svc).config_test(host)
                    if res.exit_status != 0:
                        raise DeployError("ROLLBACK_CONFIG_TEST_FAILED", f"{svc} rejects the restored configuration: {_clip(res.stdout or '', 300)}")
                if self.state.get("reload_started"):
                    for svc in self.service_types():
                        self.ensure_locks()
                        res = await get_adapter(svc).reload(host, bool(self.strategy.get("allow_restart")))
                        if res.exit_status != 0:
                            raise DeployError("ROLLBACK_RELOAD_FAILED", f"{svc} reload after restore failed: {_clip(res.stdout or '', 300)}")
                problems = await backups.verify_files_match(host, backup)
                if problems:
                    raise DeployError("ROLLBACK_VERIFY_FAILED", "; ".join(problems))
                served = await self._verify_baseline()
                st["detail"]["served"] = served
        except Exception as exc:  # noqa: BLE001
            code, msg = classify(exc)
            self.job.rollback_status = "manual_intervention_required"
            self.set_status("manual_intervention_required", None, error=(code, f"{reason.code}: {reason.message}; rollback failed: {msg}"))
            self._notify("rollback.failed", "critical", {"reason": reason.code, "rollback_error": code,
                                                        "message": _clip(msg, 300)})
            self._after_final("manual_intervention_required")
            return "manual_intervention_required"
        backup.restore_status = "restored"
        backup.restored_at = utcnow()
        await self._cleanup_stage()
        for t in self.targets:
            inst = self.installs.get(t.id)
            if inst is not None and t.previous_fingerprint:
                inst.last_observed_fingerprint = t.previous_fingerprint
                inst.last_observed_at = utcnow()
                inst.drift_status = "in_sync"
        self.set_status("rolled_back", None, error=(reason.code, reason.message))
        self._after_final("rolled_back")
        return "rolled_back"

    async def _verify_baseline(self) -> list[dict[str, Any]]:
        """After a rollback every endpoint that was reachable before must serve what it served before."""
        retries = int(self.strategy.get("verify_retries", 5))
        delay = float(self.strategy.get("verify_delay_seconds", 1.5))
        out: list[dict[str, Any]] = []
        for t in self.targets:
            for ep in (t.meta or {}).get("verify_endpoints", []):
                if not ep.get("reachable"):
                    out.append({**{k: ep[k] for k in ("host", "port", "sni")}, "skipped": "unreachable before deployment"})
                    continue
                want = ep.get("served_fingerprint")
                got = None
                for attempt in range(1, retries + 1):
                    res = await self._probe(ep)
                    got = res.leaf.fingerprint_sha256 if res.ok and res.leaf else None
                    if got == want:
                        break
                    if attempt < retries:
                        await asyncio.sleep(delay)
                if got != want:
                    raise DeployError("ROLLBACK_SERVED_MISMATCH",
                                      f"{ep['host']}:{ep['port']} serves {got} instead of the previous certificate {want}")
                out.append({"host": ep["host"], "port": ep["port"], "sni": ep.get("sni"), "served_fingerprint": got})
        return out

    # ------------------------------------------------------------------ resume / reconcile
    async def _resume(self) -> str:
        """The previous worker died mid-flight. Decide from remote state; never redo destructive steps blindly."""
        status = self.primary.status
        self.note(f"resuming interrupted target in state '{status}'", "warning")
        backup = self.db.get(Backup, self.primary.backup_id) if self.primary.backup_id else None
        art = planner.load_artifacts(self.db, self.db.get(CertificateVersion, self.job.version_id))
        specs = self.file_specs()
        async with self.step("reconcile") as st:
            if backup is None:
                classification = "no_backup"
            else:
                try:
                    backups.verify_backup(backup, self.db)
                except backups.BackupIntegrityError:
                    classification = "backup_corrupt"
                else:
                    expected = self.state.get("expected", {})
                    now_hashes = {}
                    for e in backup.manifest["files"]:
                        now_hashes[e["path"]] = (await self.host.stat(e["path"])).sha256
                    all_new = bool(expected) and all(now_hashes.get(p) == s for p, s in expected.items())
                    all_prev = all(now_hashes.get(e["path"]) == e["sha256"] for e in backup.manifest["files"])
                    classification = "all_new" if all_new else ("all_previous" if all_prev else "mixed")
            st["detail"]["classification"] = classification
        if classification in ("no_backup", "backup_corrupt"):
            self.set_status("manual_intervention_required", None, error=(
                "RECONCILE_FAILED", f"interrupted deployment cannot be reconciled ({classification})"))
            self._notify("rollback.failed", "critical", {"reason": "RECONCILE_FAILED", "classification": classification})
            self._after_final("manual_intervention_required")
            return "manual_intervention_required"
        if self.revoked:
            return await self._resume_revoked(status, classification)
        if status == "rolling_back" or classification != "all_new":
            return await self._rollback(DeployError("WORKER_INTERRUPTED",
                                                    f"worker was interrupted during '{status}' (files: {classification}); rolling back"))
        return await self._activate_and_verify(specs, art, skip_install=True)

    async def _resume_revoked(self, status: str, classification: str) -> str:
        """Safety recovery of an interrupted unit whose initiating user was revoked.

        Authorization to *continue* is gone, the duty to leave the host in a known state is not. Whatever the
        reconciliation found, the only allowed outcome is the previous state: restore from the verified backup (config
        test, reload when a reload had started, previous fingerprint served again) or ``manual_intervention_required``.
        Only a unit whose files provably equal the backup and that never replaced anything is simply cancelled.
        """
        rv = self.revoked or {}
        who = rv.get("username") or str(rv.get("user_id"))
        self.note(f"initiating user {who} is no longer authorised ({rv.get('message')}); recovering the previous state only",
                  "warning")
        if classification == "all_previous" and not self.state.get("activated") and status != "rolling_back":
            await self._cleanup_stage()
            self.set_status("cancelled", None, error=("AUTHZ", rv.get("message") or "initiating user revoked"))
            self._record_revoked_recovery("cancelled", classification)
            self._after_final("cancelled")
            return "cancelled"
        outcome = await self._rollback(DeployError(
            "AUTHZ_REVOKED", f"the initiating user ({who}) is no longer authorised: {rv.get('message')}; the interrupted "
            "deployment was not continued and the previous state was restored"))
        self._record_revoked_recovery(outcome, classification)
        return outcome

    def _record_revoked_recovery(self, outcome: str, classification: str) -> None:
        rv = self.revoked or {}
        try:
            audit.record(self.db, action="DEPLOYMENT_AUTHZ_REVOKED_RECOVERY", resource_type="deployment_target",
                         resource_id=self.primary.id, actor_name=ACTOR,
                         after={"job_id": str(self.job_id), "target_ids": [str(t.id) for t in self.targets],
                                "revoked_user_id": str(rv.get("user_id")), "revoked_username": rv.get("username"),
                                "reason": rv.get("message"), "classification": classification, "outcome": outcome},
                         outcome="success" if outcome in ("rolled_back", "cancelled") else "failure")
            self.db.commit()
        except Exception as exc:  # noqa: BLE001 - the audit trail of the targets already carries the result
            self.db.rollback()
            log.warning("deployment_revoked_audit_failed", error=type(exc).__name__)

    # ------------------------------------------------------------------ helpers
    async def _cleanup_stage(self) -> None:
        stage = self.state.pop("stage_dir", None)
        self.state.pop("staged", None)
        if stage and self.host is not None:
            with contextlib.suppress(Exception):
                await self.host.cleanup(stage)
        with contextlib.suppress(Exception):
            self._flush()

    def _notify(self, event: str, severity: str, extra: dict[str, Any]) -> None:
        try:
            from app.services import notifications

            notifications.notify(self.db, event, severity, {
                "deployment_id": str(self.job_id), "target_id": str(self.primary.id), "server_name": self.server.name,
                "installation_id": str(self.primary.installation_id) if self.primary.installation_id else None, **extra},
                f"{event}:{self.primary.id}", commit=True)
        except Exception as exc:  # noqa: BLE001 - notification problems never affect a deployment
            self.db.rollback()
            log.warning("deployment_notify_failed", error=type(exc).__name__)

    def _after_final(self, status: str) -> None:
        self._publish("target.final", status=status)


# =========================================================================== job runner
@dataclass
class _UnitInfo:
    index: int
    target_ids: list[uuid.UUID]
    server_id: uuid.UUID
    batch: int
    is_canary: bool


class JobRunner:
    def __init__(self, job_id: uuid.UUID, host_factory: planner.HostFactory | None = None):
        self.job_id = job_id
        self.factory = host_factory or HOST_FACTORY or planner.default_host_factory
        self.owner = f"worker:{uuid.uuid4()}"
        self.failures = 0
        self.canary_failed = False
        self._server_locks: dict[uuid.UUID, asyncio.Lock] = {}

    # ------------------------------------------------------------------ job-level persistence helpers
    def _publish(self, type_: str, **payload: Any) -> None:
        try:
            from app.services.events import publish_job_event

            publish_job_event("deployment", self.job_id, {"type": type_, **payload})
        except Exception:  # noqa: BLE001, S110
            pass

    def _set_job(self, db: Session, job: DeploymentJob, status: str, *, error: str | None = None) -> None:
        before = job.status
        job.status = status
        if error is not None:
            job.error_summary = _clip(str(redact(error)), 2000)
        audit.record(db, action="DEPLOYMENT_STATE", resource_type="deployment", resource_id=job.id, actor_name=ACTOR,
                     before={"status": before}, after={"status": status, **({"error": _clip(error, 300)} if error else {})},
                     outcome="failure" if status in ("failed", "manual_intervention_required", "partially_failed") else "success")
        db.commit()
        self._publish("job.status", status=status)

    async def run(self) -> str:
        if not locks.acquire(locks.job_key(self.job_id), owner=self.owner, job_id=None, ttl_seconds=locks.DEFAULT_TTL_SECONDS):
            raise JobBusy(str(self.job_id))
        beat = asyncio.ensure_future(self._beat())
        try:
            return await self._run()
        finally:
            beat.cancel()
            with contextlib.suppress(BaseException):
                await beat
            locks.release(locks.job_key(self.job_id), owner=self.owner)

    async def _beat(self) -> None:
        while True:
            await asyncio.sleep(locks.HEARTBEAT_SECONDS)
            with contextlib.suppress(Exception):
                locks.renew(locks.job_key(self.job_id), owner=self.owner)

    async def _run(self) -> str:
        with SessionLocal() as db:
            job = db.get(DeploymentJob, self.job_id)
            if job is None:
                raise AppError("DEPLOYMENT_NOT_FOUND", "deployment not found", 404)
            if job.status in planner.FINAL_JOB_STATUSES or job.status == "awaiting_approval":
                return job.status
            targets = list(db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)
                                      .order_by(DeploymentTarget.created_at, DeploymentTarget.id)))
            user = db.get(User, job.initiated_by) if job.initiated_by else None
            try:
                if user is None or not user.enabled:
                    raise AppError("AUTHZ", "the initiating user no longer exists or is disabled", 403)
                authorize(user, "deployments:create")
            except AppError as exc:
                return await self._authz_revoked(db, job, targets, user, exc.message)
            if job.started_at is None:
                job.started_at = utcnow()
                audit.record(db, action="DEPLOYMENT_STARTED", resource_type="deployment", resource_id=job.id,
                             actor_name=ACTOR, after={"targets": len(targets)})
                db.commit()
            if job.status in ("pending", "preflight") and not await self._preflight(db, job, targets):
                return job.status
            self._set_job(db, job, "activating")
            units = self._units(targets)
            self.failures = sum(1 for t in targets if t.status in ("failed", "rolled_back", "manual_intervention_required"))
            strategy = job.strategy or {}
            sem = asyncio.Semaphore(int(strategy.get("concurrency", 3)))
            for batch in sorted({u.batch for u in units}):
                await asyncio.gather(*(self._run_unit(u, sem, strategy) for u in units if u.batch == batch))
            db.expire_all()
            return self._finalize(db, job)

    def _units(self, targets: list[DeploymentTarget]) -> list[_UnitInfo]:
        groups: dict[int, list[DeploymentTarget]] = {}
        for t in targets:
            groups.setdefault(int((t.meta or {}).get("unit", len(groups) + 1000 + len(groups))), []).append(t)
        out = []
        for idx, ts in sorted(groups.items()):
            out.append(_UnitInfo(idx, [t.id for t in ts], ts[0].server_id, min(t.batch_index for t in ts),
                                 any(t.is_canary for t in ts)))
        return sorted(out, key=lambda u: (u.batch, u.index))

    async def _run_unit(self, unit: _UnitInfo, sem: asyncio.Semaphore, strategy: dict[str, Any]) -> None:
        async with sem:
            lock = self._server_locks.setdefault(unit.server_id, asyncio.Lock())
            async with lock:
                skip = self._skip_reason(unit, strategy)
                if skip:
                    self._skip(unit, skip)
                    return
                runner = UnitRunner(self.job_id, unit.target_ids, self.factory, self.owner)
                outcome = await runner.run()
                if outcome not in ("completed", "cancelled"):
                    self.failures += 1
                    if unit.is_canary:
                        self.canary_failed = True

    def _skip_reason(self, unit: _UnitInfo, strategy: dict[str, Any]) -> str | None:
        with SessionLocal() as db:
            t = db.get(DeploymentTarget, unit.target_ids[0])
            if t.status != "pending":
                return None          # resuming an in-flight / finished unit is handled by the runner
            job = db.get(DeploymentJob, self.job_id)
            if job.cancel_requested:
                return "cancelled by user"
        if self.canary_failed:
            return "canary target did not succeed"
        thr = int(strategy.get("failure_threshold", 1))
        if thr > 0 and self.failures >= thr and not strategy.get("continue_on_failure"):
            return f"failure threshold reached ({self.failures}/{thr})"
        return None

    def _skip(self, unit: _UnitInfo, why: str) -> None:
        with SessionLocal() as db:
            for tid in unit.target_ids:
                t = db.get(DeploymentTarget, tid)
                t.status, t.error_code, t.error_message = "cancelled", "SKIPPED", why
                t.current_step = None
                audit.record(db, action="DEPLOYMENT_TARGET_STATE", resource_type="deployment_target", resource_id=t.id,
                             actor_name=ACTOR, before={"status": "pending"}, after={"status": "cancelled", "reason": why})
            db.commit()
        self._publish("target.status", target_ids=[str(i) for i in unit.target_ids], status="cancelled",
                      error_code="SKIPPED", message=why)

    # ------------------------------------------------------------------ revoked initiator
    @staticmethod
    def _may_have_mutated(t: DeploymentTarget) -> bool:
        """True when the persisted state shows that files on the host may have been replaced."""
        meta = t.meta or {}
        return t.status in MUTATING_STATES or bool(meta.get("activated")) or bool(meta.get("reload_started"))

    async def _authz_revoked(self, db: Session, job: DeploymentJob, targets: list[DeploymentTarget],
                             user: User | None, message: str) -> str:
        """The initiating user may no longer continue this job (disabled, deleted, role removed).

        Authorization to continue and safety recovery are separate: targets that never started mutating are cancelled;
        units that may have mutated are only brought back to their previous state (locks, reconcile, verified restore)
        under the system actor, never moved forward.
        """
        units = self._units(targets)
        by_id = {t.id: t for t in targets}
        recover = [u for u in units if any(self._may_have_mutated(by_id[i]) for i in u.target_ids
                                           if by_id[i].status not in FINAL_TARGET)]
        if not recover:
            return self._abort(db, job, targets, "AUTHZ", message)
        recover_ids = {i for u in recover for i in u.target_ids}
        for t in targets:
            if t.status not in FINAL_TARGET and t.id not in recover_ids:
                t.status, t.error_code, t.error_message = "cancelled", "AUTHZ", message
                t.current_step = None
        audit.record(db, action="DEPLOYMENT_AUTHZ_REVOKED", resource_type="deployment", resource_id=job.id, actor_name=ACTOR,
                     after={"revoked_user_id": str(job.initiated_by) if job.initiated_by else None,
                            "revoked_username": user.username if user else None, "reason": message,
                            "recovering_targets": len(recover_ids)}, outcome="failure")
        db.commit()
        revoked = {"user_id": job.initiated_by, "username": user.username if user else None, "message": message}
        for u in recover:
            lock = self._server_locks.setdefault(u.server_id, asyncio.Lock())
            async with lock:
                await UnitRunner(self.job_id, u.target_ids, self.factory, self.owner, revoked=revoked).run()
        db.expire_all()
        return self._finalize(db, job)

    # ------------------------------------------------------------------ preflight
    def _abort(self, db: Session, job: DeploymentJob, targets: list[DeploymentTarget], code: str, message: str) -> str:
        for t in targets:
            if t.status not in FINAL_TARGET:
                t.status, t.error_code, t.error_message = "cancelled", code, message
        self._set_job(db, job, "failed", error=f"{code}: {message}")
        job.finished_at = utcnow()
        db.commit()
        self._notify_job(db, job, "failed")
        self._publish("done", status="failed")
        return "failed"

    async def _preflight(self, db: Session, job: DeploymentJob, targets: list[DeploymentTarget]) -> bool:
        self._set_job(db, job, "preflight")
        version = db.get(CertificateVersion, job.version_id)
        inst_ids = [t.installation_id for t in targets if t.installation_id]
        try:
            plan = await planner.build_plan_async(
                db, version, inst_ids, job.strategy, acknowledged=list(job.acknowledged_warnings or []),
                exceptions=(job.strategy or {}).get("exceptions"), host_factory=self.factory, job_id=job.id)
        except AppError as exc:
            self._abort(db, job, targets, exc.code, exc.message)
            return False
        job.dry_run_plan = plan
        db.commit()
        if not plan["summary"]["can_proceed"]:
            codes = sorted({f["code"] for f in plan["findings"] if f["severity"] == "blocking"}
                           | set(plan["summary"]["unacknowledged_warnings"]))
            self._abort(db, job, targets, "PREFLIGHT_FAILED", "pre-flight checks failed: " + ", ".join(codes))
            return False
        by_inst = {t["installation_id"]: t for t in plan["targets"]}
        for t in targets:
            pt = by_inst.get(str(t.installation_id))
            if pt is None:
                self._abort(db, job, targets, "PREFLIGHT_FAILED", "a target is missing from the pre-flight plan")
                return False
            t.previous_fingerprint = pt["current_fingerprint"]
            t.batch_index, t.is_canary = pt["batch_index"], pt["is_canary"]
            t.meta = {**(t.meta or {}), "unit": pt["unit"], "files": pt["files"], "verify_endpoints": pt["verify_endpoints"],
                      "verification_mode": pt["verification_mode"], "shared_with": pt["shared_with"]}
        db.commit()
        return True

    # ------------------------------------------------------------------ finalisation
    def _finalize(self, db: Session, job: DeploymentJob) -> str:
        targets = list(db.scalars(select(DeploymentTarget).where(DeploymentTarget.job_id == job.id)))
        st = [t.status for t in targets]
        completed = st.count("completed")
        if "manual_intervention_required" in st:
            final = "manual_intervention_required"
        elif completed == len(st):
            final = "completed"
        elif completed > 0:
            final = "partially_failed"
        elif "failed" in st:
            final = "failed"
        elif "rolled_back" in st:
            final = "rolled_back"
        else:
            final = "cancelled"
        if any(s == "manual_intervention_required" for s in st):
            job.rollback_status = "manual_intervention_required"
        elif any(s == "rolled_back" for s in st):
            job.rollback_status = "rolled_back"
        errs = [f"{t.error_code}: {t.error_message}" for t in targets if t.status in ("failed", "rolled_back", "manual_intervention_required") and t.error_code]
        self._set_job(db, job, final, error="; ".join(errs[:5]) if errs else None)
        job.finished_at = utcnow()
        audit.record(db, action="DEPLOYMENT_FINISHED", resource_type="deployment", resource_id=job.id, actor_name=ACTOR,
                     after={"status": final, "completed": completed, "total": len(st)},
                     outcome="success" if final == "completed" else "failure")
        db.commit()
        self._notify_job(db, job, final)
        self._publish("done", status=final)
        return final

    def _notify_job(self, db: Session, job: DeploymentJob, final: str) -> None:
        try:
            from app.services import notifications

            event = "deployment.completed" if final == "completed" else "deployment.failed"
            notifications.notify(db, event, "info" if final == "completed" else "high",
                                 {"deployment_id": str(job.id), "status": final, "error": job.error_summary},
                                 f"{event}:{job.id}", commit=True)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("deployment_notify_failed", error=type(exc).__name__)


# =========================================================================== entry points
def run_job(job_id: uuid.UUID, host_factory: planner.HostFactory | None = None) -> str:
    """Synchronous entry point used by the Celery task. Raises :class:`JobBusy` if another worker runs the job."""
    return asyncio.run(JobRunner(job_id, host_factory).run())


async def run_job_async(job_id: uuid.UUID, host_factory: planner.HostFactory | None = None) -> str:
    return await JobRunner(job_id, host_factory).run()


# =========================================================================== manual restore
@dataclass
class RestoreScope:
    """Everything a manual restore of one backup touches: the backup is attached to every target of a shared unit and
    restores the whole manifest, so all of their installations / services / endpoints are one unit."""
    targets: list[DeploymentTarget]
    installs: list[CertificateInstallation]

    def service_types(self) -> list[str]:
        return sorted({i.service_type for i in self.installs})


def resolve_restore_scope(db: Session, backup: Backup, target: DeploymentTarget | None = None) -> RestoreScope:
    """All targets / installations associated with ``backup``.

    Deployment backups: every target carrying this ``backup_id`` (a unit shares one backup) plus the target the backup
    was taken for and the one requested. Backups not tied to a deployment: every installation on the server whose
    cert / key / chain / fullchain path (or its realpath) appears in the manifest.
    """
    cond = [DeploymentTarget.backup_id == backup.id]
    if backup.deployment_target_id:
        cond.append(DeploymentTarget.id == backup.deployment_target_id)
    found = list(db.scalars(select(DeploymentTarget).where(or_(*cond))
                            .order_by(DeploymentTarget.created_at, DeploymentTarget.id)))
    targets: dict[uuid.UUID, DeploymentTarget] = {t.id: t for t in found}
    if target is not None:
        targets.setdefault(target.id, target)
    installs: dict[uuid.UUID, CertificateInstallation] = {}

    def add(inst: CertificateInstallation | None) -> None:
        if inst is not None:
            installs.setdefault(inst.id, inst)

    if backup.installation_id:
        add(db.get(CertificateInstallation, backup.installation_id))
    for t in targets.values():
        if t.installation_id:
            add(db.get(CertificateInstallation, t.installation_id))
    if backup.deployment_target_id is None:
        paths = {e.get(k) for e in backup.manifest["files"] for k in ("path", "realpath")} - {None}
        for inst in db.scalars(select(CertificateInstallation).where(CertificateInstallation.server_id == backup.server_id)):
            if paths & {inst.cert_path, inst.key_path, inst.chain_path, inst.fullchain_path}:
                add(inst)
    return RestoreScope(list(targets.values()), list(installs.values()))


def restore_lock_keys(db: Session, backup: Backup, target: DeploymentTarget | None = None,
                      scope: RestoreScope | None = None) -> list[str]:
    """Locks a restore of ``backup`` needs: every backed-up path and the service of EVERY affected installation."""
    scope = scope or resolve_restore_scope(db, backup, target)
    keys = [locks.file_key(backup.server_id, e["realpath"]) for e in backup.manifest["files"]]
    keys += [locks.service_key(backup.server_id, svc) for svc in scope.service_types()]
    return keys


def _previous_leaf(db: Session, backup: Backup, inst: CertificateInstallation):
    """Leaf certificate the backup holds for ``inst`` (None when its certificate file is not part of the backup)."""
    want = inst.cert_path or inst.fullchain_path
    for e in backup.manifest["files"]:
        if want and want in (e["path"], e.get("realpath")):
            certs = parse_pem_certificates(backups.load_file_content(e, db))
            return certs[0] if certs else None
    return None


def _restore_reloads(scope: RestoreScope) -> bool:
    """Mirror of the engine's rule: services are reloaded after a restore only when a reload had started (or the
    deployment completed / the backup is restored on its own); before that they never served the new files."""
    if not scope.targets:
        return True
    return any(t.status == "completed" or (t.meta or {}).get("reload_started") for t in scope.targets)


def manual_restore_targets(scope: RestoreScope, target: DeploymentTarget | None) -> list[DeploymentTarget]:
    """Targets whose status a manual restore updates: the requested one and every other target of the unit that
    is in a restorable state."""
    return [t for t in scope.targets if (target is not None and t.id == target.id) or t.status in RESTORABLE_TARGET_STATES]


async def restore_backup_async(db: Session, backup: Backup, actor: User, *, target: DeploymentTarget | None = None,
                               host_factory: planner.HostFactory | None = None,
                               previous_restore_status: str | None = None) -> dict[str, Any]:
    """Restore a backup to its server (admin-triggered rollback of a completed target / backup restore).

    Same verified routine as the automatic rollback, applied to the whole unit the backup belongs to: the locks of
    every affected service and path are taken, the files are restored once, every affected service type is config
    tested and (see :func:`_restore_reloads`) reloaded, every affected endpoint must serve the previous certificate
    again, and only then are the inventory and the status of every affected target / installation updated. Any
    failure leaves ALL affected targets in ``manual_intervention_required`` with the failing service named.

    A restore that cannot take its locks (``LOCK_HELD``, K3) changed nothing: the targets and the backup keep their
    previous state and the caller may simply try again.
    """
    factory = host_factory or HOST_FACTORY or planner.default_host_factory
    server = db.get(Server, backup.server_id)
    scope = resolve_restore_scope(db, backup, target)
    owner = f"restore:{uuid.uuid4()}"
    keys = restore_lock_keys(db, backup, target, scope)
    prior_status = previous_restore_status or (backup.restore_status if backup.restore_status != "in_progress" else "none")
    affected = manual_restore_targets(scope, target)
    affected_ids = [t.id for t in affected]
    prior_steps = {t.id: t.current_step for t in affected}
    previous: dict[uuid.UUID, Any] = {}
    for inst in scope.installs:
        try:
            previous[inst.id] = _previous_leaf(db, backup, inst)
        except Exception:  # noqa: BLE001 - an unreadable backup is reported by restore_files below
            previous[inst.id] = None
    services = scope.service_types()
    do_reload = _restore_reloads(scope)
    backup.restore_status = "in_progress"
    db.commit()
    result: dict[str, Any] = {"backup_id": str(backup.id), "ok": False, "files": [], "served": [],
                              "services": services, "target_ids": [str(i) for i in affected_ids],
                              "installation_ids": [str(i.id) for i in scope.installs]}
    try:
        async with factory(server) as host, locks.LockSet(keys, owner=owner, job_id=None, target_id=None) as held:
            outcome = await backups.restore_files(db, host, backup, before_change=lambda: _ensure_locks(held))
            result["files"] = [{"path": r.path, "action": r.action, "detail": r.detail} for r in outcome.files]
            if not outcome.ok:
                raise DeployError("RESTORE_FAILED", outcome.error or "files could not be restored")
            for svc in services:
                _ensure_locks(held)
                if (await get_adapter(svc).config_test(host)).exit_status != 0:
                    result["failed_service"] = svc
                    raise DeployError("RESTORE_CONFIG_TEST_FAILED", f"{svc} rejects the restored configuration")
            if do_reload:
                for svc in services:
                    _ensure_locks(held)
                    if (await get_adapter(svc).reload(host, False)).exit_status != 0:
                        result["failed_service"] = svc
                        raise DeployError("RESTORE_RELOAD_FAILED", f"{svc} reload after restore failed")
            problems = await backups.verify_files_match(host, backup)
            if problems:
                raise DeployError("RESTORE_VERIFY_FAILED", "; ".join(problems))
            from app.integrations.tls.probe import probe_endpoint

            mismatches: list[str] = []
            failed_services: list[str] = []
            for inst in scope.installs:
                leaf = previous.get(inst.id)
                if leaf is None:
                    continue
                for ep in planner.verify_endpoints_for(inst, server, leaf.sans):
                    got = None
                    for attempt in range(RESTORE_VERIFY_ATTEMPTS):
                        res = await probe_endpoint(ep["host"], ep["port"], ep["sni"], 5.0)
                        got = res.leaf.fingerprint_sha256 if res.ok and res.leaf else None
                        if got == leaf.fingerprint_sha256:            # a positive match is required
                            break
                        if attempt + 1 < RESTORE_VERIFY_ATTEMPTS:
                            await asyncio.sleep(RESTORE_VERIFY_DELAY)
                    if got != leaf.fingerprint_sha256:
                        mismatches.append(f"{inst.service_type} {ep['host']}:{ep['port']} does not serve the restored certificate")
                        if inst.service_type not in failed_services:
                            failed_services.append(inst.service_type)
                        continue
                    result["served"].append({**ep, "service_type": inst.service_type, "served_fingerprint": got})
            if mismatches:
                result["failed_service"] = ", ".join(failed_services)
                raise DeployError("RESTORE_SERVED_MISMATCH", "; ".join(mismatches))
        result["ok"] = True
    except Exception as exc:  # noqa: BLE001
        code, msg = classify(exc)
        result.update({"error_code": code, "error": msg})
    now = utcnow()
    if result.get("error_code") == "LOCK_HELD":
        # nothing was touched: leave targets and backup as they were
        db.rollback()
        backup = db.get(Backup, backup.id)
        backup.restore_status = prior_status
        for tid in affected_ids:
            t = db.get(DeploymentTarget, tid)
            if t is not None and t.current_step == "manual_rollback":
                t.current_step = prior_steps.get(tid) if prior_steps.get(tid) != "manual_rollback" else None
        audit.record(db, action="BACKUP_RESTORE_FAILED", resource_type="backup", resource_id=backup.id, actor=actor,
                     after={"error_code": "LOCK_HELD", "target_id": str(target.id) if target else None},
                     outcome="failure", error=result.get("error"))
        db.commit()
        return result
    backup.restore_status = "restored" if result["ok"] else "failed"
    backup.restored_at = now if result["ok"] else backup.restored_at
    failure_text = None
    if not result["ok"]:
        failure_text = _clip(str(redact(
            f"restore of the shared unit failed ({', '.join(services) or 'no service'}"
            + (f"; failing service: {result['failed_service']}" if result.get("failed_service") else "")
            + f"): {result.get('error', '')}")), 1000)
    for t in affected:
        t.rollback_attempts = (t.rollback_attempts or 0) + 1
        t.current_step = None
        if result["ok"]:
            t.status, t.error_code, t.error_message = "rolled_back", "MANUAL_ROLLBACK", "restored from backup by an administrator"
            if len(scope.targets) > 1:
                t.error_message += " (together with the other targets sharing this backup)"
        else:
            t.status, t.error_code, t.error_message = "manual_intervention_required", result.get("error_code"), failure_text
    if result["ok"]:
        for inst in scope.installs:
            leaf = previous.get(inst.id)
            if leaf is not None:
                inst.last_observed_fingerprint, inst.last_observed_at, inst.drift_status = leaf.fingerprint_sha256, now, "in_sync"
    jobs = {t.job_id for t in affected}
    result["job_ids"] = [str(j) for j in jobs]
    audit.record(db, action="BACKUP_RESTORED" if result["ok"] else "BACKUP_RESTORE_FAILED", resource_type="backup",
                 resource_id=backup.id, actor=actor,
                 after={"files": result["files"], "target_id": str(target.id) if target else None,
                        "target_ids": result["target_ids"], "installation_ids": result["installation_ids"],
                        "services": services,
                        **({"error_code": result.get("error_code"), "failed_service": result.get("failed_service")}
                           if not result["ok"] else {})},
                 outcome="success" if result["ok"] else "failure", error=result.get("error"))
    db.commit()
    return result


def restore_backup(db: Session, backup: Backup, actor: User, **kw: Any) -> dict[str, Any]:
    return asyncio.run(restore_backup_async(db, backup, actor, **kw))


def run_restore(backup_id: uuid.UUID, actor_id: uuid.UUID, target_id: uuid.UUID | None = None, *,
                previous_restore_status: str | None = None, permission: str = "backups:restore") -> dict[str, Any]:
    """Worker entry point of a queued manual restore / manual target rollback.

    The API already checked permission and re-authentication; the worker authorises again because the request may have
    waited in the queue (user disabled, role removed) and never trusts the message alone.
    """
    with SessionLocal() as db:
        backup = db.get(Backup, backup_id)
        if backup is None:
            return {"ok": False, "error_code": "BACKUP_NOT_FOUND", "error": "backup not found"}
        user = db.get(User, actor_id)
        target = db.get(DeploymentTarget, target_id) if target_id else None
        prior = previous_restore_status or "none"

        def refuse(code: str, message: str) -> dict[str, Any]:
            backup.restore_status = prior
            for t in resolve_restore_scope(db, backup, target).targets:
                if t.current_step == "manual_rollback":
                    t.current_step = None
            audit.record(db, action="BACKUP_RESTORE_FAILED", resource_type="backup", resource_id=backup.id, actor=user,
                         actor_name=None if user else ACTOR, after={"error_code": code}, outcome="denied", error=message)
            db.commit()
            return {"backup_id": str(backup.id), "ok": False, "error_code": code, "error": message, "files": [], "served": []}

        if user is None or not user.enabled:
            return refuse("AUTHZ", "the requesting user no longer exists or is disabled")
        try:
            authorize(user, permission)
        except AppError as exc:
            return refuse("AUTHZ", exc.message)
        if target is not None and target.status not in ("completed", "manual_intervention_required", "failed"):
            return refuse("INVALID_STATE", f"target is {target.status}; only completed/failed targets can be rolled back manually")
        result = restore_backup(db, backup, user, target=target, previous_restore_status=prior)
        if result.get("error_code") != "LOCK_HELD":
            job_ids = {uuid.UUID(j) for j in result.get("job_ids", [])} | ({target.job_id} if target is not None else set())
            for job_id in job_ids:
                job = db.get(DeploymentJob, job_id)
                if job is not None:
                    job.rollback_status = "rolled_back" if result["ok"] else "manual_intervention_required"
            db.commit()
        return result
