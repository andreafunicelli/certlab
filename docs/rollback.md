# Rollback

When Cert Deploy Pro (CDP) reverts a certificate change, how it proves the revert worked, what `manual_intervention_required`
means, and how an operator recovers a target by hand.

Basis: source at commit `a353f1e`. Read: `services/deployment_engine.py` (`_rollback`, `_resume`, `restore_backup_async`),
`services/backups.py` (`restore_files`, `verify_files_match`, `verify_backup`), `services/deployments.py`
(`rollback_target`), `api/v1/backups.py`, `api/v1/deployments.py`. The rollback-related scenarios in
`backend/tests/integration/test_deploy_live.py` (e, f, g, k, l) and the unit tests in `backend/tests/unit/deploy/` were read
for what they assert. **No test was run for this page.** Runtime behaviour that rests on reading alone is marked
**(unverified)**. Defects found by reading are marked **Known issue**. Commands shown are **(not run)**.

Related: [deployment-engine.md](deployment-engine.md) (the forward path and state machine),
[backup-restore.md](backup-restore.md) (how backups are stored and what the platform itself needs to restore),
[security.md](security.md) (roles and re-authentication), [troubleshooting.md](troubleshooting.md).

---

## 1. When rollback runs

Rollback applies to failures from the `activate` step onward, which is the first step that can change the host. A failure
earlier (connect, lock, recheck, backup, stage, validate) stops the target as `failed`, because nothing on the host has
been changed.

| Trigger (target error code) | Step where it is raised |
|---|---|
| `INSTALL_HASH_MISMATCH`, or any error from helper `install` (for example `PERMISSION_DENIED`, `DISK_FULL`, `PATH_NOT_ALLOWED`) | `activate` |
| `CONFIG_TEST_FAILED` | `config_test` |
| `RELOAD_FAILED`, or an SSH error from a reload | `reload` |
| `VERIFY_UNREACHABLE`, `VERIFY_NO_ENDPOINT`, `VERIFY_FINGERPRINT_MISMATCH`, `VERIFY_HOSTNAME_MISMATCH`, `VERIFY_FILE_MISMATCH` | `verify` |
| `INTERNAL_ERROR` (any other exception in those steps) | `activate`, `config_test`, `reload` or `verify` |
| `WORKER_INTERRUPTED` (crash recovery found the files neither all new nor all previous) | `reconcile`, on resume |

Not triggers:

- **Cancellation** is not honoured after `before_activation` (see [deployment-engine.md](deployment-engine.md) section 14).
- **Failures after verification** (`cleanup`, `finalize`) do not trigger a rollback: the new files were verified. Finalize is
  retried; if the database still refuses, the target is `completed` (files and endpoint verified) or
  `manual_intervention_required` (**Fixed**, deployment-engine K2, section 12).
- **Authorisation checks** run only at checkpoints before activation, so they cannot trigger a rollback.
- **A lost lock** (`LOCK_LOST`, deployment-engine K6, fixed) stops the unit before its next change. After activation started,
  the normal rollback runs.

---

## 2. The rollback procedure

The code is `UnitRunner._rollback` in `deployment_engine.py`. Each step below is a failure point. Any failure goes to
section 5.

1. **Start.** Every target's `rollback_attempts` is incremented. The status becomes `rolling_back` (step `rollback`), and
   a `rollback.triggered` notification is sent at severity `warning`.
2. **Find the backup.** The primary target's `backup_id` is loaded. None gives `ROLLBACK_NO_BACKUP`.
3. **Restore files** (`backups.restore_files`):
   - The backup's HMAC and every artifact are verified first (`verify_backup`). A failure is reported as an integrity error.
   - For each manifest file, `stat` is compared with the backup: SHA-256, mode, owner and group. A match is `unchanged` and is
     skipped.
   - Otherwise the backup content is staged (mode 0600), installed with the recorded mode, owner and group, and re-`stat`-ed.
     The SHA-256 and mode must now match, or the file is `failed`.
   - Any failed file gives `ROLLBACK_RESTORE_FAILED`, with the failed paths in the message.
4. **Config test.** Each service of the target runs its config test. A failure gives `ROLLBACK_CONFIG_TEST_FAILED`.
5. **Reload**, only if the forward run had started a reload (`reload_started`). Each service reloads with the strategy's
   `allow_restart`. A failure gives `ROLLBACK_RELOAD_FAILED`.
6. **Verify files.** `verify_files_match` compares every path with the manifest: SHA-256, mode, owner, group, and symlink
   target. Any difference gives `ROLLBACK_VERIFY_FAILED`.
7. **Verify endpoints** (`_verify_baseline`). Each endpoint that was reachable at preflight must serve the fingerprint it
   served before the deployment. Up to `verify_retries` probes, `verify_delay_seconds` apart. A different or missing
   fingerprint gives `ROLLBACK_SERVED_MISMATCH`. Endpoints that were unreachable before are skipped and listed as
   `unreachable before deployment`.
8. **Success.** The backup's `restore_status` becomes `restored` and `restored_at` is set. The staging directory is removed.
   Each installation's `last_observed_fingerprint` is reset to the previous fingerprint from preflight, and `drift_status`
   becomes `in_sync`. The target becomes `rolled_back` with the original reason as its error code.

### 2.1 What "verified" means

A rollback counts as complete only if all of the following hold. Each row is checked in the order above.

| Requirement | Check | Failure code |
|---|---|---|
| Backup is intact | HMAC over the manifest, every artifact decrypts and matches its hash | `ROLLBACK_RESTORE_FAILED` (integrity message) |
| Every file equals the backup | SHA-256, mode, owner, group | `ROLLBACK_VERIFY_FAILED` |
| Symlinks unchanged | Symlink target of each path equals the manifest | `ROLLBACK_VERIFY_FAILED` |
| Configuration valid | Config test passes for each service | `ROLLBACK_CONFIG_TEST_FAILED` |
| Services reloaded (if reloaded before) | Reload exit 0 | `ROLLBACK_RELOAD_FAILED` |
| Previous certificate served | Each previously reachable endpoint serves the previous fingerprint | `ROLLBACK_SERVED_MISMATCH` |

If any requirement fails, the target is `manual_intervention_required`, not `rolled_back`.

---

## 3. Outcomes and job status

| Target status | Meaning |
|---|---|
| `rolled_back` | Rollback verified. Remote state equals the backup. |
| `manual_intervention_required` | Rollback failed, or a resume could not classify the files. The remote state is not known to match the backup. |

The job's `rollback_status` is `rolled_back` or `manual_intervention_required`. The job's own status follows the rules in
[deployment-engine.md](deployment-engine.md) section 6.2. In short: any `manual_intervention_required` target makes the
job `manual_intervention_required`. A canary failure that rolls back and skips the rest gives a job `rolled_back`
(live test (l)).

Each target records `rollback_attempts`. The error text on a rolled-back target is the original reason, for example
`VERIFY_FINGERPRINT_MISMATCH: <message>`. On a manual target it is the original reason plus `; rollback failed: <code>: <message>`.

---

## 4. Crash recovery and rollback

After a worker dies, `_resume` classifies each file of the interrupted target as `all_new`, `all_previous`, `mixed`,
`no_backup` or `backup_corrupt` (table in [deployment-engine.md](deployment-engine.md) section 13).

- `all_new` resumes forward at config test, reload and verify.
- `all_previous` or `mixed` runs the same rollback as in section 2.
- `no_backup` or `backup_corrupt` goes straight to `manual_intervention_required` with `RECONCILE_FAILED`.
- Any SSH error during reconciliation also gives `manual_intervention_required` with `RECONCILE_FAILED`.
- A target already in `rolling_back` is rolled back again from the start.

---

## 5. `manual_intervention_required`

### 5.1 What it means

The engine could not prove that the host is back in the backup state. Files may hold the new content, the previous content,
or a mix. Services may or may not have reloaded. The engine stops touching the target. It does not retry.

### 5.2 What it blocks and where it shows

- **New deployments to that installation** fail preflight with `MANUAL_INTERVENTION_PENDING` (blocking) while the target
  is in this status.
- **Retry** does not include the target. Retry looks only at `failed` and `rolled_back` targets.
- **Job status** is `manual_intervention_required`, and `rollback_status` is set.
- **Notification** `rollback.failed` (severity `critical`) is sent, with the reason and the rollback error.

Leaving the status requires a successful manual restore (section 6). A successful restore sets the target to `rolled_back`,
which no longer matches the blocking check.

---

## 6. Operator runbook

This runbook assumes an administrator who can sign in to the console, and who has SSH or console access to the target
server as a user who can read the certificate paths.

### Step 1. Establish the facts from CDP

- `GET /api/v1/deployments/{job_id}`: `status`, `error_summary`, `rollback_status`, and for each target `status`,
  `error_code`, `error_message`, `current_step`, `backup_id`, `steps`, `log`, `verification`, and `files`.
- `GET /api/v1/audit-events?resource_type=deployment_target&resource_id={target_id}` lists the state changes. The audit log
  has no correlation-ID filter in the API (see [troubleshooting.md](troubleshooting.md)).

Note the `error_code` and `current_step`. They say where the run stopped and what failed.

### Step 2. Check the backup

- `GET /api/v1/backups/{backup_id}`: `verified` must be `true`, `files` lists every path with its `sha256`, `mode`,
  `owner`, `group` and `symlink_target`, and `restore_status` shows whether it was already restored.
- `GET /api/v1/backups?deployment_id={job_id}` lists the backups created by the job.

If `verified` is `false`, no verified restore exists. Go to section 6, step 7.

### Step 3. Look at the host (read-only)

On the target, as root. **(not run)**

```bash
# certificate currently on disk (first certificate in the file)
openssl x509 -noout -fingerprint -sha256 -in /path/to/fullchain.pem

# SHA-256 of the file on disk, to compare with the manifest
sha256sum /path/to/fullchain.pem

# what the endpoint serves right now (repeat per endpoint from the target's verification data)
echo | openssl s_client -connect 127.0.0.1:8443 -servername nginx.example.com 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256

# configuration test for the service
nginx -t
```

Compare with the backup: the previous fingerprint is in the manifest or in the backup archive (step 4). The fingerprint printed by
`openssl` is colon-separated and upper-case. CDP stores it lower-case without colons. Convert before comparing:
`| sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'`.

Do not print or copy private key files while doing this.

### Step 4. Optionally download the backup

`GET /api/v1/backups/{backup_id}/download` (needs `backups:download` and recent re-authentication). It returns a gzip tar
named `backup-<id>.tar.gz`, with `manifest.json` and `files/<path without leading slash>`. The files are **decrypted,
including private keys**, and the response is `Cache-Control: no-store`. Treat the archive as a secret. Keep it only as
long as needed, and delete it afterwards.

```bash
# (not run) with an authenticated session cookie jar
curl -sS -b cookies.txt -o backup.tar.gz https://console.example.com/api/v1/backups/<backup_id>/download
tar -tzf backup.tar.gz
tar -xzOf backup.tar.gz files/etc/nginx/ssl/fullchain.pem | openssl x509 -noout -fingerprint -sha256
```

The archive's `manifest.json` still contains `artifact_id` values, because `public_manifest` does not strip them, unlike
the API's `backup_out` (**Known issue**, minor; see [backup-restore.md](backup-restore.md) section 1.4).

### Step 5. Re-authenticate

Restore and manual rollback both need recent re-authentication, as set by `security.reauth_minutes` (default 10). Do this
in the console, or with `POST /api/v1/auth/reauth` (`password`, plus `totp` if enabled). The request needs the `X-CSRF-Token`
header (`cdp_csrf` cookie value) because it is a `POST`.

### Step 6. Restore

Use one of two endpoints. Both run the same routine (section 7).

- **Restore the backup:** `POST /api/v1/backups/{backup_id}/restore` (`backups:restore`, re-auth, CSRF). No body.
- **Roll back the target:** `POST /api/v1/deployments/{job_id}/targets/{target_id}/rollback` (`deployments:rollback`, re-auth,
  CSRF). Allowed only when the target is `completed`, `failed` or `manual_intervention_required`, and the backup is verified.

```bash
# (not run) example, after re-authenticating
curl -sS -X POST -b cookies.txt -H "X-CSRF-Token: <cdp_csrf value>" \
  https://console.example.com/api/v1/backups/<backup_id>/restore
```

Both answer **202 Accepted** at once and the work runs in the Celery task `backups.restore`. The response has `accepted`,
`backup_id`, `target_id`, `job_id`, `restore_status: "in_progress"` and (for the backup endpoint) the `backup`. Follow progress with
`GET /api/v1/backups/{id}` (`restore_status`: `in_progress`, then `restored` or `failed`) and `GET /api/v1/deployments/{job_id}`
(the target is `rolled_back`, or `manual_intervention_required` with `error_code`). Permission and re-authentication are checked in
the API; the worker authorises the user again (an `AUTHZ` outcome leaves everything unchanged). If a held lock makes the API
refuse, you get 409 `LOCK_HELD`; a broker outage gives 503 `QUEUE_UNAVAILABLE`.

### Step 7. Check the outcome

- On success, `restore_status` is `restored`. The audit event `BACKUP_RESTORED` lists the files; the served check compares each endpoint with `served_fingerprint`. The target is
  `rolled_back` (if it was in a rollback-eligible status), and the backup's `restore_status` is `restored`.
- Repeat step 3 on the host. Confirm the served fingerprint equals the previous one.
- Run discovery on the server (`POST /api/v1/servers/{id}/discover`). The installation's `drift_status` should be `in_sync`.

If the restore failed, read the target's `error_code` (or the `BACKUP_RESTORE_FAILED` audit event):

| Code | Likely cause | Action |
|---|---|---|
| `RESTORE_FAILED` | A file could not be written, or its SHA-256 or mode did not match after writing. | Check the message for the path. Check disk space (`df -h`), write permissions, the SELinux context, and whether the destination is a symlink to an unexpected target. |
| `RESTORE_CONFIG_TEST_FAILED` | The restored configuration does not pass its test. | Fix the configuration file (it may have been changed since the backup). Run `nginx -t` or the equivalent. |
| `RESTORE_RELOAD_FAILED`, or `COMMAND_FAILED` with the message "is not running" | Reload failed, or the service is not running. A stopped service is raised by the SSH layer as an error (`COMMAND_FAILED`), not as `RESTORE_RELOAD_FAILED`. | Start or restart the service manually. The manual path never restarts a stopped service (section 8). |
| `RESTORE_VERIFY_FAILED` | Files do not match the manifest afterwards (content, mode, owner or symlink target). | Something is changing the files. Check for another automation tool, config management, or a manual edit. |
| `RESTORE_SERVED_MISMATCH` | An endpoint serves a certificate other than the previous one. | Check SNI, the vhost selected for that name, a load balancer or cache in front of the server, or a second listener. |
| `LOCK_HELD` | Another deployment or restore holds a lock on one of the same paths or on the service. | Wait for that job to finish, or for its lock to expire (120 seconds after its last heartbeat). Check `deployment_locks`. Nothing was changed: target and backup keep their state (**Fixed**, K3). |

A failed restore can be repeated. Files that already match the backup are skipped.

Do not edit the database by hand to clear a target's status. The engine's guards then no longer match the host.

---

## 7. The restore routines

Both endpoints queue the task `backups.restore`, which calls `engine.run_restore` and then `restore_backup_async` in `deployment_engine.py`.

| | `POST /api/v1/backups/{id}/restore` | `POST /api/v1/deployments/{job}/targets/{target}/rollback` |
|---|---|---|
| Permission | `backups:restore`, re-auth | `deployments:rollback`, re-auth |
| Target | Optional. Attached if the backup belongs to a target in `completed`, `manual_intervention_required` or `failed`. | Required. Must belong to the job. |
| Allowed states | Any backup. | Target `completed`, `failed` or `manual_intervention_required`. Backup must be `verified`, otherwise `NO_BACKUP`. |
| Side effects | `backup.restore_status`, `restored_at`. On success, the target becomes `rolled_back` (only if attached) and the installation's fingerprint resets. | Same, always has a target. The job's `rollback_status` is set. Audit `DEPLOYMENT_MANUAL_ROLLBACK`. |
| Locks | File locks for each backed-up path, plus the service lock of **every** affected installation. | Same. |
| Served check | Every affected installation whose previous certificate can be read from the backup. | Same. |
| Scope | The whole unit (see "Shared backups" below). | Same: rolling back one target of a shared unit rolls back the whole unit. |

The routine:

1. Resolves the scope (below), takes the locks for every backed-up path and the service of every affected installation.
   Sets `restore_status = in_progress`.
2. `restore_files` once for the whole manifest (same as the automatic rollback, step 3).
3. Config test of every affected service type, then reload of every affected service with `allow_restart = false`
   (the automatic rollback uses the strategy's value). As in the engine, a reload only happens if one had started
   (`reload_started` on a target of the unit) or the deployment `completed`; a backup restored on its own always reloads.
4. `verify_files_match`.
5. Probes each endpoint of every affected installation up to 5 times, 1 second apart. A positive match with the previous
   certificate is required for each.
6. Records the outcome in `restore_status` (`restored` or `failed`), the status of **every** affected target (`rolled_back`
   or `manual_intervention_required`), the inventory of every affected installation, and the audit log
   (`BACKUP_RESTORED` or `BACKUP_RESTORE_FAILED`, with the target ids and services).

**Shared backups (fixed).** `UnitRunner` attaches one backup to every target of a unit that shares files (for example nginx
and Apache using the same certificate and key). The restore therefore resolves, via `resolve_restore_scope`: all targets
with the same `backup_id` and their installations; for a backup not tied to a deployment, all installations on that server
whose cert/key/chain/fullchain path (or realpath) appears in the manifest. All of them are one unit: one lock set, one
file restore, config test and reload per service, and verification of every endpoint. If any step fails, **all** affected
targets become `manual_intervention_required` and the error names the failing service (for example
`restore of the shared unit failed (apache, nginx; failing service: apache): ...`). Codes are unchanged. The 202 response
of both endpoints lists `unit_target_ids` and `services`, and says that the whole unit is restored when the backup is shared.

**Asynchronous (fixed).** The request only validates, checks the locks, sets `restore_status = in_progress` (and the target's
`current_step = manual_rollback`), writes the audit event (`DEPLOYMENT_MANUAL_ROLLBACK` or `BACKUP_RESTORE_REQUESTED`) and queues
the task. No second restore is refused while one is `in_progress`: a lost message would block restores for good, and the file
locks serialise two restores of the same files.

**Served check (fixed).** The manual routine requires a positive match with the previous fingerprint, like the automatic
`_verify_baseline`: an unreachable endpoint fails the restore (`RESTORE_SERVED_MISMATCH`).

---

## 8. Limitations

- **The symlink itself is not restored.** The restore writes the content of the path, which follows the link. If the link
  was changed after the backup, `verify_files_match` reports a symlink-target difference, and the rollback fails. Rollback
  cannot repair a changed link. The helper keeps the link during `install`.
- **No check that the backup is the latest.** Restoring an older backup overwrites newer files for every backed-up path,
  with no warning. Nothing compares the on-disk content with the deployment's expected content before overwriting, beyond
  skipping files that already match the backup.
- **The manual reload never restarts.** `restore_backup_async` calls `reload(host, False)`. A stopped service therefore fails
  the restore (`RESTORE_RELOAD_FAILED`) even when the automatic rollback would have restarted it.
- **Synchronous HTTP work: fixed.** See section 7.
- **Lock conflicts (K3): fixed.** `classify()` maps `LockHeld` to `LOCK_HELD`; the API answers 409 and the worker leaves the target
  and backup unchanged.
- **`chain_valid` is not checked** by rollback or by the manual routine. This matches the forward path.
- **Restore does not re-run preflight.** It does not check current disk usage, locks held by other jobs (beyond the file and
  service locks it takes), or whether the service is currently healthy.
- **Restore is only as good as the backup.** Every backup is written before the change, but a backup taken from a file that
  was already wrong keeps that state. Nothing checks the backup's contents against any certificate policy.

---

## 9. Test coverage

Live tests in `backend/tests/integration/test_deploy_live.py` (not run for this page):

- (e) config test fails after a real key mismatch: rolls back, verifies the old certificate is served and the tree is
  byte-identical.
- (f) endpoint serves another certificate: rolls back and checks the previous certificate.
- (g) rollback fails during restore: `manual_intervention_required`, then a verified manual restore brings the target back.
- (k) worker killed mid-activation: rolls back as `WORKER_INTERRUPTED`, classified `mixed`.
- (l) canary failure: rolls back the canary and skips the rest.

Unit tests (names read; not run): `test_rollback_failure_needs_manual_intervention`,
`test_rollback_failure_when_previous_cert_not_served_again`, `test_resume_after_crash_between_installs_rolls_back`,
`test_resume_after_crash_with_all_files_new_continues_to_verification` in `test_engine.py`. The manual restore and
rollback API, including the re-authentication and operator-denied cases, is in `test_list_get_events_cancel_retry_and_backups_api`
in `test_deploy_api.py`. Backup creation, verification and restore are in `tests/unit/deploy/test_backups.py`.

New unit tests in `test_d3_engine.py` cover the lock-held restore (K3), the queued restore and rollback, the worker's second
authorisation, the finalize recovery paths (K2) and lost locks (K6). As far as the test names show, no test covers a manual
restore that hits an endpoint which is down, or a symlink changed after the backup.

---

## 10. Known issues status

| # | Issue | Status |
|---|---|---|
| K2 | Failure after verification marked the target `failed` with the new files in place. | **Fixed.** Retried finalize; `completed` or `manual_intervention_required` (deployment-engine section 12). |
| K3 | A manual restore blocked by a lock was `INTERNAL_ERROR` and set `manual_intervention_required`. | **Fixed.** `LOCK_HELD`, 409 at the API, state unchanged. |
| K6 | A lost lock did not stop the work. | **Fixed.** `LOCK_LOST` before the next mutating step; rollback if already activated. |
| K7 | Cancellation is not honoured after activation starts. | **Kept** (it would leave mixed files). The cancel response says `too_late`. |
| - | Manual restore and manual target rollback ran inside the HTTP request. | **Fixed.** 202 and Celery task `backups.restore`; the worker re-authorises. |
| - | Manual served check accepted an unreachable endpoint (section 7). | **Fixed.** A positive fingerprint match is required. |
| - | Manual restore of a backup shared by several targets/services handled only the primary one. | **Fixed.** One unit: all services and endpoints are locked, restored, reloaded, verified and recorded together (section 7). |
| - | The initiating user was revoked during an interrupted deployment and mid-mutation targets were just cancelled. | **Fixed.** The system restores the previous state (deployment-engine section 13.1). |
