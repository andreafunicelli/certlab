# Deployment engine

How Cert Deploy Pro (CDP) replaces certificates on managed servers: pre-flight planning, approval, the strategy
scheduler, the per-target state machine, locking, backup, activation, verification, crash recovery, and the validation
findings that gate it.

Basis: source at commit `a353f1e`. Read in full: `services/deployment_planner.py`, `services/deployment_engine.py`,
`services/deployments.py`, `services/backups.py`, `services/locks.py`, `services/uploads.py`,
`integrations/certificates/validate.py` and `parse.py`, `integrations/services/adapters/`, `workers/`, and the helper
`infra/remote-helper/cdp-helper`. The live tests `backend/tests/integration/test_deploy_live.py` (scenarios a to l) and the
unit suites under `backend/tests/unit/deploy/` were read for what they assert. **No test was run for this page.** Runtime
claims that rest on reading alone are marked **(unverified)**. Defects found by reading are marked **Known issue**. A few
were reproduced by calling the real functions on fake input (for example, the verification SNI in section 11); those
say so.

Related: [certificate-discovery.md](certificate-discovery.md) (where the installations come from),
[rollback.md](rollback.md) (automatic rollback and manual recovery), [backup-restore.md](backup-restore.md) (backup
storage), [ssh-permissions.md](ssh-permissions.md) (what the helper may do),
[architecture.md](architecture.md) (job pipeline), [security.md](security.md) (roles and re-authentication).

---

## 1. Lifecycle at a glance

1. **Plan (optional).** `POST /api/v1/deployments/plan` returns a read-only plan with every finding. Nothing is written.
2. **Create.** `POST /api/v1/deployments` with an `Idempotency-Key` header. The service runs the same preflight again. Any
   blocking finding returns 409 `PREFLIGHT_BLOCKED`. Unacknowledged warnings return 422. Otherwise the job is stored with
   one target per installation, status `pending` or `awaiting_approval`.
3. **Approve** if required (section 4.2). Approval moves the job to `pending` and dispatches it.
4. **Worker start** (`deployments.run`, `JobRunner`). The job lock is taken. If the job is still `pending` or `preflight`,
   preflight runs again, because the state may have changed since creation. Status becomes `activating`.
5. **Units and batches.** Targets that write the same file on the same server form one unit. Units are run in batches
   according to the strategy (section 5). Units on one server never run at the same time.
6. **Per unit** (`UnitRunner`): connect, lock, recheck, backup, stage, validate, activate, config test, reload, verify,
   cleanup, finalize. Any failure after activation starts an automatic rollback (see [rollback.md](rollback.md)).
7. **Final status** from `_finalize` (section 6.2). Notifications `deployment.completed` or `deployment.failed` are sent.

---

## 2. Permissions

| Action | Permission | Notes |
|---|---|---|
| Plan | `deployments:plan` | Operator and admin. |
| Create | `deployments:create` | Operator and admin. `continue_on_failure` and `exception_approvals` need `deployments:approve` (admin). |
| Approve | `deployments:approve` | Admin only, with recent re-authentication (`REAUTH_REQUIRED` otherwise). |
| Cancel | `deployments:cancel` | Operator and admin. |
| Retry | `deployments:retry` | Operator and admin. |
| Manual target rollback | `deployments:rollback` | Admin only, with re-authentication. |

Re-authentication window: `security.reauth_minutes`, default 10 (`services/auth.py`, `require_recent_reauth`). The
permission matrix is in `core/permissions.py`.

---

## 3. Pre-flight planning

### 3.1 When it runs

| Point | Function | Effect |
|---|---|---|
| `POST /deployments/plan` | `deployments.plan` -> `build_plan` | Returns the plan. Nothing is stored. |
| `POST /deployments` | `deployments.create` -> `build_plan` | Blocks creation on blocking findings. The plan is stored in `dry_run_plan`. |
| Worker start, for a `pending` or `preflight` job | `_preflight` -> `build_plan_async` | Aborts the job with `PREFLIGHT_FAILED` and the codes. |
| Resume after a crash | not run | The recorded per-target plan is used. |

The plan's `summary.can_proceed` is true only when there are no blocking findings, no unacknowledged warnings, at least
one target, and every selected installation has a target.

### 3.2 Dry-run guarantees

`build_plan` is read-only. The planner module states that the integration test `test_i_dry_run_leaves_remote_filesystem_byte_identical`
asserts the remote tree is byte-identical afterwards. That test was not run for this page. What the dry run does, from the
code:

- Connects over strict SSH, then calls helper `probe`.
- Calls helper `stat` on every destination and on each key path.
- Calls helper `read-public` on each current certificate. For a combined PEM it calls `backup_file` and keeps the bytes in
  memory only.
- Calls the service's own config test (`nginx -t`, `apachectl configtest`, `haproxy -c`) to learn whether the current
  configuration is valid. The planner does not change files itself. Whether a config test has side effects is
  **(unverified)** for each service.
- Calls helper `df` for free space.
- Opens TLS connections to each verify endpoint (5 s timeout).
- Reads the database for locks, active deployments and manual-intervention targets.

It never calls `stage-dir`, `write-staged`, `install` or `reload`, and it stores no backup.

### 3.3 Findings

Severity meanings:

- **blocking**: create is refused (409 `PREFLIGHT_BLOCKED`), and a worker start aborts the job.
- **warning**: must appear in `acknowledged_warnings` by code, or create returns 422 `WARNINGS_NOT_ACKNOWLEDGED`.
- **info**: shown only.

**Candidate and version checks** (`build_plan_async`, `validate_bundle`):

| Code | Severity | Meaning |
|---|---|---|
| `VERSION_NOT_DEPLOYABLE` | blocking | Version is `rejected` or `superseded`. |
| `VERSION_INVALID` | blocking | Version failed validation. |
| `VERSION_INTEGRITY` | blocking | Stored certificate does not match the recorded fingerprint. |
| `KEY_MISMATCH` | blocking | Private key does not match the certificate. |
| `WEAK_KEY`, `WEAK_SIGNATURE`, `UNSUPPORTED_KEY_ALGORITHM` | blocking | Policy minimums (section 16). |
| `CERT_EXPIRED`, `CERT_NOT_YET_VALID`, `IS_CA_CERT` | blocking | Validity and type. |
| `CHAIN_INVALID`, `CHAIN_UNTRUSTED` | blocking or warning | Chain problems (section 16). |
| `EXPIRES_SOON`, `CHAIN_INCOMPLETE`, `CHAIN_POLICY_VIOLATION`, `SAN_MISSING_CN_FALLBACK` | warning | Must be acknowledged. |

**Per-installation eligibility and files:**

| Code | Severity | Meaning |
|---|---|---|
| `CERTBOT_MANAGED` | blocking | Installation is managed by certbot. Section 15. |
| `INSTALLATION_NOT_DEPLOYABLE` | blocking | Classification is `unsupported`, `unreadable`, `error` or `requires_mapping`. |
| `UNSUPPORTED_SERVICE` | blocking | No adapter for the installation's `service_type`, such as `filesystem`. |
| `PLAN_ERROR` | blocking | The adapter refuses the file layout (for example nginx with a combined PEM). |
| `KEY_REQUIRED` | blocking | Version has no key and the installation does not reuse the existing key. |
| `REUSE_KEY_MISMATCH` | blocking | Reuse requested, but the new certificate has a different public key from the installed one. |
| `REUSE_KEY_UNVERIFIABLE` | blocking | Reuse requested, but the installed certificate cannot be read to compare. |
| `REUSE_KEY_UNAVAILABLE` | blocking | Reuse of a combined PEM key, but the key cannot be extracted from the installed file. |

**Host, privilege and service checks:**

| Code | Severity | Meaning |
|---|---|---|
| `SERVER_DISABLED` | blocking | Server is disabled. |
| `HOST_KEY_UNKNOWN` | blocking | No SSH host key enrolled. |
| `CONNECT_FAILED` | blocking | SSH failed. The SSH error code is in `details.remote_error`. |
| `HELPER_UNAVAILABLE` | blocking | Helper missing, sudo denied, or privilege mode is not `helper-sudo`. |
| `UNSUPPORTED_OS` | warning | OS is not in `SUPPORTED_OS_IDS` (`ubuntu`, `debian`, `rhel`, `rocky`, `almalinux`, `ol`). |
| `SERVICE_NOT_INSTALLED` | blocking | The service is not installed on the server. |
| `CONFIG_BROKEN` | blocking | The current configuration fails its own test. Fix it before deploying. |

**Current state on disk:**

| Code | Severity | Meaning |
|---|---|---|
| `PATH_UNREADABLE` | blocking | `stat` failed or the file is not readable. |
| `PATH_MISSING` | blocking | Destination is missing or a broken symlink. The tool never creates it. |
| `PATH_NOT_REGULAR` | blocking | Destination is a directory or other non-file. |
| `PATH_TOO_LARGE` | blocking | Destination is over 10 MiB. |
| `SYMLINK` | info | Destination is a symlink. The link is kept and its target replaced. |
| `CURRENT_CERT_UNREADABLE` | warning | Installed certificate could not be read or parsed. |
| `CURRENT_KEY_MISMATCH` | warning | Installed combined PEM's key does not match its certificate. |
| `INVENTORY_STALE` | blocking, acknowledgeable | Disk differs from the last inventory observation. Acknowledging it with the code downgrades it. |
| `INVENTORY_UNKNOWN` | info | No inventory baseline. |
| `ENDPOINT_SERVES_DIFFERENT_CERT` | warning | Verify endpoint currently serves a certificate other than the file on disk. |

**Replacement comparison** (also `validate_bundle` against the installed certificate):

| Code | Severity | Meaning |
|---|---|---|
| `SAN_MISMATCH` | blocking | A required hostname is not covered. **The only code that an administrator can except** (section 3.4). |
| `SHORTER_VALIDITY_THAN_CURRENT` | warning | New certificate expires before the one on disk. |
| `SAME_AS_CURRENT` | info | Identical certificate. |
| `REPLACES_DIFFERENT_KEY_TYPE` | info | Key type or size changes. |

**Capacity and verification:**

| Code | Severity | Meaning |
|---|---|---|
| `DISK_SPACE` | blocking | Free space below `max(4 x new content, 1 MiB)`. |
| `DISK_CHECK_FAILED` | warning | `df` failed. |
| `NO_VERIFY_ENDPOINT` | blocking, or info with `allow_file_only_verification` | No endpoint can be derived. |
| `VERIFY_ENDPOINT_UNREACHABLE` | blocking, or info with `allow_file_only_verification` | Endpoint did not answer the baseline probe. |

**Cross-target and concurrency:**

| Code | Severity | Meaning |
|---|---|---|
| `PATH_CONTENT_CONFLICT` | blocking | Two installations share a file on the same server but need different content, mode or owner. |
| `SHARED_PATH_NOT_IN_PLAN` | blocking | A file in the plan is also used by an installation that is not in the plan. All sharers must be deployed together. |
| `MANUAL_INTERVENTION_PENDING` | blocking | A previous deployment on this installation needs manual intervention. |
| `ACTIVE_DEPLOYMENT` | blocking | Another job for the installation is pending or running. |
| `LOCKED` | blocking | A lock is held on a file or service key (section 8). |

An unknown installation ID is not a finding: the planner raises `INSTALLATION_NOT_FOUND` (HTTP 404). Any other error code
raised while building a target is passed through as a blocking finding.

### 3.4 Acknowledgements and exceptions

- **Acknowledgement:** list each warning code in `acknowledged_warnings`. Creation with an unacknowledged warning returns
  422 `WARNINGS_NOT_ACKNOWLEDGED`. The worker checks again at start.
- **Exception approvals:** `exception_approvals` (admin only) can except `SAN_MISMATCH` only, for one installation or for
  all. The justification must be at least 10 characters. An excepted finding becomes a warning with the text
  `(administrator exception recorded)`. The exception is stored in `strategy.exceptions`.
- **Unit tests:** `test_continue_on_failure_requires_admin_and_keeps_going` and
  `test_production_requires_approval_by_a_second_admin_with_recent_reauth` cover the admin paths (names read; not run).

---

## 4. Creating, approving, cancelling and retrying

### 4.1 Idempotency

- `POST /api/v1/deployments` requires `Idempotency-Key`, 1 to 80 characters (400 `IDEMPOTENCY_KEY_REQUIRED` otherwise).
- The stored key is `<user id hex>:<key>`, so keys are scoped per user (test `test_idempotency_keys_are_scoped_per_user`).
- A SHA-256 hash over the canonical request body is stored: version, installation IDs in the order given, strategy,
  sorted acknowledged warnings, and exception approvals. A different body with the same key returns 409
  `IDEMPOTENCY_KEY_CONFLICT`.
- A replay returns the existing job with HTTP 201 and `"idempotent_replay": true`. It is not planned again and is not
  dispatched again.

### 4.2 Approval

`_needs_approval` returns true when any target's environment has `requires_approval`, or has `is_production` and
`security.require_production_approval` is on (default true).

- The job starts as `awaiting_approval`. Nothing is dispatched.
- `POST /api/v1/deployments/{id}/approve` needs `deployments:approve` and recent re-authentication. The job becomes
  `pending` and is dispatched. The plan is not stored again at approval time, but the worker re-runs preflight on start.
- The initiator cannot approve their own job unless `security.allow_self_approval` is true (default false). A refusal is
  403 `SELF_APPROVAL_FORBIDDEN` and is audited as `DEPLOYMENT_APPROVAL_DENIED`.

### 4.3 Cancelling

- `awaiting_approval`: cancelled at once, and all targets become `cancelled` with `CANCELLED`.
- Any other non-terminal job: `cancel_requested` is set. It is honoured only at the checkpoints in section 14.
- A `pending` job whose message never reached a worker is not cancelled by this call (section 18, K5).

### 4.4 Retrying

`POST /api/v1/deployments/{id}/retry` (`deployments:retry`) works only for a finished job with targets in `failed` or
`rolled_back`. It creates a new job for those installations, with the same strategy and acknowledgements, a new internal
idempotency key, and `retry_of` set. Preflight runs again in full. `manual_intervention_required` targets are not
retried (see [rollback.md](rollback.md)).

---

## 5. Strategy

Strategy fields are normalised by `normalize_strategy`. Defaults come from the `ssh` settings section
(`schemas/settings.py`).

| Field | Default | Range | Effect |
|---|---|---|---|
| `mode` | `canary` if `ssh.canary` is true, else `batch` | `canary`, `batch`, `all` | How units are grouped into batches. |
| `concurrency` | `ssh.deployment_concurrency`, 3 | 1 to 50 | Maximum units running at once. |
| `failure_threshold` | `ssh.failure_threshold`, 1 | 0 to 100 | Stop starting new units once this many have failed. 0 means never stop. |
| `continue_on_failure` | false | boolean; admin only | Ignore the threshold. |
| `allow_restart` | false | boolean | Passed to reload as `--allow-restart`. The service may be restarted instead of reloaded. |
| `allow_file_only_verification` | false | boolean | Accept no endpoint, or an unreachable endpoint, and verify by file hash only. |
| `verify_retries` | 5 | 1 to 30 | Probes per endpoint. |
| `verify_delay_seconds` | 1.5 | 0 to 60 at the API | Pause between probes. |

### 5.1 How the strategy is applied

- **Units.** Targets that write the same real path on the same server are merged into one unit (union-find over
  `realpath`). The unit has one connection and one lock set. Units never run in parallel on one server, even when
  `concurrency` is greater than 1 (`JobRunner._server_locks`).
- **canary.** The first unit runs alone in batch 0. Batches 1 and later start only when the canary unit succeeds. A failed
  canary cancels every later unit with `SKIPPED` and the reason `canary target did not succeed`.
- **batch.** Units are grouped into batches of `concurrency`.
- **all.** One batch. `concurrency` still limits how many units run at once.
- **Threshold.** A unit that ends in any state other than `completed` or `cancelled` counts as a failure. When failures
  reach a threshold above 0, and `continue_on_failure` is off, each pending unit is cancelled with `SKIPPED`
  `failure threshold reached (n/thr)`. Units already running are not stopped.
- **Cancellation** (`cancel_requested`) cancels pending units with `SKIPPED` and the reason `cancelled by user`.

Live test (l) (`test_l_multi_target_canary_failure_stops_further_activations`) covers the canary stop, and the unit tests
cover the threshold and canary paths (names read; not run).

### 5.2 `allow_restart`

Without it, a reload of a stopped service makes the helper exit 13 (`NOT_RUNNING`). The SSH layer raises that as an error
rather than a reload result, so the `reload` step fails with code `COMMAND_FAILED` and the target rolls back. With it,
the helper starts or restarts the service (section 11). A restart drops connections. **No live test
uses `allow_restart`** (checked by searching `test_deploy_live.py`).

---

## 6. State machines

### 6.1 Target statuses

Each target has one status. The table is what the engine writes (`set_status` and `step`).

| Status | Set by | Terminal |
|---|---|---|
| `pending` | created by `create`. Also still shown during `connect`, `lock` and `recheck`, which do not change status. | No |
| `backing_up` | `backup` step | No |
| `staging` | `stage` step | No |
| `validating` | `validate` step | No |
| `activating` | `activate` and `config_test` steps | No |
| `reloading` | `reload` step | No |
| `verifying` | `verify` step | No |
| `completed` | `finalize` | Yes |
| `failed` | pre-mutation failure (`_run`), or a failure after verification (**Known issue** K2) | Yes |
| `cancelled` | cancellation at a checkpoint (`CANCELLED`), or `SKIPPED` by the scheduler | Yes |
| `rolling_back` | `rollback` step | No |
| `rolled_back` | verified rollback | Yes |
| `manual_intervention_required` | rollback failed, or a resume could not reconcile the state | Yes, but it blocks new deployments to that installation (`MANUAL_INTERVENTION_PENDING`) |

`preflight` is a job status only. No target is ever set to it.

### 6.2 Job statuses

| Status | Meaning |
|---|---|
| `awaiting_approval` | Stored, not dispatched. |
| `pending` | Dispatched or approved, waiting for a worker. |
| `preflight` | Worker is re-running preflight. |
| `activating` | Running. (The schema has no generic `running`.) |
| `completed` | Every target completed. |
| `partially_failed` | Some targets completed, and others did not. |
| `failed` | Preflight aborted, or a failure with no completed target. |
| `rolled_back` | Targets rolled back and none completed. |
| `cancelled` | Cancelled before any change. |
| `manual_intervention_required` | At least one target needs manual recovery. Takes precedence over the others. |

`_finalize` picks the first match in this order: any `manual_intervention_required`; all `completed`; some `completed`;
any `failed`; any `rolled_back`; otherwise `cancelled`. The job's `rollback_status` is set separately.

---

## 7. Steps

Each target records its steps in `deployment_targets.steps` (name, status `running`, `ok` or `failed`, times, error code,
redacted detail). `GET /api/v1/deployments/{id}` returns them.

| Step | Target status during step | What it does | Typical failure codes |
|---|---|---|---|
| `connect` | unchanged | Opens a strict-host-key SSH session for the unit. | SSH codes (see [troubleshooting.md](troubleshooting.md)). |
| `lock` | unchanged | Takes the lock set (section 8). | `LOCK_HELD` |
| `recheck` | unchanged | Compares each destination's current SHA-256 with the plan. | `FILE_CHANGED_SINCE_PREFLIGHT` |
| `backup` | `backing_up` | Creates and verifies the central backup (section 9.1). | `BACKUP_FAILED` |
| `stage` | `staging` | Renders each artifact, writes it to the staging directory, and checks the remote SHA-256. | `PLAN_CONTENT_MISMATCH`, `STAGED_HASH_MISMATCH`, `DISK_FULL` |
| `validate` | `validating` | Local checks on the exact bytes (section 9.2). | `STAGED_CERT_MISMATCH`, `STAGED_KEY_MISMATCH`, `STAGED_KEY_INVALID` |
| checkpoints `before_backup`, `before_activation` | unchanged | Cancellation and authorisation check (section 14). | `CANCELLED`, `AUTHZ` |
| `activate` | `activating` | Installs each staged file (section 10). | `INSTALL_HASH_MISMATCH`, `PERMISSION_DENIED`, `DISK_FULL`, `PATH_NOT_ALLOWED` (includes helper `SYMLINK_DEST` and `PRIVATE_KEY_REFUSED`) |
| `config_test` | `activating` | Runs the config test for each service. | `CONFIG_TEST_FAILED` |
| `reload` | `reloading` | Reloads each service. | `RELOAD_FAILED` |
| `verify` | `verifying` | Probes endpoints and re-hashes files (section 11). | `VERIFY_*` (section 11.3) |
| `cleanup` | unchanged | Removes the staging directory. | |
| `finalize` | unchanged | Writes installation and version state (section 12). | **Known issue** K2 |
| `rollback` | `rolling_back` | Restores the backup (`rollback.md`). | `ROLLBACK_*` |
| `reconcile` | unchanged | Resume-only classification (section 13). | `RECONCILE_FAILED` |

---

## 8. Locks

Lock state is in the `deployment_locks` table (`services/locks.py`). It is durable, so it survives a worker restart.

| Lock | Resource key | Taken by |
|---|---|---|
| File | `<server_id>:<realpath>` | Each file the unit replaces. |
| Service | `<server_id>:service:<type>` | Each service type of the unit. |
| Job | `job:<job_id>` | `JobRunner`, for the whole job. |

- **Acquire** is one atomic `INSERT ... ON CONFLICT DO UPDATE ... WHERE`. A lock is taken over only if it has expired, or
  if the same job already holds it (so a resumed worker re-acquires its own locks).
- **TTL** is 120 seconds (`DEFAULT_TTL_SECONDS`). A holder renews every 20 seconds (`HEARTBEAT_SECONDS`). After a crash, a
  lock is free at most 120 seconds after the last heartbeat.
- **Acquisition is all-or-nothing** in sorted key order. A conflict releases the locks already taken and raises
  `LOCK_HELD`.
- **Release** happens in `finally`, and only if the owner matches.
- **Planning** reports a held lock as `LOCKED` (blocking). Other jobs' targets are reported as `ACTIVE_DEPLOYMENT`.
- **Purge:** `deployments.purge_locks` runs every 10 minutes and deletes expired rows.
- **Job lock conflict:** if another live worker holds the job lock, the Celery task retries after 30 seconds, up to 60
  times (`deploy_tasks.run_deployment`).

**Known issue (K6).** `LockSet.lost` is set when a heartbeat renewal fails, and a log line is written. Nothing reads the
flag, so the engine keeps working after a lock is lost (grep confirms no reader).

---

## 9. Backup, staging and validation

### 9.1 Backup (`backup` step)

- `backups.create_backup` reads each destination with helper `backup` (base64, at most 10 MiB per file).
- The SHA-256 of the returned bytes must equal the remote SHA-256 from `stat`, or the backup fails with
  `BACKUP_FAILED` ("changed or was corrupted while it was read").
- Each file is encrypted and stored as a vault artifact (`purpose = backup`). The manifest records the path, real path,
  SHA-256, size, mode, uid and gid, owner, group, symlink target, SELinux context, and the artifact ID. It never holds
  content.
- The manifest is authenticated with an HMAC (section 1.3 of [backup-restore.md](backup-restore.md)). The backup is
  **verified** only after every artifact has been decrypted and re-hashed. A failed verification discards the new
  artifacts and fails with `BACKUP_FAILED`.
- For a unit, all targets point at the same backup.
- Before the first change, the backup's SHA-256 for each file must match the value recorded at preflight, or the run
  fails with `FILE_CHANGED_SINCE_PREFLIGHT`.

### 9.2 Staging and validation

- `stage_dir` creates `/var/lib/cdp-helper/staging/s.XXXXXXXX` (mode 0700). Each artifact is written with `write-staged`
  as base64 on stdin, mode 0600, named `NN-<artifact>.pem`. The remote SHA-256 must equal the planned value.
- A combined PEM that reuses its key takes the key from the backup (`load_private_key` on the backup bytes), never from
  the database.
- `check_staged` validates the bytes that are about to be installed:
  - For `cert`, `fullchain` and `combined`, the first certificate must have the new leaf's fingerprint.
  - For `key` and `combined`, if the content contains `PRIVATE KEY`, it must match the new certificate.

  This is a check of the local render. The remote copy is checked by hash only.

---

## 10. Activation order and shared files

- Files are ordered by `(artifact != key, destination path)`, so **private keys are installed first**.
- Each file is installed with helper `install`. The helper writes a temporary file in the destination directory, sets
  owner, group and mode, and renames it over the destination. A symlink destination keeps the link and replaces its target.
  The post-install SHA-256 must equal the planned value (`INSTALL_HASH_MISMATCH` otherwise).
- Mode and owner come from the file on disk (`st.mode`, `st.owner`). The adapter defaults (`0644` for certificates,
  `0600` for keys) are used only when the current mode cannot be read.
- Reused keys are not written (`action = keep`). For a combined PEM, the file is rebuilt from the new leaf, the chain
  and the existing key.
- **Shared-file units.** Two installations that write the same real file on one server are one unit and are written once.
  Their content must match (`PATH_CONTENT_CONFLICT` otherwise).
- Adapter file layouts (`integrations/services/adapters/builtin.py`):
  - nginx: `ssl_certificate` gets the full chain (leaf plus intermediates), `ssl_certificate_key` gets the key.
  - apache with `SSLCertificateChainFile`: the certificate file gets the leaf, the chain file gets the intermediates.
    Without a chain file: the certificate file gets the full chain (requires Apache 2.4.8 or later, per the code comment).
  - haproxy: one combined file of leaf, then intermediates, then key.

---

## 11. Config test, reload and verification

### 11.1 Config test and reload

- `config_test` runs once per service type of the unit: `nginx -t`, `apachectl configtest` (or `apache2ctl configtest`;
  a bare `httpd` binary gets `-t`), `haproxy -c -f ...`. A failed test (helper exit 9) gives `CONFIG_TEST_FAILED`, and the
  first 300 characters of output are stored in the step detail.
- `reload` sets `reload_started` before it runs, so a later rollback knows whether to reload again. It runs
  `cdp-helper reload <service> [--allow-restart]`. A failed reload reported by the helper (exit 9) gives `RELOAD_FAILED`.
  Other helper failures, such as `NOT_RUNNING` (exit 13), are raised by the SSH layer and reach the rollback with the
  SSH error code (`COMMAND_FAILED`).
- Reload per service, from `cdp-helper` (`cmd_reload`):
  - nginx: `systemctl reload nginx` if systemd and a unit exist, otherwise `nginx -s reload`. With `allow_restart`, a
    failed reload is followed by a restart.
  - apache: `systemctl reload <unit>`, otherwise `apachectl -k graceful`. With `allow_restart`, `-k restart`.
  - haproxy: `systemctl reload haproxy`, otherwise a seamless reload with `haproxy -sf <old pid>` (pidfile
    `/run/haproxy.pid`).

**Unverified:** the systemd branches are not exercised by the live target. Its setup script says it has no systemd
(`infra/test-target/setup-local.sh`, header).

### 11.2 Verify endpoints

Endpoints come from `verify_endpoints_for(installation, server)`:

- host: `verify_host`, else the server address, else the hostname;
- port: `verify_port`, else `listen_port`;
- SNI: `verify_sni`, else `vhost`, else the first usable server name.

**Known issue (K1): the `vhost` fallback is not a hostname.** `vhost` is the composite `names:ports` string described in
[certificate-discovery.md](certificate-discovery.md) section 6.4. Discovery normally sets `verify_sni` to a usable name,
but it leaves it empty for:

- a wildcard-only `server_name`, such as `*.example.com`;
- a server with no `server_name`, such as the nginx default server or an haproxy bind with no names.

For these installations the planner's SNI becomes a non-hostname string. This was checked by calling the real
`_Resolver.resolve()` and `planner.verify_endpoints_for()` on a fake host (a read-only run). The results were
`*.example.com:443` for the wildcard case and `-:8443` for the nameless case. Neither can match a certificate's
hostname check, so the verification at the end of a deployment fails (`VERIFY_HOSTNAME_MISMATCH` or
`VERIFY_UNREACHABLE`), and the deployment rolls back unless `allow_file_only_verification` is set. Installations with
an explicit `verify_sni` are not affected. The live tests and unit fixtures always set `verify_sni`, so no test
exercises this path. The inventory verify action uses a separate rule (`inventory.endpoint_for`) that skips wildcards,
so the same installation can pass "Verify" and still fail a deployment.

Work-around until fixed (**unverified**): set `verify_sni` on the installation with `PATCH /api/v1/installations/{id}`.

### 11.3 Verification procedure

`_verify_new` runs per endpoint. Each probe is `probe_endpoint` with a 5-second timeout and the configured trust anchors.

1. Probe up to `verify_retries` times, with `verify_delay_seconds` between probes. Stop as soon as the served leaf matches
   the new fingerprint.
2. Evaluate each endpoint:

| Outcome | Result |
|---|---|
| Not reachable, file-only not allowed | `VERIFY_UNREACHABLE` (rollback). |
| Not reachable, file-only allowed | Mode `file_only` for this endpoint. |
| Served fingerprint differs from the new leaf | `VERIFY_FINGERPRINT_MISMATCH` (rollback). |
| SNI set and hostname does not match the leaf (checked only when the served certificate is the new one) | `VERIFY_HOSTNAME_MISMATCH` (rollback). |
| No endpoint, file-only not allowed | `VERIFY_NO_ENDPOINT` (rollback). |
| No endpoint, file-only allowed | Mode `file_only`. |

3. Re-hash every destination. Any difference from the plan is `VERIFY_FILE_MISMATCH` (rollback).
4. Store the result in `target.verification`: `mode` (`live` or `file_only`), endpoint rows, file hashes, `chain_valid`,
   and a timestamp.

`chain_valid` is recorded per endpoint and in aggregate. **It is not enforced.** A `False` value does not fail the
deployment. The probe checks the chain against the configured trust anchors or the system store.

---

## 12. Completion (`finalize`)

- A `certificates` row is created from the new leaf if none exists. A race with another creator is tolerated with a
  savepoint.
- For each target's installation: `last_observed_fingerprint` and `last_observed_at` are set to the new leaf,
  `last_deployment_id` is set to the job, `drift_status` is `in_sync`, `certificate_id` is set, and `last_verification`
  records `ok: true` with `source: deployment` and the verify mode.
- The version becomes `deployed`, and its `certificate_id` is set if it was empty.
- The target and the job become `completed`. Notifications are sent at job level.

---

## 13. Crash recovery (resume)

When a worker dies, the job's `acks_late` task is redelivered, and `JobRunner` runs again. A target that was in a
**mutating** state (`activating`, `reloading`, `verifying`, `rolling_back`) is resumed by `_resume`. The `reconcile` step
compares the remote files with two references:

- `expected`: the planned new SHA-256 for each file (saved in the target state before staging);
- the backup manifest (previous SHA-256).

| Classification | Meaning | Action |
|---|---|---|
| `all_new` | Every file already holds the new content. | Skip install. Continue at config test, reload and verify. |
| `all_previous` | Every file holds the previous content. | Roll back. |
| `mixed` | Some files are new, some previous. | Roll back. |
| `no_backup` or `backup_corrupt` | Nothing reliable to restore to. | `manual_intervention_required` (`RECONCILE_FAILED`). |

A target in `rolling_back` always rolls back again. An SSH failure during reconcile is also
`manual_intervention_required` (`RECONCILE_FAILED`). Targets in pre-mutation states (`pending`, `backing_up`, `staging`,
`validating`) are simply run from the start, with a new backup.

Consequence: a crash after the target status becomes `activating` but before the first file is installed is classified
`all_previous`, so the target ends `rolled_back`, not retried. Live tests `test_k_worker_killed_mid_activation_then_resumed`
and `test_k2_crash_after_all_files_installed_continues_without_reinstalling` cover the `mixed` and `all_new` cases (names
read; not run). Unit tests cover resume in `test_engine.py`.

---

## 14. Cancellation checkpoints

Cancellation is checked only at these points:

| Checkpoint | Before |
|---|---|
| `start` | Any remote call (not on resume). |
| `before_backup` | Backup. |
| `before_activation` | First install. |

At a checkpoint, a cancel request stops the unit with status `cancelled` and the text `cancelled by user before any change
was made`. The staging directory is removed. Nothing has been changed on the remote host at that point.

**After `before_activation`, a cancel request is not honoured.** The unit continues to completion or to a rollback.
`cancel_requested` stays set on the job.

Each checkpoint also re-checks the initiating user. A disabled user, or one who lost `deployments:create`, produces an
`AUTHZ` error. Before activation that is a plain `failed`. After activation it triggers a rollback.

---

## 15. Certbot policy

Installations whose path is under `/etc/letsencrypt/live/` (or whose real path is under `archive/`) are `managed_by_certbot`.
Preflight blocks them with `CERTBOT_MANAGED`, and creation returns 409. This is covered by live test (j).

The blocking message says to use "a certbot deploy hook instead (see docs: 'certbot deploy hooks')". **No such document is in
this repository** (searched `docs/` and the backend), and no hook integration exists in the code. The message points readers
at something that is not here.

---

## 16. Validation findings

These codes are produced when a certificate version is uploaded and when it is validated again. Deployment preflight
reuses most of them (section 3.3). Severities are those in the source.

### 16.1 Parsing (`integrations/certificates/parse.py`, `services/uploads.py`)

| Code | Severity | Meaning |
|---|---|---|
| `CERT_PARSE_ERROR` | blocking | Input is not a valid certificate, or a JKS keystore (refused: "convert to PKCS#12 or PEM"). |
| `KEY_PARSE_ERROR` | blocking | The key field does not contain a PEM private key. |
| `KEY_PASSPHRASE_REQUIRED` | blocking | Encrypted key with no passphrase. |
| `KEY_PASSPHRASE_INVALID` | blocking | Wrong passphrase. |
| `UNSUPPORTED_KEY_ALGORITHM` | blocking | Key algorithm not supported, or a PKCS#12 algorithm that is not supported. |
| `PKCS12_PASSWORD_OR_DATA_INVALID` | blocking | PKCS#12 would not open: wrong password or corrupt. |
| `INPUT_TOO_LARGE` | blocking | Input over 256 KiB. |
| `TOO_MANY_CERTS` | blocking | More than 10 certificates. |
| `AMBIGUOUS_LEAF` | warning | More than one end-entity candidate. The first one is used. |
| `UNRELATED_CERTS` | warning | Certificates not on the leaf's chain are ignored. |
| `KEY_ENCRYPTED_INPUT` | info | Passphrase-protected key: stored and deployed unencrypted. |
| `NO_LEAF` | blocking | No leaf could be identified. |

PKCS#12 uploads are accepted. The leaf, chain and key are extracted. The key is kept in the vault (encrypted at rest) but
deployed unencrypted. Upload is limited
to 256 KiB per part (`uploads.MAX_UPLOAD_BYTES`), and the proxy caps `/api/*` bodies at 2 MB (`infra/caddy/Caddyfile`).

### 16.2 Policy (`integrations/certificates/validate.py`)

Default policy for uploads: RSA at least 2048 bits, EC at least 256 bits, signatures SHA-256, SHA-384 or SHA-512, self-signed
not allowed, warning when expiry is within 30 days.

| Code | Severity | Meaning |
|---|---|---|
| `IS_CA_CERT` | blocking | The end-entity certificate has `CA=true`. |
| `CERT_EXPIRED` | blocking | Leaf or a chain certificate has expired. |
| `CERT_NOT_YET_VALID` | blocking | Leaf or a chain certificate is not yet valid. |
| `EXPIRES_SOON` | warning | Leaf expires in 30 days or fewer. |
| `KEY_MISSING` | info | No key supplied (blocking only if the policy requires a key). Replaced at upload by `KEY_REUSE_REQUIRED`. |
| `KEY_MISMATCH` | blocking | Private key does not match the leaf. |
| `UNSUPPORTED_KEY_ALGORITHM` | blocking | Not RSA, EC or Ed25519. |
| `WEAK_KEY` | blocking | RSA under 2048 bits, or EC under 256 bits. |
| `WEAK_SIGNATURE` | blocking | MD2, MD4, MD5, SHA-1, or any hash outside SHA-256/384/512. |
| `SAN_MISMATCH` | blocking | A required hostname is not in the SANs (or there are no SANs and the CN does not match). Exceptionable at deployment. |
| `SAN_MISSING_CN_FALLBACK` | warning | No SANs; the CN matches the hostname. Modern clients ignore the CN. |
| `CHAIN_INVALID` | blocking | An issuer is not a CA, a signature does not verify, or an issuer name claims a configured anchor but does not verify. |
| `CHAIN_UNTRUSTED` | blocking when self-signed and not an anchor; otherwise warning | Chain does not end at a configured anchor. |
| `CHAIN_INCOMPLETE` | warning | Only the leaf is supplied and it is not self-signed. |
| `CHAIN_POLICY_VIOLATION` | warning | `cryptography` path validation against the anchors reports a problem. Private CAs often trip this. |
| `SHORTER_VALIDITY_THAN_CURRENT` | warning | New expiry is earlier than the installed certificate's. |
| `SAME_AS_CURRENT` | info | Identical to the installed certificate. |
| `REPLACES_DIFFERENT_KEY_TYPE` | info | Key type or size differs from the installed certificate. |

### 16.3 Key reuse (`services/uploads.py`)

| Code | Severity | Meaning |
|---|---|---|
| `KEY_REUSE_REQUIRED` | info | No key supplied. The key already on each target is reused, and compatibility is checked again at preflight. |
| `KEY_REUSE_INCOMPATIBLE` | blocking | The new certificate's key differs from the current certificate's key. |
| `KEY_REUSE_UNVERIFIED` | warning | Some target has no identified certificate, so compatibility can only be checked at preflight. |

### 16.4 Route-level errors

| Code | HTTP | Meaning |
|---|---|---|
| `UPLOAD_INVALID` | 422 | No usable leaf. The findings are in `details.findings`. |
| `PAYLOAD_TOO_LARGE` | 413 | Part over 256 KiB. |
| `VALIDATION_ERROR` | 422 | No certificate or PKCS#12 given. |

Upload validation statuses: `invalid` if any blocking finding, `warnings` if any warning, otherwise `valid`.

---

## 17. Supported services and test coverage

Deployment is implemented for three services. The live target has no systemd, so systemd branches are untested.

| Service | Discovery parser | Deploy layout | Config test | Reload | Live coverage (`test_deploy_live.py`) | Live discovery coverage |
|---|---|---|---|---|---|---|
| nginx | `nginx -T` | full chain + key | `nginx -t` | `nginx -s reload` (no systemd) | a, c, e, f, g, k, l | yes, incl. symlink and certbot |
| apache | `apachectl -D DUMP_INCLUDES` | chain file, or full chain; key | `apachectl configtest` | `apachectl -k graceful` (no systemd) | b, l (second target), i (plan only) | yes, with chain file |
| haproxy | `haproxy.cfg` `crt` | combined PEM | `haproxy -c` | seamless `-sf` (no systemd) | d | yes, endpoint fingerprint |
| filesystem | filesystem scan | not deployable (classified `unmanaged`, no adapter) | | | none | yes, unmanaged |

Other facts:

- `allow_restart` and `allow_file_only_verification` are not covered by the live suite. Unit tests cover the file-only
  rule (`test_file_only_verification_needs_explicit_strategy_flag`).
- RHEL-family behaviour (`/etc/httpd`, `httpd` unit names) is not covered by any live test. `SUPPORTED_OS_IDS` includes
  `rhel`, `rocky`, `almalinux` and `ol`, but the only host probed in the live suite is Debian-family (the discovery test
  asserts `os_family == "debian"`).
- Owner and group are kept from the existing file. See section 10 for the mode rule.

---

## 18. Limitations and known issues

| # | Issue | Source | Status |
|---|---|---|---|
| K1 | Verification SNI falls back to the composite `vhost`, which is not a hostname, for installations with no `verify_sni` (wildcard-only names, no names). Deployments then roll back. | `deployment_planner.verify_endpoints_for`, `deployment_engine._verify_new` | **Reproduced** (real functions on fake input). Not run against a live host. |
| K2 | `_complete` runs outside the try block that covers rollback. An exception in cleanup or finalize (for example a database error after verification) marks the target `failed`. The new files stay in place, and no rollback runs. | `deployment_engine._activate_and_verify`, `_run` | From reading. |
| K3 | A manual restore that cannot take its locks is reported as `INTERNAL_ERROR`, not `LOCK_HELD`, because `classify()` does not know `LockHeld`. The target is then set to `manual_intervention_required`. | `deployment_engine.restore_backup_async`, `classify` | **Reproduced** for the classification step. |
| K4 | Job dispatch in `create` and `approve` is not guarded. If the broker call fails after the commit, the job stays `pending`. An identical replay returns that job without dispatching it. Discovery guards the same call and marks the job failed with `QUEUE_UNAVAILABLE`. | `deployments.create`, `approve`, `dispatch` | From reading. |
| K5 | If a `pending` deployment's message never reaches a worker, no sweep re-dispatches it. `cancel` only sets `cancel_requested` and does not move it out of `pending`. Notification deliveries have a sweep. Discovery jobs stuck in `pending` are marked failed after 30 minutes, but deployments have no equivalent. | `workers/tasks.py`, `deployments.cancel`, `discovery._expire_stale` | From reading. See [troubleshooting.md](troubleshooting.md). |
| K6 | `LockSet.lost` is never read. A lost lock does not stop the work. | `services/locks.py` | From reading. |
| K7 | Cancellation after `before_activation` is not honoured. | Section 14 | Design, from reading. |
| K8 | `chain_valid` is recorded, not enforced. | Section 11.3 | Design, from reading. |
| K9 | `CANCELLED` is raised by the SSH layer only when a `cancel_event` is passed, and no caller passes one. | `integrations/ssh/connection.py` | From reading. |
| K10 | The per-host SSH limit setting is not applied. The default of 4 is always used. | `connection.set_host_concurrency_limit` is never called | From reading. |
| K11 | The staged bytes are checked by hash only. They are not re-parsed on the host. | Section 9.2 | Design. |
| K12 | `allow_restart` can drop connections, and no live test covers it. | Section 5.2 | Design, untested. |
| K13 | The certbot message points to a document that does not exist. | Section 15 | From grep. |
| K14 | Units on one server are serialised. A high `concurrency` does not speed up a single server. | Section 5.1 | Design, by code. |

Live tests were not run for this page. Each scenario listed in section 17 is asserted in `test_deploy_live.py`. Their
results on a real target are **(unverified)**.
