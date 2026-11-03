# Troubleshooting

Symptom-first guide for Cert Deploy Pro (CDP): where the logs are, what each SSH and helper error means, and what to check
for discovery, deployment, rollback, queue, login and CSRF problems.

Basis: source at commit `a353f1e`. Error codes come from `integrations/contracts.py` (`RemoteErrorCode`),
`integrations/ssh/parsing.py` (`map_failure`, helper exit codes), `integrations/ssh/errors.py`, `infra/remote-helper/cdp-helper`
(exit statuses), `core/errors.py`, and the services named in each section. Log event names are the literal `event` strings
in the code. **No command on this page was run against a live system.** Commands are marked **(not run)**. Behaviour that
rests on reading alone is marked **(unverified)**. Known defects are marked **Known issue**, with a reference to the page
that describes them.

Related: [api.md](api.md) (error shape and correlation IDs), [certificate-discovery.md](certificate-discovery.md),
[deployment-engine.md](deployment-engine.md), [rollback.md](rollback.md), [backup-restore.md](backup-restore.md),
[ssh-permissions.md](ssh-permissions.md) (helper, sudo and `ALLOWED_ROOTS`), [installation.md](installation.md) (stack
operations), [configuration.md](configuration.md) (settings).

---

## 1. Logs and correlation IDs

### 1.1 Where the logs are

| Service | Command | What is there |
|---|---|---|
| `api` | `docker compose logs -f api` | Requests and their errors. `unhandled_exception` for crashes. |
| `worker` | `docker compose logs -f worker` | Discovery and deployment tasks. Events such as `discovery_task_finished`, `deployment_finished`, `deployment_job_busy`, `discovery_unexpected_error`, `notification_delivery_failed`. |
| `beat` | `docker compose logs -f beat` | Scheduler activity. Nothing is logged when a scheduled run does not start. |
| `migrate` | `docker compose logs migrate` | Whether `alembic upgrade head` completed. |
| `proxy` | `docker compose logs proxy` | Routing and TLS. |
| `postgres`, `redis` | `docker compose logs postgres`, `docker compose logs redis` | Start-up and errors. |

Logs are structured JSON (structlog). Secret-looking keys and PEM blocks are redacted before output. The log level is set by
`CDP_LOG_LEVEL` (default `INFO`). Logs are the container's standard output. Whether the Docker log driver keeps them on the
host depends on the host's Docker configuration (**unverified** for your host).

Useful combined views:

```bash
docker compose logs --since 30m api worker beat | less
docker compose logs --tail=500 worker | grep -E 'discovery|deployment|unexpected'   # (not run)
```

### 1.2 Using a correlation ID

1. Send the request with `X-Correlation-ID: <your id>` (8 to 64 characters, `A-Z a-z 0-9 . _ -`), or note the one the server
   returned. Every response carries the header, and every error body carries it in `error.correlation_id`.
2. Search the logs for that value. Use a fixed-string search so the JSON layout does not matter:

   ```bash
   docker compose logs api worker | grep -F '<correlation id>'      # (not run)
   ```

3. Find the audit events written during that request. The API cannot filter on this column (see [api.md](api.md) section 5),
   so query the table directly. This is read-only. **(not run)**

   ```bash
   docker compose exec -T postgres psql -U cdp -d cdp -c \
     "SELECT ts, action, outcome, resource_type, resource_id, error FROM audit_events
      WHERE correlation_id = '<correlation id>' ORDER BY ts;"
   ```

Include the correlation ID in any bug report. It is the fastest way to tie a user's failure to the log lines.

### 1.3 Useful event names

| Event | Where | Meaning |
|---|---|---|
| `startup_complete` | api | The API started. Only a KEK length check runs at start (see [backup-restore.md](backup-restore.md) section 1.2). |
| `discovery_task_finished` | worker | A discovery job ended. The `status` field gives the result. |
| `discovery_unexpected_error`, `discovery_persist_failed` | worker | An exception in discovery. The traceback is logged. |
| `deployment_finished` | worker | A deployment task ended. |
| `deployment_job_busy` | worker | Another live worker holds the job lock. The task retries after 30 seconds. |
| `deployment_lock_lost` | worker | A heartbeat failed to renew a lock. Nothing acts on it (deployment-engine K6). |
| `rate_limit_redis_unavailable` | api | Rate limiting fell back to in-memory counters. |
| `notification_delivery_failed` | worker | A delivery attempt failed. The `final` field says whether it will be retried. |
| `backup_artifact_delete_failed` | api/worker | A purged backup's ciphertext could not be deleted (backup-restore 1.5). |
| `unhandled_exception` | api | A request crashed. The client got a generic 500. |

---

## 2. Login, sessions and CSRF

| Symptom | Likely cause | Check or fix |
|---|---|---|
| Sign-in succeeds, but the next page says you are signed out. | The browser did not store the `Secure` cookies. This happens on plain `http://`. | Use the HTTPS address. Set `CDP_COOKIE_SECURE=false` only for local development ([configuration.md](configuration.md)). |
| 401 `UNAUTHENTICATED` | No session cookie, the session has expired, or it was revoked. | Sign in again. Sessions expire after `security.session_minutes` (default 480) or `CDP_SESSION_TTL`, whichever is shorter. They are also revoked by a password change, by disabling the user, or by a role change made by another admin. |
| 403 `CSRF_FAILED` | `X-CSRF-Token` header missing, or not equal to the `cdp_csrf` cookie. | The frontend sends it automatically. For scripts, copy the `cdp_csrf` value from the cookie jar into the header ([security.md](security.md) section 1.4). |
| 401 `INVALID_CREDENTIALS` | Wrong username or password, disabled or locked account, or a wrong TOTP code. All four give the same response. | Five failed passwords lock the account for 15 minutes. Check the account is enabled. Check the time on the device that generates the TOTP code. |
| 429 `RATE_LIMITED` | Too many requests from one client IP (600 per minute for the API, 10 logins per minute per IP, 5 per username). | Honour `Retry-After`. **Behind the bundled proxy, every client looks like the proxy's address unless `CDP_TRUST_PROXY_HEADERS=true`** (see [api.md](api.md) section 1). |
| 403 `REAUTH_REQUIRED` | The action needs recent re-authentication. | `POST /api/v1/auth/reauth` with the password (and TOTP), then retry. The window is `security.reauth_minutes` (default 10). |
| 403 `FORBIDDEN` with `details.required_permission` | The role does not grant the permission. | Check the user's roles (`GET /api/v1/auth/me`). Roles are listed in [security.md](security.md) section 2. |
| 403 `FORBIDDEN`, "Account is disabled" | The account is disabled. | Enable it (an administrator). |
| OIDC sign-in loops, or returns an error | The redirect URI does not match, or the state cookie was not stored (`cdp_oidc`, `Path=/api/v1/auth/oidc`). | Check `CDP_PUBLIC_BASE_URL` and the redirect URI registered at the identity provider. The state cookie needs HTTPS (section 2 first row). |

---

## 3. SSH and helper errors

Every SSH call returns a `RemoteErrorCode`. The job or deployment step records it as `error_code`. Discovery records it in
the job's `error` text and in `connection_status` on the server (`_STATUS_BY_ERROR`).

### 3.1 Error codes

| Code | Typical cause | What to check or do |
|---|---|---|
| `DNS_FAILURE` | The hostname or address does not resolve from the `worker` (or `api`) container. | `docker compose exec worker getent hosts <name>`. Fix the server's address or the container's DNS. |
| `CONNECTION_REFUSED` | Nothing listens on the SSH port, or a firewall rejects the connection. | Check the server's `ssh_port`. Test from the worker container with `nc -vz <host> <port>` (**not run**). |
| `TIMEOUT` | No answer within `ssh.connect_timeout` (default 10 s), or a helper call exceeded `ssh.command_timeout` (default 60 s), or a discovery exceeded its 20-minute limit, or no SSH slot was free in 300 s. | Check routing and firewalls. Raise the timeouts in `ssh` settings only if the host is slow. Reduce discovery roots or depth if the job timed out. |
| `HOST_KEY_UNKNOWN` | No host key is enrolled for the server. The enrolled key is not a valid OpenSSH key. | `POST /api/v1/servers/{id}/host-key/scan`, compare the fingerprint with the server's own (out of band), then `POST .../host-key/enroll` with the scanned key and fingerprint. |
| `HOST_KEY_MISMATCH` | The server presents a key other than the enrolled one. This happens after a rebuild, or when someone is intercepting the connection. | **Do not re-enrol by reflex.** Confirm the new key out of band with the server's owner. Only then re-enrol with `replace=true`. Discovery writes `HOST_KEY_CHANGED` to the audit log and sends a critical `hostkey.changed` notification. |
| `AUTH_REJECTED` | The server rejected the public key, the username is wrong, or the stored private key or passphrase cannot be loaded. | Check `ssh_username` on the server, and that the credential's public key is in that account's `authorized_keys`. Check the passphrase. See [ssh-permissions.md](ssh-permissions.md). |
| `PERMISSION_DENIED` | Sudo refused the helper ("password is required", "not allowed to execute"), or the helper reported a permission failure. | On the target: `sudo -n /usr/local/libexec/cdp-helper probe` (read-only; **not run**). If it fails, check `/etc/sudoers.d/cdp-cdpdeploy` ([ssh-permissions.md](ssh-permissions.md)). |
| `HELPER_MISSING` | `cdp-helper` is not installed at `/usr/local/libexec/cdp-helper` (exit 127, or "no such file"). | Run `infra/remote-helper/install.sh` on the target. |
| `UNSUPPORTED_OS` | The OS is not one of `ubuntu`, `debian`, `rhel`, `rocky`, `almalinux`, `ol`. The connection test fails this step. | Use a supported OS, or extend the list in code. Deployments show `UNSUPPORTED_OS` as a warning. |
| `COMMAND_FAILED` | A helper failed and is not classified more precisely. The `details.exit_status` and `details.helper_error` say which. Also raised for oversized output, invalid JSON, and an unknown service name. | Read `details` in the step log (below). |
| `PATH_NOT_ALLOWED` | A path is outside `ALLOWED_ROOTS` (exit 3). Also used for `PRIVATE_KEY_REFUSED` (exit 5) and `SYMLINK_DEST` (exit 7). | To manage a path under another root, extend `ALLOWED_ROOTS` in `/etc/cdp-helper.conf` ([ssh-permissions.md](ssh-permissions.md) section 4). Never add `/` or a whole home directory. |
| `DISK_FULL` | No space left (exit 6), or the planner's space check failed. | Free space on the target's certificate and staging filesystems (`/var/lib/cdp-helper/staging`). |
| `CANCELLED` | Raised only when a cancel event is passed to the SSH layer. No current caller does this (deployment-engine K9). | Not expected in practice. |
| `UNKNOWN` | Connection lost, channel open failed, SSH disconnect, key exchange failure, or an unclassified exception. | Look at the logs for the exception type. Retry. Idempotent reads are retried up to 3 times. |

### 3.2 Helper exit codes

`cdp-helper` (`infra/remote-helper/cdp-helper`) writes a JSON error line on stderr and exits with one of these statuses.
The backend maps them as shown.

| Exit | Helper error | Backend code | Meaning |
|---|---|---|---|
| 2 | `BAD_ARGUMENT` | `COMMAND_FAILED` | Bad argument, or path not absolute or containing control characters. |
| 3 | `PATH_NOT_ALLOWED` | `PATH_NOT_ALLOWED` | Outside `ALLOWED_ROOTS`, or a `..` component. |
| 4 | `PERMISSION_DENIED` | `PERMISSION_DENIED` | Not run as root, or the destination could not be written. |
| 5 | `PRIVATE_KEY_REFUSED` | `PATH_NOT_ALLOWED` (`details.helper_error`) | `read-public` refused a file that holds a private key. Expected for combined PEM files. |
| 6 | `DISK_FULL` | `DISK_FULL` | No space left. |
| 7 | `SYMLINK_DEST` | `PATH_NOT_ALLOWED` | Destination is a symlink that does not resolve to a regular file inside the roots. |
| 8 | `SERVICE_NOT_INSTALLED` | `COMMAND_FAILED` | Service binary not found. |
| 9 | `COMMAND_FAILED` | `COMMAND_FAILED`, or a `CONFIG_TEST_FAILED` / `RELOAD_FAILED` in a deployment | The service command failed. For config test and reload, the helper prints its result as JSON, and the engine reads it as a result. |
| 10 | `BAD_CONFIG` | `COMMAND_FAILED` | `/etc/cdp-helper.conf` is not a root-owned regular file with mode 0644, 0640, 0600, 0444, 0440 or 0400. |
| 11 | `TOO_LARGE` | `COMMAND_FAILED` | File over `MAXBYTES` (discovery reads 1 MiB) or staged content over 10 MiB. Discovery turns this into `unsupported`. |
| 12 | `NOT_FOUND` | `COMMAND_FAILED` | Path or staging directory does not exist. Discovery skips a missing scan root. |
| 13 | `NOT_RUNNING` | `COMMAND_FAILED` | Service is not running and `--allow-restart` was not given. |

### 3.3 Host key workflow

1. `POST /api/v1/servers/{id}/host-key/scan` (`servers:hostkey`) returns the presented key and its SHA-256 fingerprint.
   It does not store anything.
2. Confirm the fingerprint with the server's owner through another channel (console, configuration management, the
   provider's console).
3. `POST /api/v1/servers/{id}/host-key/enroll` with the same key and fingerprint. The server is scanned again. If the key
   differs from the posted one, the request fails with 409 `HOST_KEY_CHANGED_DURING_ENROLL`. If a different key is already
   enrolled, it fails with 409 `HOST_KEY_ALREADY_ENROLLED` unless `replace=true`.
4. `POST /api/v1/servers/{id}/test-connection` to confirm each step passes.

---

## 4. Discovery problems

| Symptom | Likely cause | Check or fix |
|---|---|---|
| Job `completed` with warnings; the `service:nginx` step (or apache, haproxy) is `warning` | That service's configuration could not be read. Often `nginx -T` fails on a broken configuration. | On the target, run `nginx -t` (or the equivalent). Fix the configuration and run discovery again. Results for the other services are still saved. |
| Job `completed` with warnings; the `filesystem_scan` step is `warning` with `PATH_NOT_ALLOWED` | A configured discovery root is outside `ALLOWED_ROOTS`. The whole filesystem scan stops. | Remove the root from `ssh.discovery_roots`, or add it to `ALLOWED_ROOTS` ([certificate-discovery.md](certificate-discovery.md) section 5.3). |
| Installation `unsupported`, "unresolved expression" | The path uses a variable (`$var`, `${var}`). | There is no automatic fix. Use a literal path in the configuration. The installation cannot be deployed. |
| Installation `unreadable`, "contains private key material and the live endpoint probe failed" | A combined PEM was read through its endpoint, and the probe did not get a certificate. | Set a reachable verify host, port and SNI with `PATCH /api/v1/installations/{id}`. Test with `POST /api/v1/installations/{id}/verify`. The backend must reach the endpoint. |
| Installation `error`, "broken symlink" or "does not exist" | The link target or file was removed. | Restore the file, or fix the link. Discovery records the change on its next run. |
| Installation `requires_mapping`, "private key file was not found" | The key path in the configuration does not exist. | Fix the configuration, or set the classification after mapping (`PATCH`). |
| Installation marked `missing` | Not seen in the last successful run for that service. Often the server name or listen port changed, which changes the identity ([certificate-discovery.md](certificate-discovery.md) section 6.4). | Check the configuration. A file found again clears `missing_since` on its next run. Operator labels on the old row do not carry over to a new identity. |
| No discovery runs on schedule | Beat is not running, or the server lacks a credential or an enrolled host key (those servers are skipped silently), or `inventory_refresh_minutes` has not elapsed. | `docker compose ps beat`. Check the server has both. Look for `discovery_task_finished` in the worker logs. |
| `DISCOVERY_ALREADY_RUNNING` (409) | A job is `pending` or `running`. | Wait for it. A job with no progress for 30 minutes is marked failed (`abandoned`) on the next request. |
| `QUEUE_UNAVAILABLE` (503) | Redis or the broker could not take the task. The job is marked failed. | Check `redis` and `worker` ([section 7](#7-queue-redis-and-workers)). |
| Job `failed` with `TIMEOUT` ("discovery timed out") | The job took more than 20 minutes. Usually many files in the scan roots, or a slow host. | Lower `discovery_max_depth` or `discovery_max_files`, and narrow `discovery_roots`. |
| Job `failed` with `PERSIST_FAILED` | Results could not be saved. | Check `discovery_persist_failed` in the worker logs. Usually a database problem. |
| Certificates missing from the scan, and no error | The scan budget (`discovery_max_files`) was used by excluded entries, or the scan was truncated silently, or the file has an extension the scan does not match. | See [certificate-discovery.md](certificate-discovery.md) section 5.3. Add an explicit configuration reference for important files. |

---

## 5. Deployment problems

### 5.1 Reading a failed deployment

1. `GET /api/v1/deployments/{job_id}`. Look at `status`, `error_summary`, `rollback_status`, and each target's `status`,
   `current_step`, `error_code` and `error_message`.
2. Each target's `steps` list shows every step with its status and error code. Its `log` list shows timestamped messages
   (the secrets are redacted). The `files` list shows what was to be replaced.
3. The stored plan (`plan`) shows the findings from preflight, including warnings.

### 5.2 Failures by step

Blocking findings at creation are reported as 409 `PREFLIGHT_BLOCKED`, and `details.findings` lists them. Each finding code
is described in [deployment-engine.md](deployment-engine.md) section 3.3. Warnings that were not acknowledged return
422 `WARNINGS_NOT_ACKNOWLEDGED`. At worker start, a job that fails preflight again gets `PREFLIGHT_FAILED` and the codes.

| Step (target status) | Error code(s) | Likely cause | Check or do |
|---|---|---|---|
| preflight (job) | `PREFLIGHT_FAILED` | The state changed between creation and start, or a finding now blocks. | Read the codes in `error_summary`, then fix the cause and create a new deployment. |
| `connect` | any SSH code (section 3) | Connection or privilege problem. | Section 3. |
| `lock` | `LOCK_HELD` | Another deployment holds a lock on a path or service of this target. | Check `deployment_locks` (`key`, `owner`, `expires_at`). Wait for the other job to finish, or for the lock to expire (120 s after its last heartbeat). |
| `recheck` | `FILE_CHANGED_SINCE_PREFLIGHT` | A destination changed after the plan was made. | Someone or something else changed the file. Plan again. |
| `backup` (`backing_up`) | `BACKUP_FAILED` | A file is missing, larger than 10 MiB, changed while it was read, or the backup did not verify. | Check the message. Check the file on the server. |
| `stage` (`staging`) | `DISK_FULL`, `STAGED_HASH_MISMATCH`, `PLAN_CONTENT_MISMATCH` | No space in `/var/lib/cdp-helper/staging`, a transfer corruption, or the rendered content differs from the plan. | Free space. For a plan mismatch, plan again. If it repeats, report it. |
| `validate` (`validating`) | `STAGED_CERT_MISMATCH`, `STAGED_KEY_MISMATCH`, `STAGED_KEY_INVALID` | The certificate and key in the version do not match, or the key cannot be used. | Upload the matching key, or a version without an unusable key. |
| `activate` (`activating`) | `PERMISSION_DENIED`, `DISK_FULL`, `PATH_NOT_ALLOWED`, `INSTALL_HASH_MISMATCH` | The destination cannot be written, has a bad owner or group, is outside the roots, or does not hold the new content after writing. | Check owner and group names on the server. Check ACLs and SELinux. Check the roots. Rollback runs automatically. |
| `config_test` (`activating`) | `CONFIG_TEST_FAILED` | The service rejects the new configuration, often because the key and certificate do not match or a file path is wrong. | The step detail holds the first 300 characters of the test output. Fix it and deploy again. Rollback runs. |
| `reload` (`reloading`) | `RELOAD_FAILED`, `COMMAND_FAILED` ("is not running") | The reload failed, or the service is stopped and `allow_restart` is off. | `systemctl status` or the service's own status command on the server. Start the service, or deploy with `allow_restart` if a restart is acceptable. Rollback runs. |
| `verify` (`verifying`) | `VERIFY_UNREACHABLE`, `VERIFY_NO_ENDPOINT`, `VERIFY_FINGERPRINT_MISMATCH`, `VERIFY_HOSTNAME_MISMATCH`, `VERIFY_FILE_MISMATCH` | The endpoint does not answer, serves another certificate, or serves a certificate that does not match the endpoint's name. | Test the endpoint with `openssl s_client` (rollback.md section 6 step 3). A wildcard-only or nameless installation may have no usable SNI, which is **Known issue** K1 ([deployment-engine.md](deployment-engine.md) section 11.2). Set `verify_sni` with `PATCH`. |
| `finalize` or `cleanup` (after verify) | `INTERNAL_ERROR` | A database error after the new certificate was verified. The target is marked failed but **the new certificate stays on the server** (**Known issue** K2). | Run discovery on the server. Check the installation's fingerprint against the served one. Review the target manually. |
| `rollback` (`rolling_back`) | `ROLLBACK_*` | The automatic restore did not verify. | Section 6. |
| `reconcile` (resume) | `RECONCILE_FAILED`, `WORKER_INTERRUPTED` | A worker died mid-deployment, and the files could not be classified as all new. | `RECONCILE_FAILED` needs manual recovery ([rollback.md](rollback.md)). `WORKER_INTERRUPTED` rolls back on its own. |
| any (job) | `AUTHZ` | The initiating user was disabled or lost `deployments:create` since the job started. | The job stops at the next checkpoint. Re-enable the user, and create a new deployment if needed. |

### 5.3 Blocking and warning codes that often surprise people

| Code | What to do |
|---|---|
| `CERTBOT_MANAGED` | Use a certbot deploy hook for this certificate. CDP has no hook integration, and the message points to docs that are not in this repository (deployment-engine K13). |
| `INVENTORY_STALE` | The file changed since the last discovery. Run discovery, or acknowledge the code if the change is expected. |
| `SAN_MISMATCH` | The certificate does not cover the installation's name. Fix the certificate. An administrator can record an exception with a justification (10 characters or more). |
| `ACTIVE_DEPLOYMENT`, `MANUAL_INTERVENTION_PENDING` | Another job for this installation is pending, or a previous one needs manual recovery. Wait, or recover it ([rollback.md](rollback.md)). |
| `SHARED_PATH_NOT_IN_PLAN` | Another installation writes the same file. Include it in the deployment. |
| `PATH_CONTENT_CONFLICT` | Two installations share a file but need different content. Use one certificate for both, or split the file. |

---

## 6. Rollback failed

A failed rollback leaves the target in `manual_intervention_required`. This blocks new deployments to that installation.

1. Read the target's `error_message`. It has the original reason and the rollback failure. The `ROLLBACK_*` codes are listed in
   [rollback.md](rollback.md) section 2.
2. Follow the runbook in [rollback.md](rollback.md) section 6. Start with the backup check and the host check.
3. Fix the cause (permissions, configuration, a file being changed by another tool), then restore with
   `POST /api/v1/backups/{id}/restore` or the target rollback endpoint.
4. A successful restore clears the block. A failed restore can be repeated.

Do not change the database by hand to clear the status. The engine's guards then no longer match the host.

---

## 7. Queue, Redis and workers

### 7.1 Jobs stay `pending`

Discovery and deployments run through Celery, with Redis as the broker. Work that is queued but not yet picked up is held in
Redis, and the job's status is in PostgreSQL.

1. Are the services up?

   ```bash
   docker compose ps worker redis
   docker compose exec worker sh -c 'celery -A app.workers.celery_app inspect ping -d "celery@$HOSTNAME" --timeout 10'   # (not run)
   ```

   The compose healthcheck runs the same `inspect ping`. A worker that does not answer is not processing jobs.

2. Is anything waiting in the queue? The default queue is `celery`. **(not run)**

   ```bash
   docker compose exec redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning LLEN celery'
   ```

   A large number with an idle worker means the worker is stuck or disconnected. Check its logs for connection errors. A
   zero with an idle worker means the message was lost.

3. Read the worker log for `deployment_job_busy` (another live worker holds the job lock) or repeated retries.

4. **A lost message (Known issue K5, [deployment-engine.md](deployment-engine.md) section 18).** A deployment queued while Redis lost its data stays `pending`. Nothing re-sends it.
   `cancel` only sets `cancel_requested`, and does not move the job out of `pending`. Discovery jobs are marked failed after 30
   minutes, which allows a new run. There is no supported API action to re-dispatch a pending deployment. To list them,
   read-only **(not run)**:

   ```bash
   docker compose exec -T postgres psql -U cdp -d cdp -c \
     "SELECT id, status, cancel_requested, created_at FROM deployment_jobs
      WHERE status IN ('pending','preflight','activating') ORDER BY created_at;"
   ```

   Check each target's state and locks before doing anything. Deciding what to do with the rows is an operator decision.
   Report the case so that a fix can be planned.

### 7.2 Scheduled work does not run

- Beat must be running: `docker compose ps beat`. Its schedule is in `/tmp` on a tmpfs, so it is rebuilt at each start.
- Schedules: discovery every 5 minutes, notification sweep every 10 minutes, lock purge every 10 minutes, expiry check at
  06:17 UTC, endpoint verification every 6 hours at minute 41, backup purge at 03:23 UTC (installation.md section 7).
- Scheduled discovery needs both halves: beat enqueues `discovery.schedule_all`, and the worker runs it and then runs the
  discovery jobs it creates. Check the logs of both.

### 7.3 Notifications

- A delivery stuck in `pending` is re-enqueued by `notifications.sweep_pending` after 10 minutes.
- A delivery is retried with exponential back-off (60 seconds times 2 to the power of the attempt, capped at one hour), up to
  six attempts. Check `GET /api/v1/notifications/deliveries?status=failed` and each delivery's `last_error`.
- A channel secret that cannot be decrypted is not retried: "channel secret cannot be decrypted (master key changed?)"
  ([backup-restore.md](backup-restore.md) section 2.5).

### 7.4 Worker restarts and redelivery

- Tasks use late acknowledgement. If a worker dies, the broker redelivers the task. The redelivery delay is governed by the
  broker's visibility timeout, which the code sets to 6 hours (`broker_transport_options`) (**unverified** how Celery applies
  it here).
- A deployment's steps are persisted, and the engine reconciles the host on resume ([deployment-engine.md](deployment-engine.md)
  section 13). No destructive step is repeated blindly.
- Compose gives the worker 300 seconds to stop (`stop_grace_period`), so in-flight steps can reach a safe checkpoint.

### 7.5 Redis is unreachable

- `GET /api/v1/readyz` returns 503 with `"redis": "unavailable"`.
- Progress events stop. The job pages still show the database state.
- Rate limits fall back to in-memory counters per process (`rate_limit_redis_unavailable`).
- Enqueueing fails. Discovery returns 503 `QUEUE_UNAVAILABLE`. A deployment whose dispatch fails after the commit stays
  `pending`, and an identical replay returns that job without dispatching it again (deployment-engine.md section 18, K4).

---

## 8. API error codes (quick reference)

| Code | Status | Meaning and fix |
|---|---|---|
| `VALIDATION_ERROR` | 422 | Request field invalid. `details.errors` names the field. |
| `IDEMPOTENCY_KEY_REQUIRED` | 400 | Send `Idempotency-Key` (1 to 80 characters) with `POST /deployments`. |
| `IDEMPOTENCY_KEY_CONFLICT` | 409 | The key was used with a different body. Use a new key. |
| `PREFLIGHT_BLOCKED` | 409 | Blocking findings. Read `details.findings`. |
| `WARNINGS_NOT_ACKNOWLEDGED` | 422 | Add the listed codes to `acknowledged_warnings`. |
| `SELF_APPROVAL_FORBIDDEN` | 403 | Another administrator must approve, or `security.allow_self_approval` must be on. |
| `REAUTH_REQUIRED` | 403 | Re-authenticate, then retry. |
| `INVALID_STATE` | 409 | The action does not apply to the job's current status. |
| `NOTHING_TO_RETRY` | 409 | No failed or rolled-back target to retry. |
| `NO_BACKUP` | 409 | The target has no verified backup. Use another recovery path ([rollback.md](rollback.md)). |
| `DISCOVERY_ALREADY_RUNNING` | 409 | Wait for the job, or for the 30-minute stale rule. |
| `SERVER_DISABLED` | 409 | Enable the server. |
| `QUEUE_UNAVAILABLE` | 503 | Redis or the worker. See section 7. |
| `HOST_KEY_CHANGED_DURING_ENROLL` | 409 | The server's key changed between scan and enrol. Scan again and confirm. |
| `HOST_KEY_ALREADY_ENROLLED` | 409 | A different key is enrolled. Confirm out of band, then use `replace=true`. |
| `SERVER_HAS_NO_CREDENTIAL` | 422 | Assign a credential to the server. |
| `SETTINGS_VERSION_CONFLICT` | 409 | Settings changed elsewhere. Reload and retry. |
| `CLASSIFICATION_NOT_ALLOWED` | 422 | An unreadable or unparseable installation cannot be set to `managed`. |
| `UPLOAD_INVALID` | 422 | No usable certificate. `details.findings` explains. |
| `PAYLOAD_TOO_LARGE` | 413 | A part is over 256 KiB. |
| `CSRF_FAILED` | 403 | Send the `X-CSRF-Token` header. Section 2. |
| `RATE_LIMITED` | 429 | Wait for `Retry-After`. |
| `UNAUTHENTICATED` | 401 | Sign in again. |
| `INVALID_CREDENTIALS` | 401 | Wrong credentials, or a locked or disabled account. |
| `INTERNAL_ERROR` | 500 | Look up the correlation ID in the `api` log. |

---

## 9. What this page does not cover

- Stack installation, upgrades and the first start: [installation.md](installation.md).
- Helper installation, sudoers and the SSH account: [ssh-permissions.md](ssh-permissions.md).
- Losing the master key, and disaster recovery: [backup-restore.md](backup-restore.md).
- Security questions: [security.md](security.md).
