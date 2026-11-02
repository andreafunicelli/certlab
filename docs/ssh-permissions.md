# Managed target preparation: SSH account and privilege model

This guide prepares a Linux host to be managed by Cert Deploy Pro (CDP). It covers the `cdpdeploy` account, the
restricted root helper, the sudoers rule, the helper configuration, what each CDP operation does as root, host-key
enrollment, distribution differences, and how to audit access.

Basis: `infra/remote-helper/` (`cdp-helper`, `install.sh`, `sudoers.cdpdeploy`, `cdp-helper.conf.example`, `README.md`)
and `backend/app/integrations/ssh/` (`paths.py`, `connection.py`, `hostkeys.py`, `testconn.py`). Commands here were
not run on a target host while writing this guide. Items marked **(not run)** are standard OpenSSH, sudo or
distribution commands that this repository does not exercise.

Related: [security.md](security.md) (threat model and trust boundary), [installation.md](installation.md).

---

## 1. Model in one paragraph

CDP connects to the target over SSH as `cdpdeploy`, using public-key authentication and a host key pinned in CDP's
database. Every privileged action is one call to the helper:

```
sudo -n /usr/local/libexec/cdp-helper <subcommand> <args...>
```

`sudo -n` never prompts. The only thing `cdpdeploy` can run as root is that helper. The helper is a POSIX shell
script with a fixed list of subcommands. It refuses any path outside `ALLOWED_ROOTS` in `/etc/cdp-helper.conf`.

---

## 2. Create the account and install the helper

Run as root on the target. Run from a checkout of this repository, because `install.sh` copies files from its own
directory (`cdp-helper`, `cdp-helper.conf.example`, `sudoers.cdpdeploy`).

```bash
# public key of the CDP credential: the "public_key" field from GET /api/v1/credentials
sudo ./infra/remote-helper/install.sh --user cdpdeploy --pubkey-file /root/cdp_deploy.pub
```

Options (as implemented in `install.sh`):

| Option | Effect |
|---|---|
| `--user NAME` | Account name. Default `cdpdeploy`. Only `a-z0-9_-` are accepted. |
| `--pubkey-file FILE` | Appends each non-empty line to `~NAME/.ssh/authorized_keys`, skipping lines already present. |
| `--allowed-roots "..."` | Replaces only the `ALLOWED_ROOTS=` line in `/etc/cdp-helper.conf`. |


What the script does:

1. Creates the account if it does not exist: `useradd --create-home --shell /bin/sh --comment "Cert Deploy Pro"`,
   then `usermod -p '*'`. The `*` locks password login and leaves key login working. If the account already exists,
   the shell and password are left unchanged.
2. Installs the public key(s) if `--pubkey-file` is given: `~/.ssh` mode 0700, `authorized_keys` mode 0600, both
   owned by the account.
3. Installs `/usr/local/libexec/cdp-helper` (mode 0755, root). Creates `/usr/local/libexec` (0755) if missing.
4. Creates `/var/lib/cdp-helper` and `/var/lib/cdp-helper/staging` (mode 0700, root).
5. Installs `/etc/cdp-helper.conf` (mode 0644, root) from the example, only if the file does not exist.
6. Writes `/etc/sudoers.d/cdp-<user>` (mode 0440, root). Validates the file with `visudo -cf` before installing it,
   if `visudo` is present. Then runs `visudo -c` on the whole configuration.

The script is idempotent for the user, the key lines and the configuration file. Re-running it replaces the helper
binary and the sudoers file.

**Manual removal.** The repository has no uninstall script. To remove, delete `/etc/sudoers.d/cdp-cdpdeploy`,
`/usr/local/libexec/cdp-helper`, `/etc/cdp-helper.conf`, `/var/lib/cdp-helper`, and the account with `userdel -r`
**(not run)**.

---

## 3. The sudoers rule

Installed from `infra/remote-helper/sudoers.cdpdeploy`, with `cdpdeploy` replaced by the chosen user name:

```
Defaults:cdpdeploy env_reset
cdpdeploy ALL=(root) NOPASSWD: /usr/local/libexec/cdp-helper
```

Reading the rule:

- `NOPASSWD` means no password prompt. CDP calls `sudo -n`, so a prompt would fail anyway.
- The grant is for one program, the helper. It is not `NOPASSWD: ALL`. An attacker who obtains the `cdpdeploy` key
  can run the helper as root but cannot run `/bin/sh` as root through sudo.
- The rule does **not** restrict arguments. sudoers would need a pattern per subcommand, and that is not expressible
  here. Every argument list is accepted by sudo. The helper's own validation (section 4) is the only control over what
  an argument list can do.
- `env_reset` clears the caller's environment. The helper then sets its own `PATH`.

Check it on the host: `sudo -l -U cdpdeploy` **(not run; standard sudo)**.

---

## 4. Helper configuration: `/etc/cdp-helper.conf`

The helper sources this file as POSIX `sh` when it runs as root. It refuses to run unless the file is a regular file,
not a symlink, owned by root, and has one of the modes 0644, 0640, 0600, 0444, 0400 or 0440. The example and the
README say 0644. Keep 0644.

| Variable | Default in example | Meaning |
|---|---|---|
| `ALLOWED_ROOTS` | `/etc/ssl /etc/pki /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt /etc/haproxy /opt /usr/local/etc` | Space-separated directory roots. A path is allowed if its canonical form (symlinks resolved) is one of these or below one. `/` is ignored. |
| `STAGING_ROOT` | `/var/lib/cdp-helper/staging` | Must be absolute. Staging directories must be direct children of it. |
| `HAPROXY_CFG` | `/etc/haproxy/haproxy.cfg` | HAProxy main configuration. |
| `HAPROXY_EXTRA_CFG` | commented out | Extra HAProxy config file or directory. Directories contribute `*.cfg` files. |
| `HAPROXY_PIDFILE` | `/run/haproxy.pid` | Used for HAProxy soft reload without systemd. |
| `NGINX_BIN`, `APACHE_CTL`, `APACHE_BIN`, `HAPROXY_BIN` | commented out | Override binary discovery. |
| `MAX_STAGED_BYTES` | `10485760` (10 MiB) | Largest file the helper will stage or back up. |

The helper's own built-in defaults match the example. The file overrides them because it is read afterwards.

**Keep `ALLOWED_ROOTS` narrow.** `/opt` and `/usr/local/etc` are broad. Anything under them is readable (including
private keys, via `backup`) and writable by the helper. Replace them with the specific directories the managed services
use. To change the list at install time, run `install.sh --allowed-roots "..."`.

Discovery roots in CDP settings (`ssh.discovery_roots`, see [configuration.md](configuration.md)) must lie inside
`ALLOWED_ROOTS` on the host, or the helper returns `PATH_NOT_ALLOWED` for that root.

---

## 5. What each operation does as root

These rows are taken from the helper's subcommand functions and the backend call sites. Subcommands run as root through
sudo. Each row names the backend operation that uses it.

| Backend operation | Helper subcommands used | What runs as root | What is read or written |
|---|---|---|---|
| Connection test | `version`; `probe` (through `helper_version` and `probe`). The step `id -un` runs as `cdpdeploy` **without** sudo. | `probe` runs `nginx -v`, `apachectl -v` or `apache2 -v`, `haproxy -v`, and `pidof`. | Reads `/etc/os-release`, kernel release, service versions and running state. Read-only. |
| Discovery, filesystem | `find ROOT DEPTH MAX`; `read-public PATH MAX`; `stat PATH` | Walks each discovery root, including root-only directories. `find` reads the first 2 MiB of each candidate to classify it. | Returns file paths and classification (`certificate`, `private_key`, `pkcs12`, and so on). `read-public` returns base64 content of public files only. `stat` returns metadata and a SHA-256 hash. |
| Discovery, service configuration | `dump nginx`; `dump apache`; `dump haproxy` | `nginx -T`; `apachectl -t -D DUMP_INCLUDES` and `apachectl -V`, then reads include files; reads HAProxy config files. | Returns configuration text. Included files outside `ALLOWED_ROOTS` are skipped with a comment. |
| Plan and pre-flight | `probe`; `stat`; `read-public`; `backup` (in memory only); `df`; `configtest` | `configtest` runs the service's configuration test. `backup` reads the current file, including any private key, into backend memory for the plan. | `df` reports free bytes on the destination filesystem. |
| Backup before a change | `stat`; `backup PATH` | Reads the raw bytes of each destination file, including private keys. | Content goes to the backend and is stored as an encrypted artifact with purpose `backup`. |
| Stage | `stage-dir`; `write-staged STAGE NAME MODE` | Creates a directory under `STAGING_ROOT` (mode 0700). Writes the new certificate or key into it, mode 0600. | Plaintext new key material sits in the staging directory until cleanup. |
| Validate | none on the target | none | Checks run in the backend on the staged content. |
| Activate (install) | `install STAGED DEST MODE OWNER GROUP` | Copies to `DEST.cdp-tmp.<pid>`, sets owner and mode, optionally sets SELinux context, then renames over `DEST`. | Writes the destination inside `ALLOWED_ROOTS`. Symlink destinations are allowed only if they resolve to a regular file inside the roots. The link is kept and its target replaced. |
| Configuration test | `configtest nginx`; `configtest apache`; `configtest haproxy` | Runs `nginx -t`; `apachectl configtest` (or `apachectl -t`); `haproxy -c -f <cfg>`. | Reads the configuration. Returns output. |
| Reload | `reload nginx`; `reload apache`; `reload haproxy`, each optionally with `--allow-restart` | With systemd and a known unit: `systemctl reload <unit>`. Otherwise `nginx -s reload`, `apachectl -k graceful`, or HAProxy `-sf` with the pidfile. Restart or start runs **only** with `--allow-restart`. | Changes service state. |
| Verify | `stat` (hash comparison) | none beyond `stat` | The live TLS probe runs from the backend, not on the target. |
| Cleanup | `cleanup STAGEDIR` | `rm -rf` on the staging directory, after a check that it is a direct child of `STAGING_ROOT`. | Removes staged key material. |
| Rollback and backup restore | `stat`; `stage-dir`; `write-staged`; `install`; `cleanup` | Same as activation: writes the backed-up content back to the destination. | Restores files from the encrypted backup. |

Every subcommand exits with a status code from the helper's table (2 bad argument, 3 path not allowed, 4 permission
denied, 5 private key refused, 6 disk full, 7 symlink or non-regular destination, 8 service not installed, 9 command
failed, 10 bad config, 11 too large, 12 not found, 13 not running). Errors are JSON on stderr.

---

## 6. Host-key enrollment

CDP connects only to a host whose key it has enrolled. The first key is not trusted automatically.

1. **Scan.** An admin calls `POST /api/v1/servers/{id}/host-key/scan`. This connects, fetches the host key and
   disconnects, with no authentication. Response: `key_type`, `fingerprint_sha256`, `public_key`.
2. **Confirm out of band.** Compare the fingerprint with the value on the host. On the host, the standard OpenSSH
   command is `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` **(not run)**. Use the key type that the scan
   returned. Confirm through a channel the attacker cannot control, such as the console or a change ticket.
3. **Enroll.** The admin calls `POST /api/v1/servers/{id}/host-key/enroll`:

   ```json
   {
     "public_key": "ssh-ed25519 AAAA...",
     "fingerprint_sha256": "SHA256:...",
     "replace": false
   }
   ```

   The backend scans again. The posted key and fingerprint must both match the fresh scan, or the request fails with
   409 `HOST_KEY_CHANGED_DURING_ENROLL`.
4. **Replacing a key.** If a different key is already enrolled, the request fails with 409
   `HOST_KEY_ALREADY_ENROLLED` unless `replace` is `true`. Use `replace: true` only after confirming the host was
   legitimately rebuilt or re-keyed.
5. **Test.** `POST /api/v1/servers/{id}/test-connection` runs seven steps in order: DNS, TCP, SSH handshake and host
   key, authentication, remote command, privilege (helper version), OS identification. A failed step skips the rest.

Enrollment and key changes are recorded as `HOST_KEY_ENROLLED`, `HOST_KEY_REPLACED`, or a failure event in the audit
trail. Only admins hold `servers:hostkey`.

After enrollment, a changed key on the host causes `HOST_KEY_MISMATCH`. The server's status becomes `host_key_mismatch`
and connections stop until an admin re-enrolls.

---

## 7. Distribution notes

The helper's configuration names these paths. Only these were checked against the code. No distribution was tested.

| Item | Debian and Ubuntu | RHEL-family |
|---|---|---|
| Apache configuration directory | `/etc/apache2` (in default `ALLOWED_ROOTS` and discovery roots) | `/etc/httpd` (in default `ALLOWED_ROOTS` and discovery roots) |
| Apache binary lookup | `apachectl`, then `apache2ctl`, then `apache2` or `httpd` | same order; `httpd` is typically the installed name |
| Apache systemd unit | `apache2` | `httpd` |
| nginx | `/etc/nginx`; unit `nginx` | same |
| HAProxy | `/etc/haproxy/haproxy.cfg` (`HAPROXY_CFG`) | same default; the actual location was not checked on RHEL |
| Helper `PATH` | fixed by the helper: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | same |

Binary discovery uses `command -v` under that fixed `PATH`. A service installed elsewhere needs its `*_BIN` override in
the configuration file.

**Service manager.** The helper uses systemd when `/run/systemd/system` exists and `systemctl` is present. Otherwise it
falls back to SysV-style or direct commands. The systemd reload and restart branch is not covered by any test in this
repository (see [security.md](security.md), gap 2).

**SELinux.** When `selinuxenabled` succeeds and `chcon` is present, `install` copies the SELinux context of the existing
destination with `chcon --reference`. For a new file it uses `restorecon` if available. Otherwise it does not relabel.
This was not tested on an SELinux host. If operations fail on such a host, check audit denials with `ausearch -m avc`
**(not run; standard RHEL tooling)**.

---

## 8. Verify the installation

Run on the target as root:

```bash
ls -l /usr/local/libexec/cdp-helper /etc/cdp-helper.conf /etc/sudoers.d/cdp-cdpdeploy
visudo -c
```

Run as `cdpdeploy` (for example from a separate SSH session with the CDP key):

```bash
sudo -n /usr/local/libexec/cdp-helper version
# expected output: {"name":"cdp-helper","version":"1.0.0"}

sudo -n /usr/local/libexec/cdp-helper stat /etc/nginx/nginx.conf   # JSON if nginx is installed
sudo -n /usr/local/libexec/cdp-helper stat /root/.bashrc           # exit 3, PATH_NOT_ALLOWED
```

The last command confirms that the path rule works. Use a path under `ALLOWED_ROOTS` for the first check. Output
formats are from the helper code. These commands have not been run on a host.

---

## 9. Audit

**On the target.** sudo logs each helper invocation with the user, working directory and full argument list **(default
sudo behaviour, not run)**. Arguments are paths, modes, owner and group names, and service names. File contents are not
in the argument list: `write-staged` reads base64 from stdin, and `backup` and `read-public` return content on stdout.
Where the log goes depends on the distribution's syslog or journald setup. Commonly `/var/log/auth.log` on Debian and
Ubuntu, `/var/log/secure` on RHEL, or the journal. For example, `journalctl _COMM=sudo` or
`grep cdp-helper /var/log/auth.log` **(not run)**.

**In CDP.** Every operation writes audit events. Query them with
`GET /api/v1/audit-events`, filtered by `actor`, `action`, `resource_type`, `resource_id`, `outcome`, `from` and `to`.
The `audit:read` permission is granted to every role (see the RBAC table in [security.md](security.md)). Example: `?resource_type=server&action=HOST_KEY_ENROLLED`. The
connection test writes `SSH_CONNECTION_TEST`. Failures carry an `error` field.

Correlate the two by time and by the correlation ID, which the API returns in `X-Correlation-ID`. The helper does not
receive that ID, so the join is by timestamp and host.
