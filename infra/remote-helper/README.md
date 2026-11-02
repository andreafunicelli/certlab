# Cert Deploy Pro remote helper

`cdp-helper` is the only privileged program Cert Deploy Pro runs on managed hosts. The SSH account
(`cdpdeploy`) has no shell privileges beyond one sudoers rule:

    cdpdeploy ALL=(root) NOPASSWD: /usr/local/libexec/cdp-helper

Every call is `sudo -n /usr/local/libexec/cdp-helper <subcommand> <args...>`; the backend shell-quotes each
argument and validates paths client-side. The helper validates everything again: paths must be absolute, free of
newlines/control characters and `..`, are canonicalised with `realpath -m` (so symlink escapes are resolved) and
must fall under `ALLOWED_ROOTS` from `/etc/cdp-helper.conf` (root-owned, mode 0644, otherwise the helper refuses).

Install: `sudo ./install.sh --pubkey-file deploy_key.pub` (creates user, installs helper 0755 root, config,
validates sudoers with `visudo -c`). Requires POSIX sh + coreutils; no Python.

## Subcommands and the privilege they need

| Subcommand | Output | Why root is needed / what it can touch |
|---|---|---|
| `version` | JSON | none |
| `probe` | JSON | reads os-release, runs `<svc> -v`, `pidof`; read-only |
| `stat PATH` | JSON | stats files that are mode 0600 root-owned (private keys) and hashes them (hash only, never content) |
| `read-public PATH MAX` | JSON base64 | reads allowed files; REFUSES any file containing `PRIVATE KEY` and `.key/.p12/.pfx/.jks` |
| `backup PATH` | JSON base64 | the ONLY path that returns private-key bytes (needed for rollback); allowed roots only |
| `find ROOT DEPTH MAX` | JSON lines | lists cert-like files (does not follow symlinks), classifies by BEGIN markers, never prints content |
| `dump nginx\|apache\|haproxy` | raw text | `nginx -T`, Apache include files, HAProxy configs (config text only) |
| `df PATH` | JSON | free bytes of the filesystem containing PATH |
| `stage-dir` | JSON | creates a 0700 dir under `STAGING_ROOT` |
| `write-staged DIR NAME MODE` | JSON | stdin (base64) to `DIR/NAME`; DIR must be a direct child of `STAGING_ROOT`; NAME `[A-Za-z0-9._-]+` |
| `install STAGED DEST MODE OWNER GROUP` | JSON | root needed for chown and writing root-owned dirs; DEST under allowed roots; copies to `DEST.cdp-tmp.$$`, chown/chmod, SELinux `chcon --reference`, atomic `mv -f`. A symlink DEST is accepted only if it resolves to a regular file inside allowed roots (the link is kept, the target replaced); otherwise exit 7 |
| `configtest nginx\|apache\|haproxy` | JSON | runs `nginx -t`, `apachectl configtest`/`httpd -t`, `haproxy -c -f cfg` |
| `reload svc [--allow-restart]` | JSON | `systemctl reload` when systemd; else `nginx -s reload`, `apachectl -k graceful`, haproxy `-sf` soft reload. Restart/start only with `--allow-restart` |
| `cleanup STAGEDIR` | JSON | removes a stage dir (must be a direct child of `STAGING_ROOT`) |

Exit codes: 2 bad argument, 3 path not allowed, 4 permission denied, 5 private key refused, 6 disk full,
7 symlink/non-regular destination, 8 service not installed, 9 command failed (configtest/reload), 10 bad config,
11 too large, 12 not found, 13 not running. Errors are JSON on stderr.

Limitations: a path whose symlink target resolves outside `ALLOWED_ROOTS` is denied (add the root to the
config if needed). `mode`/owner in `stat` describe the resolved target.
