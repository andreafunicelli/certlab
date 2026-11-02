#!/bin/sh
# Install the Cert Deploy Pro remote helper on a target host (run as root).
# Usage: install.sh [--user cdpdeploy] [--pubkey-file FILE] [--allowed-roots "..."] [--conf-only]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
USER_NAME=cdpdeploy
PUBKEY_FILE=""
ALLOWED=""
while [ $# -gt 0 ]; do
    case "$1" in
        --user) USER_NAME=$2; shift 2 ;;
        --pubkey-file) PUBKEY_FILE=$2; shift 2 ;;
        --allowed-roots) ALLOWED=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
case "$USER_NAME" in *[!a-z0-9_-]* | '') echo "bad user name" >&2; exit 2 ;; esac

if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/sh --comment "Cert Deploy Pro" "$USER_NAME"
    # '*' (not '!') keeps the account usable for public-key auth while having no valid password
    usermod -p '*' "$USER_NAME" 2>/dev/null || true
fi
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
if [ -n "$PUBKEY_FILE" ]; then
    install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh"
    touch "$HOME_DIR/.ssh/authorized_keys"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        grep -qxF "$line" "$HOME_DIR/.ssh/authorized_keys" || printf '%s\n' "$line" >>"$HOME_DIR/.ssh/authorized_keys"
    done <"$PUBKEY_FILE"
    chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
    chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
fi

install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root "$SRC/cdp-helper" /usr/local/libexec/cdp-helper
install -d -m 0700 -o root -g root /var/lib/cdp-helper /var/lib/cdp-helper/staging

if [ ! -e /etc/cdp-helper.conf ]; then
    install -m 0644 -o root -g root "$SRC/cdp-helper.conf.example" /etc/cdp-helper.conf
fi
if [ -n "$ALLOWED" ]; then
    # replace only the ALLOWED_ROOTS line
    tmp=$(mktemp)
    grep -v '^ALLOWED_ROOTS=' /etc/cdp-helper.conf >"$tmp"
    printf 'ALLOWED_ROOTS="%s"\n' "$ALLOWED" >>"$tmp"
    install -m 0644 -o root -g root "$tmp" /etc/cdp-helper.conf
    rm -f "$tmp"
fi

SUDOERS_TMP=$(mktemp)
sed "s/cdpdeploy/$USER_NAME/g" "$SRC/sudoers.cdpdeploy" >"$SUDOERS_TMP"
if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$SUDOERS_TMP" >/dev/null || { echo "sudoers validation failed" >&2; rm -f "$SUDOERS_TMP"; exit 1; }
fi
install -d -m 0750 -o root -g root /etc/sudoers.d
install -m 0440 -o root -g root "$SUDOERS_TMP" "/etc/sudoers.d/cdp-$USER_NAME"
rm -f "$SUDOERS_TMP"
if command -v visudo >/dev/null 2>&1; then visudo -c >/dev/null; fi
echo "cdp-helper installed (user=$USER_NAME)"
