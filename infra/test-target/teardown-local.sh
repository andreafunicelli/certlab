#!/bin/bash
# Tear down the disposable test target created by setup-local.sh. Run as root.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
STATE=/var/lib/cdp-test
[ -f "$STATE/sshd.pid" ] && kill "$(cat "$STATE/sshd.pid")" 2>/dev/null
nginx -s stop 2>/dev/null
apachectl -k stop 2>/dev/null
[ -f /run/haproxy.pid ] && kill "$(head -n1 /run/haproxy.pid)" 2>/dev/null
sleep 1
rm -f /etc/nginx/conf.d/cdp-test.conf
a2dissite -q cdp-test 2>/dev/null; rm -f /etc/apache2/sites-available/cdp-test.conf
a2disconf -q cdp-servername 2>/dev/null; rm -f /etc/apache2/conf-available/cdp-servername.conf
[ -f /etc/apache2/ports.conf.cdp-orig ] && mv -f /etc/apache2/ports.conf.cdp-orig /etc/apache2/ports.conf
[ -f /etc/haproxy/haproxy.cfg.cdp-orig ] && mv -f /etc/haproxy/haproxy.cfg.cdp-orig /etc/haproxy/haproxy.cfg
rm -rf /etc/ssl/cdp-test /etc/letsencrypt/live/certbot.test.local /etc/letsencrypt/archive/certbot.test.local "$STATE"
rm -rf /var/lib/cdp-helper
rm -f /usr/local/libexec/cdp-helper /etc/cdp-helper.conf /etc/sudoers.d/cdp-cdpdeploy
userdel -r cdpdeploy 2>/dev/null
echo "cdp test target removed"
