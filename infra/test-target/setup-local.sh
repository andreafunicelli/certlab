#!/bin/bash
# Provision a DISPOSABLE local test target (sshd on 127.0.0.1:2222, nginx :8443, apache :9443, haproxy :10443)
# directly in this container (no systemd, no docker). Idempotent. Run as root. Test infra only.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
STATE=/var/lib/cdp-test
CERTS=/etc/ssl/cdp-test
USER_NAME=cdpdeploy
PASSPHRASE=cdp-test-passphrase

mkdir -p "$STATE" "$CERTS" /run/sshd
chmod 755 "$STATE"

# ------------------------------------------------------------------ keys
[ -f "$STATE/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -C cdp-test-host -f "$STATE/ssh_host_ed25519_key"
[ -f "$STATE/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C cdp-test-client -f "$STATE/id_ed25519"
[ -f "$STATE/id_rsa_enc" ] || ssh-keygen -q -t rsa -b 3072 -N "$PASSPHRASE" -m PEM -C cdp-test-client-enc -f "$STATE/id_rsa_enc"
[ -f "$STATE/id_ed25519_unauthorized" ] || ssh-keygen -q -t ed25519 -N '' -C cdp-test-unauthorized -f "$STATE/id_ed25519_unauthorized"
printf '%s' "$PASSPHRASE" >"$STATE/id_rsa_enc.passphrase"
chmod 600 "$STATE"/id_* "$STATE"/ssh_host_ed25519_key "$STATE/id_rsa_enc.passphrase"
chmod 644 "$STATE"/*.pub
cat "$STATE/id_ed25519.pub" "$STATE/id_rsa_enc.pub" >"$STATE/authorized_keys.pub"

# ------------------------------------------------------------------ helper + user
sh "$REPO/infra/remote-helper/install.sh" --user "$USER_NAME" --pubkey-file "$STATE/authorized_keys.pub"

# ------------------------------------------------------------------ certificates
mkcert() { # mkcert DIR CN [extra SAN]
    local dir=$1 cn=$2
    mkdir -p "$dir"
    [ -f "$dir/privkey.pem" ] && return 0
    openssl req -new -newkey rsa:2048 -nodes -keyout "$dir/privkey.pem" -subj "/CN=$cn" -out "$dir/req.csr" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$cn" >"$dir/ext.cnf"
    openssl x509 -req -in "$dir/req.csr" -CA "$CERTS/ca/inter.pem" -CAkey "$CERTS/ca/inter.key" -CAcreateserial \
        -days 365 -sha256 -extfile "$dir/ext.cnf" -out "$dir/cert.pem" 2>/dev/null
    cp "$CERTS/ca/inter.pem" "$dir/chain.pem"
    cat "$dir/cert.pem" "$dir/chain.pem" >"$dir/fullchain.pem"
    rm -f "$dir/req.csr" "$dir/ext.cnf"
    chmod 600 "$dir/privkey.pem"; chmod 644 "$dir/cert.pem" "$dir/chain.pem" "$dir/fullchain.pem"
}
if [ ! -f "$CERTS/ca/ca.pem" ]; then
    mkdir -p "$CERTS/ca"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERTS/ca/ca.key" -subj "/CN=CDP Test Root CA" -days 3650 \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$CERTS/ca/ca.pem" 2>/dev/null
    openssl req -new -newkey rsa:2048 -nodes -keyout "$CERTS/ca/inter.key" -subj "/CN=CDP Test Intermediate CA" -out "$CERTS/ca/inter.csr" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$CERTS/ca/inter.cnf"
    openssl x509 -req -in "$CERTS/ca/inter.csr" -CA "$CERTS/ca/ca.pem" -CAkey "$CERTS/ca/ca.key" -CAcreateserial \
        -days 3650 -sha256 -extfile "$CERTS/ca/inter.cnf" -out "$CERTS/ca/inter.pem" 2>/dev/null
    chmod 600 "$CERTS"/ca/*.key
fi
mkcert "$CERTS/nginx" nginx.test.local
mkcert "$CERTS/nginx-link/releases" nginx-link.test.local
if [ ! -L "$CERTS/nginx-link/fullchain.pem" ]; then
    ln -s releases/fullchain.pem "$CERTS/nginx-link/fullchain.pem"
    ln -s releases/privkey.pem "$CERTS/nginx-link/privkey.pem"
fi
mkcert "$CERTS/apache" apache.test.local
mkcert "$CERTS/haproxy-src" haproxy.test.local
mkdir -p "$CERTS/haproxy"
if [ ! -f "$CERTS/haproxy/combined.pem" ]; then
    cat "$CERTS/haproxy-src/cert.pem" "$CERTS/haproxy-src/chain.pem" "$CERTS/haproxy-src/privkey.pem" >"$CERTS/haproxy/combined.pem"
    chmod 600 "$CERTS/haproxy/combined.pem"
fi
# certbot-like layout
LE=/etc/letsencrypt
if [ ! -L "$LE/live/certbot.test.local/fullchain.pem" ]; then
    mkcert "$CERTS/certbot-src" certbot.test.local
    mkdir -p "$LE/archive/certbot.test.local" "$LE/live/certbot.test.local"
    cp "$CERTS/certbot-src/cert.pem" "$LE/archive/certbot.test.local/cert1.pem"
    cp "$CERTS/certbot-src/chain.pem" "$LE/archive/certbot.test.local/chain1.pem"
    cp "$CERTS/certbot-src/fullchain.pem" "$LE/archive/certbot.test.local/fullchain1.pem"
    cp "$CERTS/certbot-src/privkey.pem" "$LE/archive/certbot.test.local/privkey1.pem"
    chmod 600 "$LE/archive/certbot.test.local/privkey1.pem"
    for f in cert chain fullchain privkey; do
        ln -sf "../../archive/certbot.test.local/${f}1.pem" "$LE/live/certbot.test.local/$f.pem"
    done
fi
mkdir -p "$CERTS/scratch"   # used by integration tests for install()

# ------------------------------------------------------------------ sshd
cat >"$STATE/sshd_config" <<CONF
Port 2222
ListenAddress 127.0.0.1
HostKey $STATE/ssh_host_ed25519_key
PidFile $STATE/sshd.pid
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowUsers $USER_NAME
AllowTcpForwarding yes
LogLevel ERROR
CONF
if [ -f "$STATE/sshd.pid" ] && kill -0 "$(cat "$STATE/sshd.pid")" 2>/dev/null; then
    kill -HUP "$(cat "$STATE/sshd.pid")"
else
    rm -f "$STATE/sshd.pid"
    /usr/sbin/sshd -f "$STATE/sshd_config" -E "$STATE/sshd.log"
fi

# ------------------------------------------------------------------ nginx
rm -f /etc/nginx/sites-enabled/default
mkdir -p /etc/nginx/conf.d
cat >/etc/nginx/conf.d/cdp-test.conf <<CONF
server {
    listen 127.0.0.1:8443 ssl default_server;
    server_name nginx.test.local;
    ssl_certificate     $CERTS/nginx/fullchain.pem;
    ssl_certificate_key $CERTS/nginx/privkey.pem;
    location / { return 200 "nginx\n"; }
}
server {
    listen 127.0.0.1:8443 ssl;
    server_name nginx-link.test.local;
    ssl_certificate     $CERTS/nginx-link/fullchain.pem;
    ssl_certificate_key $CERTS/nginx-link/privkey.pem;
    location / { return 200 "nginx-link\n"; }
}
server {
    listen 127.0.0.1:8443 ssl;
    server_name certbot.test.local;
    ssl_certificate     /etc/letsencrypt/live/certbot.test.local/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/certbot.test.local/privkey.pem;
    location / { return 200 "certbot\n"; }
}
CONF
nginx -t
if [ -f /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then nginx -s reload; else rm -f /run/nginx.pid; nginx; fi

# ------------------------------------------------------------------ apache
if [ ! -f /etc/apache2/ports.conf.cdp-orig ]; then cp /etc/apache2/ports.conf /etc/apache2/ports.conf.cdp-orig; fi
printf 'Listen 127.0.0.1:8081\nListen 127.0.0.1:9443\n' >/etc/apache2/ports.conf
printf 'ServerName localhost\n' >/etc/apache2/conf-available/cdp-servername.conf
a2enconf -q cdp-servername >/dev/null
a2enmod -q ssl >/dev/null
a2dissite -q 000-default default-ssl 2>/dev/null || true
cat >/etc/apache2/sites-available/cdp-test.conf <<CONF
<VirtualHost 127.0.0.1:8081>
    ServerName apache-plain.test.local
</VirtualHost>
<VirtualHost 127.0.0.1:9443>
    ServerName apache.test.local
    SSLEngine on
    SSLCertificateFile    $CERTS/apache/cert.pem
    SSLCertificateKeyFile $CERTS/apache/privkey.pem
    SSLCertificateChainFile $CERTS/apache/chain.pem
</VirtualHost>
CONF
a2ensite -q cdp-test >/dev/null
mkdir -p /var/run/apache2 /var/lock/apache2
apachectl configtest
if pidof apache2 >/dev/null 2>&1; then apachectl -k graceful; else rm -f /var/run/apache2/apache2.pid; apachectl -k start; fi

# ------------------------------------------------------------------ haproxy
if [ ! -f /etc/haproxy/haproxy.cfg.cdp-orig ]; then cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.cdp-orig; fi
cat >/etc/haproxy/haproxy.cfg <<CONF
global
    daemon

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend fe_tls
    bind 127.0.0.1:10443 ssl crt $CERTS/haproxy/combined.pem
    http-request return status 200 content-type text/plain string "haproxy\n"
CONF
haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
if [ -f /run/haproxy.pid ] && kill -0 "$(head -n1 /run/haproxy.pid)" 2>/dev/null; then
    haproxy -f /etc/haproxy/haproxy.cfg -D -p /run/haproxy.pid -sf $(cat /run/haproxy.pid)
else
    rm -f /run/haproxy.pid; haproxy -f /etc/haproxy/haproxy.cfg -D -p /run/haproxy.pid
fi

# ------------------------------------------------------------------ wait
for port in 2222 8443 9443 10443; do
    for _ in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && break || sleep 0.2
    done
done
echo "cdp test target ready: ssh 127.0.0.1:2222 user=$USER_NAME key=$STATE/id_ed25519 hostkey=$STATE/ssh_host_ed25519_key.pub"
