from __future__ import annotations

from app.integrations.contracts import ServiceType
from app.integrations.services.parsers.haproxy import parse_haproxy_cfg

CFG = '''global
    log /dev/log local0
    crt-base /etc/ssl/private
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    mode http
    timeout connect 5s

frontend https_in
    bind :80
    bind *:443 ssl crt /etc/haproxy/certs/site.pem crt wildcard.pem alpn h2,http/1.1
    bind [::]:443,0.0.0.0:8443 v4v6 ssl crt "/etc/haproxy/certs/quoted.pem"  # trailing comment
    bind unix@/run/haproxy.sock ssl crt /etc/haproxy/certs/sock.pem
    default_backend app

frontend dirfront
    bind :9443 ssl crt /etc/haproxy/certs/
    bind :9444 ssl crt /etc/haproxy/certdir
    bind :9445 ssl crt /etc/haproxy/single.pem

listen stats
    bind 10.0.0.1:8404 ssl crt-list /etc/haproxy/crt-list.txt
    bind ipv4@:8405 crt /etc/haproxy/not-ssl.pem
    bind :8406 ssl crt /etc/haproxy/$HOST.pem

backend app
    bind :1234 ssl crt /etc/haproxy/ignored.pem
    server s1 10.0.0.5:80
'''


def paths(refs):
    return [r.cert_path for r in refs]


def test_multiple_crt_and_ports():
    refs = parse_haproxy_cfg(CFG)
    assert all(r.service == ServiceType.HAPROXY for r in refs)
    assert paths(refs)[:4] == [
        "/etc/haproxy/certs/site.pem",
        "/etc/ssl/private/wildcard.pem",
        "/etc/haproxy/certs/quoted.pem",
        "/etc/haproxy/certs/sock.pem",
    ]
    first, second, third, sock = refs[:4]
    assert first.listen_ports == (443,) and second.listen_ports == (443,)
    assert third.listen_ports == (443, 8443)
    assert sock.listen_ports == ()
    assert first.is_combined_pem and first.key_path is None and not first.is_directory
    assert first.config_file == "/etc/haproxy/haproxy.cfg" and first.line == 12
    assert "https_in" in first.context and "sibling key convention: /etc/haproxy/certs/site.pem.key" in first.context


def test_crt_base_applies_to_relative_only():
    refs = parse_haproxy_cfg(CFG)
    assert refs[1].cert_path == "/etc/ssl/private/wildcard.pem"
    refs = parse_haproxy_cfg(CFG.replace("    crt-base /etc/ssl/private\n", ""))
    assert refs[1].cert_path == "/etc/haproxy/wildcard.pem"
    refs = parse_haproxy_cfg(CFG.replace("    crt-base /etc/ssl/private\n", ""), base_dir="/opt/hap")
    assert refs[1].cert_path == "/opt/hap/wildcard.pem"


def test_directory_crt():
    refs = {r.cert_path: r for r in parse_haproxy_cfg(CFG)}
    d = refs["/etc/haproxy/certs"]
    assert d.is_directory and d.confidence == 1.0 and d.listen_ports == (9443,)
    nod = refs["/etc/haproxy/certdir"]
    assert nod.is_directory and nod.confidence < 1.0
    single = refs["/etc/haproxy/single.pem"]
    assert not single.is_directory and single.confidence == 1.0


def test_crt_list_unsupported():
    (r,) = [r for r in parse_haproxy_cfg(CFG) if r.unresolved_expression and "crt-list" in r.unresolved_expression]
    assert r.cert_path is None and r.confidence <= 0.2 and r.listen_ports == (8404,)
    assert "not supported" in r.context


def test_variable_unresolved():
    (r,) = [r for r in parse_haproxy_cfg(CFG) if r.unresolved_expression and "$HOST" in r.unresolved_expression]
    assert r.cert_path is None and r.confidence == 0.0


def test_non_ssl_and_backend_binds_ignored():
    ps = paths(parse_haproxy_cfg(CFG))
    assert "/etc/haproxy/not-ssl.pem" not in ps and "/etc/haproxy/ignored.pem" not in ps


def test_multi_file_dump_and_crt_base_in_other_file():
    text = '''# configuration file /etc/haproxy/haproxy.cfg:
global
    log stdout local0

# configuration file /etc/haproxy/conf.d/10-front.cfg:
frontend fe
    bind :443 ssl crt a.pem
# configuration file /etc/haproxy/conf.d/00-global.cfg:
global
    crt-base /srv/tls
'''
    (r,) = parse_haproxy_cfg(text)
    assert r.config_file == "/etc/haproxy/conf.d/10-front.cfg" and r.line == 2
    assert r.cert_path == "/srv/tls/a.pem"


def test_empty_and_garbage():
    assert parse_haproxy_cfg("") == []
    assert parse_haproxy_cfg("bind :443 ssl crt /x.pem") == []  # not inside a frontend/listen
    parse_haproxy_cfg('frontend f\n  bind :443 ssl crt "unterminated')  # must not raise
