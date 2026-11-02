from __future__ import annotations

from app.integrations.contracts import ServiceType
from app.integrations.services.parsers.nginx import parse_nginx_dump, tokenize

DUMP = r'''nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
# configuration file /etc/nginx/nginx.conf:
user www-data;
events { worker_connections 768; }
http {
    # server { ssl_certificate /should/not/count.pem; }   braces } { in comment
    ssl_certificate     /etc/ssl/default.crt;
    ssl_certificate_key /etc/ssl/default.key;
    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include sites-enabled/*;
}

# configuration file /etc/nginx/mime.types:
types { text/html html; }

# configuration file /etc/nginx/conf.d/a.conf:
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name a.example.com www.a.example.com;
    ssl_certificate /etc/letsencrypt/live/a/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/a/privkey.pem;
}
server {
    listen 80;
    server_name plain.example.com;
}
server {
    listen 8443 ssl;
    server_name inherits.example.com;
}

# configuration file /etc/nginx/sites-enabled/dual:
server {
    listen 443 ssl;
    server_name dual.example.com;
    ssl_certificate certs/rsa.crt;
    ssl_certificate_key certs/rsa.key;
    ssl_certificate "/etc/nginx/certs/ecdsa.crt";
    ssl_certificate_key '/etc/nginx/certs/ecdsa.key';
}
server {
    listen 443 ssl;
    server_name var.example.com;
    ssl_certificate /etc/ssl/$ssl_server_name.crt;
    ssl_certificate_key /etc/ssl/$ssl_server_name.key;
}
server {
    listen 443 ssl;
    server_name data.example.com;
    ssl_certificate data:$cert_var;
    ssl_certificate_key data:$key_var;
}
server {
    listen unix:/run/nginx.sock;
    listen 127.0.0.1:9443 ssl;
    server_name sock.example.com;
    ssl_certificate /etc/ssl/s.crt;
    ssl_certificate_key /etc/ssl/s.key;
}
server {
    ssl on;
    server_name noport.example.com;
    ssl_certificate /etc/ssl/n.crt;
    ssl_certificate_key /etc/ssl/n.key;
}

# configuration file /etc/nginx/unrelated.conf:
server { listen 443 ssl; ssl_certificate /not/included.crt; ssl_certificate_key /not/included.key; }
'''


def by_name(refs, name):
    return [r for r in refs if name in r.server_names]


def test_servers_and_defaults():
    refs = parse_nginx_dump(DUMP)
    assert all(r.service == ServiceType.NGINX for r in refs)
    assert not [r for r in refs if r.cert_path == "/not/included.crt"]
    assert not [r for r in refs if r.cert_path == "/should/not/count.pem"]
    a = by_name(refs, "a.example.com")
    assert len(a) == 1
    r = a[0]
    assert r.cert_path == "/etc/letsencrypt/live/a/fullchain.pem"
    assert r.key_path == "/etc/letsencrypt/live/a/privkey.pem"
    assert r.server_names == ("a.example.com", "www.a.example.com")
    assert r.listen_ports == (443,)
    assert r.config_file == "/etc/nginx/conf.d/a.conf" and r.line == 5
    assert r.confidence == 1.0 and r.unresolved_expression is None and not r.is_combined_pem
    assert "a.example.com" in r.context and "443" in r.context


def test_http_level_inheritance():
    refs = parse_nginx_dump(DUMP)
    (r,) = by_name(refs, "inherits.example.com")
    assert r.cert_path == "/etc/ssl/default.crt" and r.key_path == "/etc/ssl/default.key"
    assert r.listen_ports == (8443,)
    assert r.config_file == "/etc/nginx/nginx.conf"
    # server without any ssl listener but inheriting certs is still reported (port 80 listener)
    (p,) = by_name(refs, "plain.example.com")
    assert p.listen_ports == (80,)


def test_dual_certificates_and_relative_paths():
    refs = by_name(parse_nginx_dump(DUMP), "dual.example.com")
    assert [(r.cert_path, r.key_path) for r in refs] == [
        ("/etc/nginx/certs/rsa.crt", "/etc/nginx/certs/rsa.key"),
        ("/etc/nginx/certs/ecdsa.crt", "/etc/nginx/certs/ecdsa.key"),
    ]
    assert refs[0].line != refs[1].line


def test_variables_unresolved():
    (r,) = by_name(parse_nginx_dump(DUMP), "var.example.com")
    assert r.cert_path is None and r.key_path is None
    assert r.confidence == 0.0
    assert "$ssl_server_name" in r.unresolved_expression


def test_data_scheme_unsupported():
    (r,) = by_name(parse_nginx_dump(DUMP), "data.example.com")
    assert r.cert_path is None and r.confidence == 0.0 and r.unresolved_expression.startswith("data:")


def test_unix_listen_ignored_and_ip_port():
    (r,) = by_name(parse_nginx_dump(DUMP), "sock.example.com")
    assert r.listen_ports == (9443,)


def test_ssl_on_without_listen_defaults_443():
    (r,) = by_name(parse_nginx_dump(DUMP), "noport.example.com")
    assert r.listen_ports == (443,)


def test_ipv6_listen_dedup():
    (r,) = by_name(parse_nginx_dump(DUMP), "a.example.com")
    assert r.listen_ports == (443,)


def test_stream_block():
    text = '''# configuration file /etc/nginx/nginx.conf:
stream {
    ssl_certificate /etc/ssl/stream-default.crt;
    ssl_certificate_key /etc/ssl/stream-default.key;
    server {
        listen 12345 ssl;
        proxy_pass backend:1234;
    }
    server {
        listen 853 ssl;
        ssl_certificate /etc/ssl/dot.crt;
        ssl_certificate_key /etc/ssl/dot.key;
    }
}
http { server { listen 443 ssl; ssl_certificate a.crt; ssl_certificate_key a.key; } }
'''
    refs = parse_nginx_dump(text)
    assert len(refs) == 3
    s1, s2, h = refs
    assert s1.cert_path == "/etc/ssl/stream-default.crt" and s1.listen_ports == (12345,)
    assert s1.context.startswith("stream ")
    assert s2.cert_path == "/etc/ssl/dot.crt" and s2.listen_ports == (853,)
    assert h.cert_path == "/etc/nginx/a.crt" and not h.context.startswith("stream")


def test_single_file_without_headers():
    text = "http { server { listen 443 ssl; server_name x.test; ssl_certificate /c.pem; ssl_certificate_key /k.pem; } }"
    (r,) = parse_nginx_dump(text)
    assert r.config_file == "/etc/nginx/nginx.conf" and r.cert_path == "/c.pem"


def test_tokenizer_quotes_escapes_comments():
    toks = tokenize('a "b c" \'d\\\'e\' f#notcomment; # comment { }\n g { }')
    vals = [(t.kind, t.value) for t in toks]
    assert vals == [("word", "a"), ("word", "b c"), ("word", "d'e"), ("word", "f#notcomment"), (";", ";"),
                    ("word", "g"), ("{", "{"), ("}", "}")]
    assert toks[-3].line == 2


def test_tokenizer_variable_braces():
    toks = tokenize("set $x ${foo}bar;")
    assert [t.value for t in toks if t.kind == "word"] == ["set", "$x", "${foo}bar"]


def test_unbalanced_and_garbage_do_not_raise():
    assert parse_nginx_dump("http { server { listen 443 ssl; ssl_certificate /a; ssl_certificate_key /b;") != []
    assert parse_nginx_dump("}}} ;;; {") == []
    assert parse_nginx_dump("") == []


def test_include_cycle_safe():
    text = '''# configuration file /etc/nginx/nginx.conf:
include /etc/nginx/a.conf;
# configuration file /etc/nginx/a.conf:
include /etc/nginx/nginx.conf;
include /etc/nginx/a.conf;
'''
    assert parse_nginx_dump(text) == []


def test_included_file_line_numbers():
    text = '''# configuration file /etc/nginx/nginx.conf:
http { include conf.d/*.conf; }
# configuration file /etc/nginx/conf.d/x.conf:


server { listen 443 ssl;
  ssl_certificate /x.crt;
  ssl_certificate_key /x.key; }
'''
    (r,) = parse_nginx_dump(text)
    assert (r.config_file, r.line) == ("/etc/nginx/conf.d/x.conf", 4)
