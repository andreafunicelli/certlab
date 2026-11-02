from __future__ import annotations

from app.integrations.contracts import ServiceType
from app.integrations.services.parsers.apache import parse_apache_dump

DUMP = r'''# configuration file /etc/apache2/apache2.conf:
# Global
ServerRoot "/etc/apache2"
Define SITE_DIR /etc/ssl/sites
Define CERT_NAME shop
Listen 80
IncludeOptional mods-enabled/*.conf
Include ports.conf
IncludeOptional sites-enabled/*.conf

# configuration file /etc/apache2/ports.conf:
Listen 80
<IfModule ssl_module>
    Listen 443
</IfModule>
<IfModule mod_gnutls.c>
    Listen 443
</IfModule>

# configuration file /etc/apache2/mods-enabled/ssl.conf:
<IfModule mod_ssl.c>
  SSLCertificateFile /etc/ssl/global-default.pem
  SSLCertificateKeyFile /etc/ssl/global-default.key
</IfModule>

# configuration file /etc/apache2/sites-enabled/main.conf:
<VirtualHost *:80>
    ServerName www.example.com
    Redirect / https://www.example.com/
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost _default_:443 [::]:8443>
    ServerName "www.example.com:443"
    ServerAlias example.com  Static.example.com
    ServerAlias \
        cdn.example.com
    sslengine ON
    SSLCERTIFICATEFILE "/etc/ssl/certs/www.crt"
    SSLCertificateKeyFile   /etc/ssl/private/www.key
    SSLCertificateChainFile chain/ca.crt
</VirtualHost>

# configuration file /etc/apache2/sites-enabled/combined.conf:
<VirtualHost 10.0.0.2:443>
    ServerName combined.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/combined.pem
</VirtualHost>
<VirtualHost *:443>
    ServerName inherits.example.com
    SSLEngine on
</VirtualHost>
<VirtualHost *:443>
    ServerName var.example.com
    SSLEngine on
    SSLCertificateFile ${SITE_DIR}/${CERT_NAME}.crt
    SSLCertificateKeyFile ${UNDEFINED_DIR}/shop.key
</VirtualHost>
<VirtualHost *:443>
    ServerName defined.example.com
    SSLEngine on
    SSLCertificateFile ${SITE_DIR}/${CERT_NAME}.crt
    SSLCertificateKeyFile ${SITE_DIR}/${CERT_NAME}.key
</VirtualHost>
<VirtualHost *:443>
    ServerName off.example.com
    SSLEngine off
    SSLCertificateFile /etc/ssl/off.crt
</VirtualHost>
<VirtualHost *:443>
    ServerName dual.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/rsa.crt
    SSLCertificateKeyFile /etc/ssl/rsa.key
    SSLCertificateFile /etc/ssl/ecc.crt
    SSLCertificateKeyFile /etc/ssl/ecc.key
</VirtualHost>
<IfDefine USE_TLS>
<VirtualHost *:9443>
    ServerName ifdefine.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/ifd.crt
    SSLCertificateKeyFile /etc/ssl/ifd.key
</VirtualHost>
</IfDefine>
<VirtualHost *:443>
    ServerName noengine.example.com
    SSLCertificateFile /etc/ssl/noengine.crt
    SSLCertificateKeyFile /etc/ssl/noengine.key
</VirtualHost>
'''


def name(refs, n):
    return [r for r in refs if n in r.server_names]


def test_vhost_full():
    refs = parse_apache_dump(DUMP)
    (r,) = name(refs, "www.example.com")
    assert r.service == ServiceType.APACHE
    assert r.cert_path == "/etc/ssl/certs/www.crt"
    assert r.key_path == "/etc/ssl/private/www.key"
    assert r.chain_path == "/etc/apache2/chain/ca.crt"  # relative -> ServerRoot
    assert not r.is_combined_pem
    assert r.server_names == ("www.example.com", "example.com", "Static.example.com", "cdn.example.com")
    assert r.listen_ports == (443, 8443)
    assert r.confidence == 1.0
    assert r.config_file == "/etc/apache2/sites-enabled/main.conf"
    assert r.line == 12  # case-insensitive directive, line of SSLCertificateFile
    assert r.context.startswith("<VirtualHost _default_:443")


def test_http_vhost_without_ssl_not_reported():
    refs = parse_apache_dump(DUMP)
    # port-80 vhost has no cert and the global default is only used where SSLEngine is on
    assert all(80 not in r.listen_ports for r in refs)


def test_combined_when_no_key():
    (r,) = name(parse_apache_dump(DUMP), "combined.example.com")
    assert r.is_combined_pem and r.key_path is None
    assert r.cert_path == "/etc/ssl/combined.pem"
    assert r.listen_ports == (443,)


def test_global_defaults_inherited():
    (r,) = name(parse_apache_dump(DUMP), "inherits.example.com")
    assert r.cert_path == "/etc/ssl/global-default.pem" and r.key_path == "/etc/ssl/global-default.key"
    assert r.config_file == "/etc/apache2/mods-enabled/ssl.conf"
    assert r.confidence == 1.0  # IfModule is treated as active


def test_define_expansion_and_unresolved():
    refs = parse_apache_dump(DUMP)
    (d,) = name(refs, "defined.example.com")
    assert d.cert_path == "/etc/ssl/sites/shop.crt" and d.key_path == "/etc/ssl/sites/shop.key"
    assert d.unresolved_expression is None
    (v,) = name(refs, "var.example.com")
    assert v.cert_path == "/etc/ssl/sites/shop.crt"  # resolvable part
    assert v.key_path is None and v.confidence == 0.0
    assert "${UNDEFINED_DIR}" in v.unresolved_expression


def test_engine_off_skipped():
    assert name(parse_apache_dump(DUMP), "off.example.com") == []


def test_multiple_cert_pairs():
    refs = name(parse_apache_dump(DUMP), "dual.example.com")
    assert [(r.cert_path, r.key_path) for r in refs] == [
        ("/etc/ssl/rsa.crt", "/etc/ssl/rsa.key"), ("/etc/ssl/ecc.crt", "/etc/ssl/ecc.key")
    ]


def test_ifdefine_lower_confidence():
    (r,) = name(parse_apache_dump(DUMP), "ifdefine.example.com")
    assert r.confidence == 0.8 and r.listen_ports == (9443,)


def test_missing_sslengine_lower_confidence():
    (r,) = name(parse_apache_dump(DUMP), "noengine.example.com")
    assert r.confidence == 0.5


def test_server_root_param_and_directive():
    text = '''# configuration file /etc/httpd/conf/httpd.conf:
ServerRoot "/etc/httpd"
Listen 443
<VirtualHost *:443>
  ServerName rel.example.com
  SSLEngine on
  SSLCertificateFile conf/ssl/rel.crt
  SSLCertificateKeyFile conf/ssl/rel.key
</VirtualHost>
'''
    (r,) = parse_apache_dump(text, server_root="/etc/apache2")
    assert r.cert_path == "/etc/httpd/conf/ssl/rel.crt"
    (r,) = parse_apache_dump(text.replace('ServerRoot "/etc/httpd"\n', ""), server_root="/srv/apache")
    assert r.cert_path == "/srv/apache/conf/ssl/rel.crt"


def test_vhost_without_port_uses_listen():
    text = '''Listen 443
Listen 8443
<VirtualHost *>
  SSLEngine on
  SSLCertificateFile /a.crt
  SSLCertificateKeyFile /a.key
</VirtualHost>'''
    (r,) = parse_apache_dump(text)
    assert r.listen_ports == (443, 8443) and r.config_file == "/etc/apache2/apache2.conf"


def test_global_only_config():
    text = '''Listen 443
ServerName g.example.com
SSLEngine on
SSLCertificateFile /g.crt
SSLCertificateKeyFile /g.key
'''
    (r,) = parse_apache_dump(text)
    assert r.context == "<global>" and r.cert_path == "/g.crt" and r.listen_ports == (443,)
    assert r.server_names == ("g.example.com",)


def test_comments_ignored_and_garbage_safe():
    text = '''# SSLCertificateFile /commented.crt
<VirtualHost *:443>
  SSLEngine on
  # SSLCertificateFile /nope
  SSLCertificateFile /real.crt
</VirtualHost>
</Directory>
<Unclosed foo
'''
    (r,) = parse_apache_dump(text)
    assert r.cert_path == "/real.crt"
    assert parse_apache_dump("") == []


def test_include_directory_and_cycle():
    text = '''# configuration file /etc/apache2/apache2.conf:
Include conf-enabled/
Include apache2.conf
# configuration file /etc/apache2/conf-enabled/x.conf:
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /x.crt
  SSLCertificateKeyFile /x.key
</VirtualHost>
'''
    (r,) = parse_apache_dump(text)
    assert r.config_file == "/etc/apache2/conf-enabled/x.conf"
