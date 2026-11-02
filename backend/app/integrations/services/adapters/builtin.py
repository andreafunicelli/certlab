"""Built-in adapters: nginx, apache, haproxy."""
from __future__ import annotations

import posixpath
import re
from importlib import import_module

from app.integrations.contracts import ConfigCertRef, RemoteHost, ServiceType
from app.integrations.services.adapters.base import (
    ArtifactKind,
    InstallationLike,
    PlanError,
    PlannedFile,
    ServiceAdapter,
    register_adapter,
)

_CERT_MODE = 0o644
_KEY_MODE = 0o600


def _require(path: str | None, what: str) -> str:
    if not path:
        raise PlanError(f"installation has no {what}")
    return path


def _parser(module: str, func: str):
    # imported lazily: parsers are a separate package (pure functions, no I/O)
    return getattr(import_module(f"app.integrations.services.parsers.{module}"), func)


@register_adapter
class NginxAdapter(ServiceAdapter):
    service_type = ServiceType.NGINX.value

    async def discover(self, host: RemoteHost) -> list[ConfigCertRef]:
        text = await host.dump_config(ServiceType.NGINX)
        return list(_parser("nginx", "parse_nginx_dump")(text))

    def plan_files(self, installation: InstallationLike) -> list[PlannedFile]:
        cert = _require(installation.cert_path, "certificate path")
        key = _require(installation.key_path, "private key path")
        if installation.is_combined_pem:
            raise PlanError("nginx does not use combined PEM files")
        # nginx `ssl_certificate` must contain leaf + intermediates
        return [
            PlannedFile(cert, ArtifactKind.FULLCHAIN, _CERT_MODE),
            PlannedFile(key, ArtifactKind.KEY, _KEY_MODE, contains_private_key=True),
        ]


@register_adapter
class ApacheAdapter(ServiceAdapter):
    service_type = ServiceType.APACHE.value

    async def discover(self, host: RemoteHost) -> list[ConfigCertRef]:
        text = await host.dump_config(ServiceType.APACHE)
        m = re.search(r"^# cdp-server-root: (\S+)", text, re.MULTILINE)
        server_root = m.group(1) if m else "/etc/apache2"
        return list(_parser("apache", "parse_apache_dump")(text, server_root))

    def plan_files(self, installation: InstallationLike) -> list[PlannedFile]:
        cert = _require(installation.cert_path, "certificate path")
        key = _require(installation.key_path, "private key path")
        if installation.is_combined_pem:
            raise PlanError("apache does not use combined PEM files")
        files: list[PlannedFile] = []
        if installation.chain_path:
            files.append(PlannedFile(cert, ArtifactKind.CERT, _CERT_MODE))
            files.append(PlannedFile(installation.chain_path, ArtifactKind.CHAIN, _CERT_MODE))
        else:
            # Apache >= 2.4.8 accepts leaf + intermediates in SSLCertificateFile
            files.append(PlannedFile(cert, ArtifactKind.FULLCHAIN, _CERT_MODE))
        files.append(PlannedFile(key, ArtifactKind.KEY, _KEY_MODE, contains_private_key=True))
        return files


@register_adapter
class HaproxyAdapter(ServiceAdapter):
    service_type = ServiceType.HAPROXY.value

    async def discover(self, host: RemoteHost) -> list[ConfigCertRef]:
        text = await host.dump_config(ServiceType.HAPROXY)
        m = re.search(r"^# configuration file (\S+):", text, re.MULTILINE)
        base_dir = posixpath.dirname(m.group(1)) if m else "/etc/haproxy"
        return list(_parser("haproxy", "parse_haproxy_cfg")(text, base_dir))

    def plan_files(self, installation: InstallationLike) -> list[PlannedFile]:
        path = _require(installation.cert_path, "certificate path")
        if getattr(installation, "is_directory", False):
            raise PlanError("haproxy 'crt <directory>' references need a per-file mapping before deployment")
        # HAProxy reads certificate, chain and key from ONE pem: cert + chain + key (in that order)
        return [PlannedFile(path, ArtifactKind.COMBINED, _KEY_MODE, contains_private_key=True)]
