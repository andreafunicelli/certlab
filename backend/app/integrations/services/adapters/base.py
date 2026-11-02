"""Service adapters: everything service specific (discovery, file plan, config test, reload, verify endpoints).

Plugin model
------------
An adapter is a subclass of :class:`ServiceAdapter` with a unique ``service_type`` (a string; the built-in ones
use ``contracts.ServiceType`` values). Register it with :func:`register_adapter` (decorator) and look it up with
:func:`get_adapter`. To add Tomcat / JKS / Postfix later:

1. add a parser module under ``integrations/services/parsers`` returning ``ConfigCertRef`` objects,
2. subclass ``ServiceAdapter`` implementing ``discover``, ``plan_files``, ``config_test``, ``reload`` and
   ``default_verify_endpoints`` (new artifact kinds, e.g. a JKS keystore, extend :class:`ArtifactKind`),
3. extend the remote helper (``infra/remote-helper/cdp-helper``) with the matching ``dump``/``configtest``/
   ``reload`` subcommand; adapters never run arbitrary commands, only helper subcommands via ``RemoteHost``.

Contract (all adapters)
-----------------------
* ``discover(host)`` is read-only: calls ``host.dump_config`` and the pure parser, returns ``ConfigCertRef`` list.
* ``plan_files(installation)`` is pure: decides which destination path receives which artifact. ``installation``
  is any object with ``cert_path``, ``key_path``, ``chain_path`` and ``is_combined_pem`` attributes (a DB row
  or a ``ConfigCertRef``). Raises :class:`PlanError` if the installation cannot be deployed to automatically.
* ``config_test`` / ``reload`` delegate to the helper, return a ``CommandResult`` (non-zero exit_status = failed).
* ``default_verify_endpoints(ref)`` yields ``(host, port, sni)`` candidates. ``host`` is the server name from the
  config (may be ``""`` when unknown); the caller substitutes the managed server's address when it is empty or
  when the admin mapped an explicit verify endpoint.
"""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Protocol

from app.integrations.contracts import CommandResult, ConfigCertRef, RemoteHost, ServiceType


class ArtifactKind(str, enum.Enum):
    CERT = "cert"                   # leaf certificate only
    KEY = "key"                     # private key (PKCS8/PEM, unencrypted)
    CHAIN = "chain"                 # intermediates only
    FULLCHAIN = "fullchain"         # leaf + intermediates
    COMBINED = "combined"           # haproxy: leaf + intermediates + private key, in that order


@dataclass(frozen=True)
class PlannedFile:
    dest_path: str
    artifact: ArtifactKind
    mode: int                       # requested file mode
    contains_private_key: bool = False
    # owner/group are deliberately not planned: the deployment engine preserves the existing file's ownership


class PlanError(ValueError):
    pass


class UnsupportedServiceError(KeyError):
    pass


class InstallationLike(Protocol):
    cert_path: str | None
    key_path: str | None
    chain_path: str | None
    is_combined_pem: bool


class ServiceAdapter(ABC):
    service_type: ClassVar[str]

    @abstractmethod
    async def discover(self, host: RemoteHost) -> list[ConfigCertRef]: ...

    @abstractmethod
    def plan_files(self, installation: InstallationLike) -> list[PlannedFile]: ...

    @property
    def _service(self) -> ServiceType:
        return ServiceType(self.service_type)

    async def config_test(self, host: RemoteHost) -> CommandResult:
        return await host.config_test(self._service)

    async def reload(self, host: RemoteHost, allow_restart: bool = False) -> CommandResult:
        return await host.reload(self._service, allow_restart)

    def default_verify_endpoints(self, ref: ConfigCertRef) -> list[tuple[str, int, str | None]]:
        ports = ref.listen_ports or (443,)
        names = [n for n in ref.server_names if n and n != "_" and not n.startswith("~")]
        out: list[tuple[str, int, str | None]] = []
        for port in ports:
            if not names:
                out.append(("", port, None))
            for name in names:
                wildcard = "*" in name
                out.append(("" if wildcard else name, port, None if wildcard else name))
        return out


_REGISTRY: dict[str, type[ServiceAdapter]] = {}


def register_adapter(cls: type[ServiceAdapter]) -> type[ServiceAdapter]:
    _REGISTRY[cls.service_type] = cls
    return cls


def get_adapter(service_type: ServiceType | str) -> ServiceAdapter:
    key = service_type.value if isinstance(service_type, ServiceType) else str(service_type)
    try:
        return _REGISTRY[key]()
    except KeyError:
        raise UnsupportedServiceError(f"no adapter for service type {key!r}") from None


def registered_service_types() -> list[str]:
    return sorted(_REGISTRY)
