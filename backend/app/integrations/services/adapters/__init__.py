from app.integrations.services.adapters import builtin  # noqa: F401  (registers built-in adapters)
from app.integrations.services.adapters.base import (
    ArtifactKind,
    PlanError,
    PlannedFile,
    ServiceAdapter,
    UnsupportedServiceError,
    get_adapter,
    register_adapter,
    registered_service_types,
)
from app.integrations.services.adapters.builtin import ApacheAdapter, HaproxyAdapter, NginxAdapter

__all__ = [
    "ApacheAdapter", "ArtifactKind", "HaproxyAdapter", "NginxAdapter", "PlanError", "PlannedFile",
    "ServiceAdapter", "UnsupportedServiceError", "get_adapter", "register_adapter", "registered_service_types",
]
