"""RBAC permission matrix. Reusable from API dependencies and background jobs."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from app.core.errors import AppError

ADMIN, OPERATOR, VIEWER = "admin", "operator", "viewer"
ALL_ROLES = (ADMIN, OPERATOR, VIEWER)

_VIEWER = frozenset({
    "dashboard:read", "servers:read", "environments:read", "certificates:read", "installations:read",
    "discovery:read", "versions:read", "deployments:read", "backups:read", "logs:read", "audit:read",
    "settings:read",
})
_OPERATOR = _VIEWER | frozenset({
    "servers:test", "discovery:run", "certificates:verify", "installations:verify", "versions:upload",
    "deployments:plan", "deployments:create", "deployments:cancel", "deployments:retry",
})

# admin gets everything ("*"); the explicit list documents the full set of known permissions.
ALL_PERMISSIONS = frozenset(_OPERATOR | {
    "users:read", "users:write", "users:roles",
    "credentials:read", "credentials:write",
    "servers:write", "servers:hostkey",
    "environments:write", "settings:write",
    "installations:write",
    "deployments:approve", "deployments:rollback",
    "backups:restore", "backups:download",
    "notifications:read", "notifications:write",
})

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    ADMIN: ALL_PERMISSIONS,
    OPERATOR: _OPERATOR,
    VIEWER: _VIEWER,
}


class HasRoles(Protocol):
    @property
    def role_names(self) -> list[str]: ...


def permissions_for_roles(roles: Iterable[str]) -> frozenset[str]:
    perms: set[str] = set()
    for r in roles:
        perms |= ROLE_PERMISSIONS.get(r, frozenset())
    return frozenset(perms)


def has_permission(roles: Iterable[str], permission: str) -> bool:
    perms = permissions_for_roles(roles)
    return permission in perms or "*" in perms


def authorize(user: HasRoles, permission: str) -> None:
    """Raise AppError(403) unless the user's roles grant ``permission``."""
    if not getattr(user, "enabled", True):
        raise AppError("FORBIDDEN", "Account is disabled", 403)
    if not has_permission(user.role_names, permission):
        raise AppError("FORBIDDEN", "You do not have permission to perform this action", 403,
                       {"required_permission": permission})
