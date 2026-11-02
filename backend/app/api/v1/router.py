from fastapi import APIRouter

from app.api.v1 import (
    auth,
    backups,
    certificates,
    credentials,
    deployments,
    discovery,
    installations,
    misc,
    notifications,
    servers,
    users,
    versions,
)

api_router = APIRouter()
# one router per line: parallel streams add their include on a new line
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(credentials.router)
api_router.include_router(servers.router)
api_router.include_router(certificates.router)
api_router.include_router(installations.router)
api_router.include_router(discovery.router)
api_router.include_router(versions.router)
api_router.include_router(notifications.router)
api_router.include_router(deployments.router)
api_router.include_router(backups.router)
api_router.include_router(misc.router)
