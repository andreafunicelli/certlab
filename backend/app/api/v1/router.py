from fastapi import APIRouter

from app.api.v1 import auth, credentials, misc, servers, users

api_router = APIRouter()
for r in (auth.router, users.router, credentials.router, servers.router, misc.router):
    api_router.include_router(r)
