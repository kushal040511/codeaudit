from fastapi import APIRouter

from app.api.routes import architecture, scans

# API routes, mounted under settings.api_prefix. /health is mounted at the root.
api_router = APIRouter()
api_router.include_router(scans.router)
api_router.include_router(architecture.router)
