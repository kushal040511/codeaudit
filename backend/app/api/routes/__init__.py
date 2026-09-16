from fastapi import APIRouter

from app.api.routes import architecture, llm, scans

# API routes, mounted under settings.api_prefix. /health is mounted at the root.
api_router = APIRouter()
api_router.include_router(scans.router)
api_router.include_router(architecture.router)
api_router.include_router(llm.router)
