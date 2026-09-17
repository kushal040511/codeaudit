from fastapi import APIRouter

from app.api.routes import architecture, auth, compare, llm, pull_requests, scans, score, sites

# API routes, mounted under settings.api_prefix. /health is mounted at the root.
api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(compare.router)
api_router.include_router(scans.router)
api_router.include_router(architecture.router)
api_router.include_router(llm.router)
api_router.include_router(score.router)
api_router.include_router(pull_requests.router)
api_router.include_router(sites.router)
