from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.errors import register_exception_handlers
from app.api.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.api.rate_limit import request_rate_limit
from app.api.routes import api_router, health
from app.config import MB, get_settings
from app.core import metrics
from app.core.live_metrics import register_api_collectors
from app.core.observability import configure_logging, init_sentry


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()
    init_sentry("api")

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        debug=settings.debug,
        # No interactive docs in production: they widen the attack surface.
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.environment == "production" else "/openapi.json",
    )
    # Allow the archive plus multipart framing overhead.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + MB)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Authorization", "X-Request-ID"],
        expose_headers=[
            "X-Request-ID",
            "Retry-After",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-RateLimit-Policy",
            "X-Total-Count",
            "Link",
        ],
    )
    # Outermost: sees every response, including errors raised by the layers above.
    app.add_middleware(RequestContextMiddleware, hsts=settings.environment == "production")
    register_exception_handlers(app)
    app.include_router(health.router)
    app.include_router(
        api_router, prefix=settings.api_prefix, dependencies=[Depends(request_rate_limit)]
    )
    metrics.reset_multiprocess_dir()
    register_api_collectors()
    return app


app = create_app()
