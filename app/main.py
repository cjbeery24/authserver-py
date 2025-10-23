"""
Main FastAPI application entry point.
"""

from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# Import OAuth2 error class for exception handling
from app.api.v1.oauth import OAuth2Error
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from contextlib import asynccontextmanager
import time
import logging
import asyncio
from datetime import datetime, timezone, timedelta

# Import custom middleware
from app.middleware import (
    AuthMiddleware,
    OptionalAuthMiddleware,
    SecurityHeadersMiddleware,
    RequestResponseLoggingMiddleware,
    RequestValidationMiddleware,
)
from app.middleware.auth_middleware import EXCLUDED_AUTH_PATHS

# Import dependencies for injection
from app.core.redis import get_redis
from app.core.database import get_db
from app.core.config import settings, get_cors_origins, get_cors_methods, get_cors_headers

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown events."""
    # Startup
    if settings.auth_rate_limit_enabled:
        redis_client = await get_redis()
        await FastAPILimiter.init(redis_client)
        logger.info("Rate limiter initialized with Redis backend")

    # Start background token cleanup task
    cleanup_task = asyncio.create_task(schedule_token_cleanup())
    logger.info("Started background token cleanup task")

    yield

    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    logger.info("Token cleanup task stopped")


async def schedule_token_cleanup():
    """
    Background task to periodically clean up expired tokens and perform maintenance.

    Runs every 24 hours.
    """
    from app.core.token import TokenRotation

    while True:
        try:
            # Wait 24 hours between cleanups
            await asyncio.sleep(24 * 60 * 60)  # 24 hours in seconds

            logger.info("Running scheduled token cleanup and maintenance...")

            # Create database session and clean up tokens
            db = next(get_db())
            try:
                # Enhanced token cleanup
                cleanup_stats = await TokenRotation.cleanup_expired_tokens(db, days_old=30)
                total_cleaned = sum(cleanup_stats.values())
                if total_cleaned > 0:
                    logger.info(f"Scheduled cleanup completed: {cleanup_stats}")
                else:
                    logger.debug("Scheduled cleanup: no expired tokens to remove")
            finally:
                db.close()

        except Exception as e:
            logger.error(f"Error in scheduled token cleanup: {e}")
            # Continue running despite errors

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Python Authentication & Authorization Server",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan,
)

# Configure OpenAPI security scheme for Bearer token authentication in docs
def custom_openapi():
    """Custom OpenAPI schema generator with Bearer token security."""
    if app.openapi_schema:
        return app.openapi_schema

    # Get the original openapi method (avoid recursion)
    original_openapi = FastAPI.openapi
    openapi_schema = original_openapi(app)

    # Ensure components exist
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}

    # Add security scheme for Bearer tokens
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT Authorization header using the Bearer scheme. Enter your token in the text input below."
        }
    }

    # Define paths that don't require authentication (from AuthMiddleware exclude_paths)
    # Include additional paths not in the middleware's exclude list
    exclude_paths = set(EXCLUDED_AUTH_PATHS + [
        "/",  # Root endpoint
    ])

    # Add security requirements to paths that require authentication
    if "paths" in openapi_schema:
        for path, methods in openapi_schema["paths"].items():
            # Skip if path is in exclude list
            if path in exclude_paths:
                continue

            # Add security requirement to each method in this path
            for method, operation in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    if "security" not in operation:
                        operation["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

# Override the default openapi method
app.openapi = custom_openapi

# Add CORS middleware
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=settings.cors_credentials,
        allow_methods=get_cors_methods(),
        allow_headers=get_cors_headers(),
    )

# Add HTTPS redirect middleware for production
if settings.app_env == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
    logger.info("HTTPS redirect middleware enabled (production mode - all HTTP redirected to HTTPS)")

# Add TrustedHost middleware for production
if settings.app_env == "production":
    trusted_hosts = (
        settings.trusted_hosts.split(",") if hasattr(settings, "trusted_hosts") and settings.trusted_hosts else ["*"]
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
    logger.info(f"Trusted host middleware enabled with hosts: {trusted_hosts}")

# Add request validation middleware
app.add_middleware(RequestValidationMiddleware)
logger.info("Request validation middleware enabled")

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)
logger.info("Security headers middleware enabled")

# Add request/response logging middleware
app.add_middleware(
    RequestResponseLoggingMiddleware,
    log_request_body=settings.debug,
    log_response_body=False,
    enable_logging=settings.debug or settings.app_env in ["development", "staging"],
)
if settings.debug or settings.app_env in ["development", "staging"]:
    logger.info("Request/response logging middleware enabled (with logging)")
else:
    logger.info("Request timing middleware enabled (logging disabled)")

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.debug else ["localhost", "127.0.0.1"],
)

# Add authentication middleware with injected dependencies
if settings.auth_middleware_enabled:
    app.add_middleware(
        AuthMiddleware,
        redis_getter=get_redis,
        db_getter=get_db,
    )
    logger.info("Authentication middleware enabled with injected dependencies")

# OAuth2 exception handler
@app.exception_handler(OAuth2Error)
async def oauth2_exception_handler(request: Request, exc: OAuth2Error):
    """Handle OAuth2 errors according to RFC 6749."""
    from app.api.v1.oauth import create_oauth2_error_response
    return create_oauth2_error_response(exc)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error" if not settings.debug else str(exc), "type": "internal_error"},
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "description": "Python Authentication & Authorization Server",
        "docs": "/docs" if settings.debug else None,
        "health": "/health",
    }

# Include API routers
from app.routers import include_routers

include_routers(app)

# Mount static files for frontend (OAuth demo UI)
# Get the path to the frontend directory
frontend_dir = Path(__file__).parent.parent / "frontend"

# Only mount if frontend directory exists
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir), html=True), name="static")
    logger.info(f"Static files mounted at /static from {frontend_dir}")
    
    # Serve index.html at /oauth-demo
    @app.get("/oauth-demo")
    async def oauth_demo_index():
        """Serve the OAuth demo frontend."""
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"error": "OAuth demo frontend not found"}
    
    # Serve login.html at /oauth-demo/login
    @app.get("/oauth-demo/login")
    async def oauth_demo_login():
        """Serve the OAuth demo login page."""
        login_file = frontend_dir / "login.html"
        if login_file.exists():
            return FileResponse(login_file)
        return {"error": "OAuth demo login page not found"}
    
    # Serve callback.html at /oauth-demo/callback
    @app.get("/oauth-demo/callback")
    async def oauth_demo_callback():
        """Serve the OAuth demo callback page."""
        callback_file = frontend_dir / "callback.html"
        if callback_file.exists():
            return FileResponse(callback_file)
        return {"error": "OAuth demo callback page not found"}
else:
    logger.warning(f"Frontend directory not found at {frontend_dir}, static files not mounted")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower(),
    )