"""
Main FastAPI application entry point.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from contextlib import asynccontextmanager
import time
import logging

# Import custom middleware
from app.middleware import AuthMiddleware, OptionalAuthMiddleware

from app.core.config import settings, get_cors_origins, get_cors_methods, get_cors_headers
from app.core.redis import get_redis

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
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

    yield

    # Shutdown (cleanup if needed)
    pass

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

# Add CORS middleware
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=settings.cors_credentials,
        allow_methods=get_cors_methods(),
        allow_headers=get_cors_headers(),
    ) 

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.debug else ["localhost", "127.0.0.1"]
)

# Add authentication middleware (must come before other middleware that might need auth)
if settings.auth_middleware_enabled:
    app.add_middleware(AuthMiddleware)
    logger.info("Authentication middleware enabled")

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error" if not settings.debug else str(exc),
            "type": "internal_error"
        }
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env
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
        "health": "/health"
    }

# Include API routers
from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router

app.include_router(health_router, prefix="/api/v1", tags=["health"])
app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])

# TODO: Add more routers as we implement them
# from app.api.v1.users import router as users_router
# from app.api.v1.oauth import router as oauth_router

# app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
# app.include_router(oauth_router, prefix="/api/v1/oauth", tags=["oauth"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower()
    )
