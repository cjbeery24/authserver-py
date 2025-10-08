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
import asyncio
from datetime import datetime, timezone, timedelta

# Import custom middleware
from app.middleware import AuthMiddleware, OptionalAuthMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

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

    # Start background token cleanup task
    cleanup_task = asyncio.create_task(schedule_token_cleanup())
    logger.info("Started background token cleanup task")

    yield

    # Shutdown (cleanup if needed)
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
    from app.core.database import get_db_session
    from app.core.security import TokenRotation

    while True:
        try:
            # Wait 24 hours between cleanups
            await asyncio.sleep(24 * 60 * 60)  # 24 hours in seconds

            logger.info("Running scheduled token cleanup and maintenance...")

            # Create database session and clean up tokens
            db = next(get_db_session())
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

# Add CORS middleware
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=settings.cors_credentials,
        allow_methods=get_cors_methods(),
        allow_headers=get_cors_headers(),
    ) 

# Add security headers middleware (first to ensure all responses have security headers)
app.add_middleware(SecurityHeadersMiddleware)
logger.info("Security headers middleware enabled")

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
from app.api.v1.oauth import router as oauth_router
from app.api.v1.security import router as security_router
from app.api.v1.mfa import router as mfa_router
from app.api.v1.users import router as users_router

app.include_router(health_router, prefix="/api/v1", tags=["health"])
app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(oauth_router, prefix="/oauth", tags=["oauth"])
app.include_router(security_router, prefix="/api/v1/security", tags=["security"])
app.include_router(mfa_router, prefix="/api/v1/mfa", tags=["mfa"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower()
    )
