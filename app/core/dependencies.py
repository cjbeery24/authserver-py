"""
Dependencies for FastAPI dependency injection.

This module contains utility dependencies for FastAPI.

For authentication, use:
- app.middleware.auth_middleware.AuthMiddleware (automatic middleware)
- app.middleware.get_current_user_or_401() (manual dependency)

For database, use:
- app.core.database.get_db()

For Redis, use:
- app.core.redis.get_redis_dependency()
"""

from typing import Generator
from fastapi import HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, get_async_db
from app.core.redis import get_redis
from app.core.config import settings


# Database dependencies (kept for convenience)
def get_database() -> Generator[Session, None, None]:
    """Get database session."""
    return get_db()


async def get_async_database() -> Generator[AsyncSession, None, None]:
    """Get async database session."""
    async for session in get_async_db():
        yield session


# Redis dependency (kept for convenience)
async def get_redis_client():
    """Get Redis client."""
    return await get_redis()


# Debug mode dependency (kept as utility function)
def require_debug_mode():
    """Check if debug mode is enabled."""
    if not settings.debug:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found"
        )
    return True


# Rate limiting dependency (kept but consider using fastapi-limiter directly)
async def check_rate_limit(
    request: Request,
    action: str = "default",
    limit: int = None,
    window: str = "minute"
):
    """
    Check rate limit for the current request.
    
    NOTE: Consider using fastapi-limiter decorators directly instead.
    """
    if not settings.rate_limit_enabled:
        return
    
    if limit is None:
        if window == "minute":
            limit = settings.rate_limit_requests_per_minute
        elif window == "hour":
            limit = settings.rate_limit_requests_per_hour
        elif window == "day":
            limit = settings.rate_limit_requests_per_day
        else:
            limit = settings.rate_limit_requests_per_minute
    
    # Get client identifier (IP address or user ID)
    client_id = request.client.host
    
    # Import here to avoid circular imports
    from app.core.redis import increment_rate_limit, get_rate_limit
    
    current_count = await increment_rate_limit(
        f"rate_limit:{client_id}:{action}:{window}",
        expire=60 if window == "minute" else 3600 if window == "hour" else 86400
    )
    
    if current_count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per {window}.",
            headers={"Retry-After": "60"}
        )
