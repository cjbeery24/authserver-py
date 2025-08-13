"""
Dependencies for FastAPI dependency injection.
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, get_async_db
from app.core.redis import get_redis
from app.core.security import verify_token
from app.core.config import settings

# Security scheme
security = HTTPBearer(auto_error=False)

# Database dependencies
def get_database() -> Generator[Session, None, None]:
    """Get database session."""
    return get_db()

async def get_async_database() -> Generator[AsyncSession, None, None]:
    """Get async database session."""
    async for session in get_async_db():
        yield session

# Redis dependency
async def get_redis_client():
    """Get Redis client."""
    return await get_redis()

# Authentication dependencies
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_database)
) -> Optional[dict]:
    """Get current authenticated user from JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_token(token, "access")
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # TODO: Fetch user from database using payload["sub"]
    # user = get_user_by_id(db, payload["sub"])
    # if not user:
    #     raise HTTPException(status_code=404, detail="User not found")
    
    return payload

async def get_current_active_user(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Get current active user."""
    # TODO: Check if user is active
    # if not current_user.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_database)
) -> Optional[dict]:
    """Get current user if authenticated, otherwise None."""
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        payload = verify_token(token, "access")
        if payload:
            # TODO: Fetch user from database
            return payload
    except Exception:
        pass
    
    return None

# Rate limiting dependency
async def check_rate_limit(
    request: Request,
    action: str = "default",
    limit: int = None,
    window: str = "minute"
):
    """Check rate limit for the current request."""
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

# Permission checking dependency
async def require_permission(
    permission: str,
    current_user: dict = Depends(get_current_active_user)
):
    """Check if current user has required permission."""
    # TODO: Implement permission checking logic
    # user_permissions = get_user_permissions(current_user["id"])
    # if permission not in user_permissions:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Insufficient permissions"
    #     )
    pass

# Admin user dependency
async def require_admin(
    current_user: dict = Depends(get_current_active_user)
):
    """Check if current user is an admin."""
    # TODO: Implement admin role checking
    # if not current_user.is_admin:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Admin access required"
    #     )
    pass

# Debug mode dependency
def require_debug_mode():
    """Check if debug mode is enabled."""
    if not settings.debug:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found"
        )
    return True
