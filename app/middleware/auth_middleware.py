"""
Authentication middleware for JWT token validation and user context management.

Uses dependency injection for Redis and database connections to improve
testability and reduce coupling.
"""

import logging
from typing import Optional, Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings
from app.core.token_utils import TokenUtils
from app.models.user import User

logger = logging.getLogger(__name__)

# Define paths that don't require authentication
EXCLUDED_AUTH_PATHS = [
    "/health",  # Root health endpoint
    "/api/v1/health",  # API health endpoint
    "/api/v1/health/detailed",
    "/api/v1/health/ready",
    "/api/v1/health/live",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/register",
    "/api/v1/auth/token",
    "/api/v1/auth/token/mfa",
    "/api/v1/auth/password-reset/request",
    "/api/v1/auth/password-reset/confirm",
    "/oauth/token",
    "/oauth/.well-known/openid-configuration",
    "/oauth/.well-known/jwks.json",
    "/oauth/authorize",  # OAuth authorization endpoint
    "/oauth/introspect",  # Token introspection
    "/oauth/revoke",  # Token revocation
]


class AuthMiddleware(BaseHTTPMiddleware):
    """
    JWT Authentication middleware for FastAPI.

    Features:
    - Automatic JWT token validation
    - Token blacklist checking
    - User context management
    - Dependency injection for testability
    - Configurable protected paths
    """

    def __init__(
        self,
        app,
        exclude_paths: Optional[list] = None,
        redis_getter: Callable = None,
        db_getter: Callable = None,
    ):
        """
        Initialize AuthMiddleware with dependency injection.

        Args:
            app: FastAPI application
            exclude_paths: Paths to skip authentication
            redis_getter: Callable that returns Redis client
            db_getter: Callable that returns database session
        """
        super().__init__(app)
        self.exclude_paths = exclude_paths or EXCLUDED_AUTH_PATHS
        if redis_getter is None or db_getter is None:
            raise ValueError("redis_getter and db_getter must be provided")
        self.redis_getter = redis_getter
        self.db_getter = db_getter

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process each request through authentication middleware.

        Uses dependency injection for Redis and database connections.
        """
        logger.debug(f"AuthMiddleware processing: {request.url.path}")

        # Skip authentication for excluded paths
        if self._should_skip_auth(request.url.path):
            logger.debug(f"Skipping auth for excluded path: {request.url.path}")
            return await call_next(request)

        # Get dependencies
        redis_client = await self.redis_getter()
        db_session = next(self.db_getter())

        try:
            # Extract and validate token using shared utility with injected deps
            user_context = await TokenUtils.extract_and_validate(
                request, redis_client, db_session, required=True
            )
            logger.debug(f"User context: {user_context}")

            if not user_context:
                return await self._unauthorized_response("Missing or invalid authentication token")

            # Add user context to request state
            request.state.user = user_context["user"]
            request.state.token_data = user_context["token_data"]

            # Store raw token for blacklisting
            raw_token = await TokenUtils.extract_token(request)
            request.state.raw_token = raw_token

            # Process the request
            response = await call_next(request)

            return response

        finally:
            # Ensure database session is closed
            db_session.close()

    def _should_skip_auth(self, path: str) -> bool:
        """Check if the path should skip authentication."""
        if path in self.exclude_paths or path == "/":
            return True
        return False

    async def _unauthorized_response(self, message: str = "Authentication required") -> JSONResponse:
        """Return standardized unauthorized response."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": message, "type": "authentication_error"},
            headers={"WWW-Authenticate": "Bearer"},
        )


class OptionalAuthMiddleware(BaseHTTPMiddleware):
    """
    Optional authentication middleware.

    Adds user context if token is present and valid,
    but doesn't block requests without authentication.
    
    Uses dependency injection for testability.
    """

    def __init__(
        self, 
        app,
        redis_getter: Optional[Callable] = None,
        db_getter: Optional[Callable] = None
    ):
        """
        Initialize OptionalAuthMiddleware with dependency injection.
        
        Args:
            app: FastAPI application
            redis_getter: Callable that returns Redis client (for testing)
            db_getter: Callable that returns database session (for testing)
        """
        super().__init__(app)
        
        # Dependency injection for testability
        if redis_getter is None:
            from app.core.redis import get_redis
            self.redis_getter = get_redis
        else:
            self.redis_getter = redis_getter
        
        if db_getter is None:
            from app.core.database import get_db
            self.db_getter = get_db
        else:
            self.db_getter = db_getter

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request with optional authentication.
        
        Uses dependency injection for Redis and database connections.
        """
        db_session = None
        try:
            # Get dependencies (allows for mocking in tests)
            redis_client = await self.redis_getter()
            db_session = next(self.db_getter())
            
            # Try to extract and validate token using shared utility
            user_context = await TokenUtils.extract_and_validate(
                request,
                redis_client,
                db_session,
                required=False
            )
            
            if user_context:
                request.state.user = user_context["user"]
                request.state.token_data = user_context["token_data"]
                
                # Store raw token if available
                raw_token = await TokenUtils.extract_token(request)
                if raw_token:
                    request.state.raw_token = raw_token
                    
        except Exception as e:
            logger.debug(f"Optional auth failed: {str(e)}")
            # Don't fail the request for optional auth
        finally:
            # Ensure database session is closed
            if db_session:
                db_session.close()

        return await call_next(request)


# Utility functions for route protection
def require_auth():
    """
    Dependency function for requiring authentication on specific routes.
    Use with Depends(require_auth) in route definitions.
    """
    def dependency(request: Request):
        if not hasattr(request.state, 'user') or not request.state.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return request.state.user
    return dependency


def get_current_user(request: Request) -> Optional[User]:
    """
    Get current authenticated user from request state.
    Returns None if not authenticated.
    """
    return getattr(request.state, 'user', None)


def get_current_user_or_401(request: Request) -> User:
    """
    Get current authenticated user or raise 401 error.
    """
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


def get_raw_token(request: Request) -> Optional[str]:
    """
    Get the raw JWT token from the request state.

    Returns None if not authenticated.
    """
    return getattr(request.state, 'raw_token', None)


def get_raw_token_or_401(request: Request) -> str:
    """
    Get the raw JWT token or raise 401 error.
    """
    token = get_raw_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return token
