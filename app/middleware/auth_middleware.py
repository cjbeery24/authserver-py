"""
Authentication middleware for JWT token validation and user context management.
"""

import logging
from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings
from app.core.token_utils import TokenUtils
from app.models.user import User

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    JWT Authentication middleware for FastAPI.

    Features:
    - Automatic JWT token validation
    - Token blacklist checking
    - User context management
    - Optional token refresh
    - Configurable protected paths
    """

    def __init__(self, app, exclude_paths: Optional[list] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/", "/health", "/docs", "/redoc", "/openapi.json",
            "/api/v1/auth/register",
            "/api/v1/auth/token",
            "/api/v1/auth/token/mfa",
            "/api/v1/auth/password-reset/request",
            "/api/v1/auth/password-reset/confirm",
        ]

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process each request through authentication middleware.
        """
        # Skip authentication for excluded paths
        if self._should_skip_auth(request.url.path):
            return await call_next(request)

        # Extract and validate token using shared utility
        user_context = await TokenUtils.extract_and_validate(request, required=True)
        
        if not user_context:
            return await self._unauthorized_response("Missing or invalid authentication token")

        # Add user context to request state
        request.state.user = user_context["user"]
        request.state.token_data = user_context["token_data"]
        
        # Store raw token for blacklisting (extract again since we need the string)
        raw_token = await TokenUtils.extract_token(request)
        request.state.raw_token = raw_token

        # Process the request
        response = await call_next(request)

        return response

    def _should_skip_auth(self, path: str) -> bool:
        """Check if the path should skip authentication."""
        # Exact match
        if path in self.exclude_paths:
            return True

        # Prefix match (for API versioning)
        for excluded_path in self.exclude_paths:
            if path.startswith(excluded_path):
                return True

        return False

    async def _unauthorized_response(self, message: str = "Authentication required") -> JSONResponse:
        """Return standardized unauthorized response."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "detail": message,
                "type": "authentication_error"
            },
            headers={"WWW-Authenticate": "Bearer"}
        )


class OptionalAuthMiddleware(BaseHTTPMiddleware):
    """
    Optional authentication middleware.

    Adds user context if token is present and valid,
    but doesn't block requests without authentication.
    """

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request with optional authentication."""
        try:
            # Try to extract and validate token using shared utility
            user_context = await TokenUtils.extract_and_validate(request, required=False)
            
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
