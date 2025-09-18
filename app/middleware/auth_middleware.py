"""
Authentication middleware for JWT token validation and user context management.
"""

import logging
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings
from app.core.security import TokenManager, TokenBlacklist
from app.core.redis import get_redis
from app.models.user import User
from app.core.database import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Security scheme for extracting tokens
security = HTTPBearer(auto_error=False)


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

        # Extract and validate token
        token_data = await self._extract_token(request)
        if not token_data:
            return await self._unauthorized_response("Missing or invalid authentication token")

        # Validate token and get user context
        user_context = await self._validate_token_and_get_user(request, token_data)
        if not user_context:
            return await self._unauthorized_response("Invalid or expired token")

        # Add user context to request state
        request.state.user = user_context["user"]
        request.state.token_data = user_context["token_data"]
        request.state.raw_token = token_data  # Store raw token for blacklisting

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

    async def _extract_token(self, request: Request) -> Optional[str]:
        """
        Extract JWT token from request.

        Supports:
        - Authorization header (Bearer token)
        - Query parameter (?token=...)
        - Cookie (auth_token)
        """
        # Try Authorization header first
        credentials: Optional[HTTPAuthorizationCredentials] = await security(request)
        if credentials:
            return credentials.credentials

        # Try query parameter
        token = request.query_params.get("token")
        if token:
            return token

        # Try cookie
        token = request.cookies.get("auth_token")
        if token:
            return token

        return None

    async def _validate_token_and_get_user(self, request: Request, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and return user context.
        """
        try:
            # Get Redis client for token validation
            redis_client = await get_redis()

            # Validate token
            payload = await TokenManager.verify_token(token, "access", redis_client)
            if not payload:
                logger.warning(f"Token validation failed for request to {request.url.path}")
                return None

            # Get database session
            db = next(get_db())

            # Get user from database
            user_id = int(payload.get("sub"))
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True
            ).first()

            if not user:
                logger.warning(f"User {user_id} not found or inactive")
                return None

            # Return user context
            return {
                "user": user,
                "token_data": {
                    "user_id": user_id,
                    "username": payload.get("username"),
                    "email": payload.get("email"),
                    "token_type": payload.get("type"),
                    "issued_at": payload.get("iat"),
                    "expires_at": payload.get("exp"),
                    "jti": payload.get("jti")
                }
            }

        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return None

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
            # Try to extract and validate token
            token = await self._extract_token(request)
            if token:
                user_context = await self._validate_token_and_get_user(request, token)
                if user_context:
                    request.state.user = user_context["user"]
                    request.state.token_data = user_context["token_data"]
        except Exception as e:
            logger.debug(f"Optional auth failed: {str(e)}")
            # Don't fail the request for optional auth

        return await call_next(request)

    async def _extract_token(self, request: Request) -> Optional[str]:
        """Extract token from request (same as AuthMiddleware)."""
        credentials: Optional[HTTPAuthorizationCredentials] = await security(request)
        if credentials:
            return credentials.credentials

        token = request.query_params.get("token")
        if token:
            return token

        token = request.cookies.get("auth_token")
        if token:
            return token

        return None

    async def _validate_token_and_get_user(self, request: Request, token: str) -> Optional[Dict[str, Any]]:
        """Validate token (same logic as AuthMiddleware)."""
        try:
            redis_client = await get_redis()
            payload = await TokenManager.verify_token(token, "access", redis_client)

            if not payload:
                return None

            db = next(get_db())
            user_id = int(payload.get("sub"))
            user = db.query(User).filter(
                User.id == user_id,
                User.is_active == True
            ).first()

            if not user:
                return None

            return {
                "user": user,
                "token_data": {
                    "user_id": user_id,
                    "username": payload.get("username"),
                    "email": payload.get("email"),
                    "token_type": payload.get("type"),
                    "issued_at": payload.get("iat"),
                    "expires_at": payload.get("exp"),
                    "jti": payload.get("jti")
                }
            }

        except Exception as e:
            logger.debug(f"Optional auth validation error: {str(e)}")
            return None


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
