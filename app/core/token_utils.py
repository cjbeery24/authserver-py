"""
JWT token utility functions for extraction and validation.

This module provides reusable utilities for handling JWT tokens
across middleware and endpoints, eliminating code duplication.

Uses dependency injection for better testability and flexibility.
"""

import logging
from typing import Optional, Dict, Any, Callable
from fastapi import Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.token import TokenManager
from app.models.user import User

logger = logging.getLogger(__name__)

# Security scheme for extracting tokens
security = HTTPBearer(auto_error=False)


class TokenUtils:
    """
    Utility class for JWT token operations.
    
    Provides centralized token extraction and validation logic
    that can be reused across middleware and endpoints.
    """
    
    @staticmethod
    async def extract_token(request: Request) -> Optional[str]:
        """
        Extract JWT token from request.
        
        Supports multiple token sources (in order of precedence):
        1. Authorization header (Bearer token) - recommended
        2. Query parameter (?token=...) - for special cases
        3. Cookie (auth_token) - for browser-based apps
        
        Args:
            request: FastAPI request object
            
        Returns:
            Token string if found, None otherwise
            
        Example:
            token = await TokenUtils.extract_token(request)
            if token:
                user_context = await TokenUtils.validate_and_get_user(request, token)
        """
        # Try Authorization header first (most secure)
        credentials: Optional[HTTPAuthorizationCredentials] = await security(request)
        if credentials:
            return credentials.credentials
        
        # Try query parameter (less secure, use sparingly)
        token = request.query_params.get("token")
        if token:
            logger.debug(f"Token extracted from query parameter for {request.url.path}")
            return token
        
        # Try cookie (for browser-based authentication)
        token = request.cookies.get("auth_token")
        if token:
            logger.debug(f"Token extracted from cookie for {request.url.path}")
            return token
        
        return None
    
    @staticmethod
    async def validate_and_get_user(
        request: Request, 
        token: str,
        redis_client,
        db_session: Session,
        token_type: str = "access"
    ) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and return user context.
        
        This method uses dependency injection for better testability.
        
        This method:
        1. Validates the token signature and expiration
        2. Checks if the token is blacklisted
        3. Fetches the user from the database
        4. Verifies the user is active
        
        Args:
            request: FastAPI request object
            token: JWT token string
            redis_client: Redis client instance (injected)
            db_session: SQLAlchemy database session (injected)
            token_type: Token type ("access" or "refresh")
            
        Returns:
            Dictionary containing user and token_data, or None if invalid
            {
                "user": User object,
                "token_data": {
                    "user_id": int,
                    "username": str,
                    "email": str,
                    "token_type": str,
                    "issued_at": int,
                    "expires_at": int,
                    "jti": str
                }
            }
            
        Example:
            from app.core.redis import get_redis
            from app.core.database import get_db
            
            redis_client = await get_redis()
            db = next(get_db())
            user_context = await TokenUtils.validate_and_get_user(
                request, token, redis_client, db
            )
            if user_context:
                user = user_context["user"]
                token_data = user_context["token_data"]
        """
        try:
            # Validate token signature, expiration, and check blacklist
            payload = await TokenManager.verify_token(token, token_type, redis_client)
            if not payload:
                logger.warning(
                    f"Token validation failed | "
                    f"path={request.url.path} | "
                    f"client={request.client.host if request.client else 'unknown'}"
                )
                return None
            
            # Extract user ID from token
            user_id = int(payload.get("sub"))
            
            # Fetch user from database and verify they're active
            user = db_session.query(User).filter(
                User.id == user_id,
                User.is_active == True
            ).first()
            
            if not user:
                logger.warning(
                    f"User not found or inactive | "
                    f"user_id={user_id} | "
                    f"path={request.url.path}"
                )
                return None
            
            # Build user context
            user_context = {
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
            
            logger.debug(
                f"Token validated successfully | "
                f"user_id={user_id} | "
                f"username={user.username}"
            )
            
            return user_context
            
        except ValueError as e:
            logger.warning(f"Invalid token payload: {str(e)}")
            return None
        except Exception as e:
            logger.error(
                f"Error validating token: {str(e)} | "
                f"path={request.url.path}",
                exc_info=True
            )
            return None
    
    @staticmethod
    async def extract_and_validate(
        request: Request,
        redis_client,
        db_session: Session,
        token_type: Optional[str] = None,
        required: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Convenience method that combines token extraction and validation.

        Uses dependency injection for Redis and database connections.

        Args:
            request: FastAPI request object
            redis_client: Redis client instance (injected)
            db_session: SQLAlchemy database session (injected)
            token_type: Token type ("access", "refresh", or None to auto-detect)
            required: If True, logs when token missing/invalid
                     If False, silently returns None

        Returns:
            User context dict or None

        Example:
            from app.core.redis import get_redis
            from app.core.database import get_db

            # For required authentication (auto-detects token type)
            redis_client = await get_redis()
            db = next(get_db())
            user_context = await TokenUtils.extract_and_validate(
                request, redis_client, db
            )
            if not user_context:
                raise HTTPException(401, "Authentication required")

            # For optional authentication
            user_context = await TokenUtils.extract_and_validate(
                request, redis_client, db, required=False
            )
            # user_context might be None, that's OK
        """
        # Extract token
        token = await TokenUtils.extract_token(request)

        if not token:
            if required:
                logger.debug(f"No token found in request to {request.url.path}")
            return None

        # Auto-detect token type if not specified
        if token_type is None:
            token_type = TokenUtils._get_token_type(token)

        # Validate token and get user (with injected dependencies)
        user_context = await TokenUtils.validate_and_get_user(
            request, token, redis_client, db_session, token_type
        )

        if not user_context and required:
            logger.debug(f"Token validation failed for {request.url.path}")

        return user_context

    @staticmethod
    def _get_token_type(token: str) -> str:
        """
        Extract token type from JWT payload without verification.

        Args:
            token: JWT token string

        Returns:
            Token type ("access" or "refresh"), defaults to "access" if unknown
        """
        try:
            # Decode without verification to check the type field
            payload = TokenManager.decode_token(token)
            if payload and "type" in payload:
                token_type = payload["type"]
                if token_type in ["access", "refresh"]:
                    return token_type
        except Exception:
            pass

        # Default to access token if type cannot be determined
        return "access"

    @staticmethod
    def get_token_from_header(authorization: str) -> Optional[str]:
        """
        Extract token from Authorization header string.
        
        Args:
            authorization: Authorization header value (e.g., "Bearer abc123")
            
        Returns:
            Token string or None
            
        Example:
            auth_header = request.headers.get("authorization")
            token = TokenUtils.get_token_from_header(auth_header)
        """
        if not authorization:
            return None
        
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        
        return parts[1]


class TokenExtractionError(Exception):
    """Raised when token extraction fails."""
    pass


class TokenValidationError(Exception):
    """Raised when token validation fails."""
    
    def __init__(self, message: str, reason: str = None):
        self.message = message
        self.reason = reason
        super().__init__(self.message)

