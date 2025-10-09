"""
Request validation and sanitization middleware using industry-standard libraries.

This middleware provides:
- Input sanitization using bleach (industry standard)
- Request size and content-type validation
- Basic path traversal protection
- Pydantic-based validation (via FastAPI)

Note: SQL injection is prevented by SQLAlchemy's parameterized queries.
      XSS is handled by bleach and Content-Security-Policy headers.
"""

import logging
import re
from typing import Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import bleach
from markupsafe import escape

from app.core.config import settings

logger = logging.getLogger(__name__)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Request validation middleware using industry best practices.
    
    Features:
    - Request size limits (using Starlette built-ins where possible)
    - Content type validation
    - Path traversal prevention
    - Basic security checks
    
    Note: This middleware focuses on protocol-level validation.
    Application-level validation is handled by Pydantic models in endpoints.
    """
    
    def __init__(
        self,
        app,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB
        allowed_content_types: list = None
    ):
        super().__init__(app)
        self.max_request_size = max_request_size
        self.allowed_content_types = allowed_content_types or [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain"
        ]
        
        # Simple path traversal patterns (basic check only)
        self.path_traversal_patterns = [
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\"),
            re.compile(r"%2e%2e[/\\]", re.IGNORECASE)
        ]
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Validate incoming requests using industry best practices."""
        
        # Skip validation for health checks and docs
        if self._should_skip_validation(request.url.path):
            return await call_next(request)
        
        # Validate content type for state-changing requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if not self._is_valid_content_type(content_type):
                logger.warning(
                    f"Invalid content type: {content_type} | "
                    f"path={request.url.path} | "
                    f"client={request.client.host if request.client else 'unknown'}"
                )
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Unsupported media type"
                )
        
        # Check request size (basic DoS prevention)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            logger.warning(
                f"Request too large: {content_length} bytes | "
                f"max={self.max_request_size} | "
                f"path={request.url.path}"
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request body too large. Maximum size: {self.max_request_size} bytes"
            )
        
        # Basic path traversal check (simple patterns only)
        if self._contains_obvious_path_traversal(request.url.path):
            logger.error(
                f"Potential path traversal detected | "
                f"path={request.url.path} | "
                f"client={request.client.host if request.client else 'unknown'}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid request path"
            )
        
        # Validate header sizes (prevent header-based attacks)
        self._validate_headers(request)
        
        # Process request
        response = await call_next(request)
        return response
    
    def _should_skip_validation(self, path: str) -> bool:
        """Check if validation should be skipped for this path."""
        skip_paths = [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico"
        ]
        return any(path.startswith(skip_path) for skip_path in skip_paths)
    
    def _is_valid_content_type(self, content_type: str) -> bool:
        """Validate content type header."""
        if not content_type:
            return False
        
        # Extract base content type (before semicolon)
        base_type = content_type.split(";")[0].strip().lower()
        
        return any(
            allowed in base_type
            for allowed in self.allowed_content_types
        )
    
    def _contains_obvious_path_traversal(self, path: str) -> bool:
        """
        Check for obvious path traversal patterns.
        
        Note: This is a basic check. The OS and web server should also
        prevent path traversal. This is just an additional layer.
        """
        return any(
            pattern.search(path)
            for pattern in self.path_traversal_patterns
        )
    
    def _validate_headers(self, request: Request) -> None:
        """Validate request headers."""
        max_header_length = 8192
        for name, value in request.headers.items():
            if len(value) > max_header_length:
                logger.warning(
                    f"Excessively long header | "
                    f"header={name} | "
                    f"length={len(value)} | "
                    f"path={request.url.path}"
                )
                raise HTTPException(
                    status_code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
                    detail="Request header too large"
                )


class InputSanitizer:
    """
    Input sanitization utilities using industry-standard libraries.
    
    Uses:
    - bleach: Industry-standard HTML sanitization (Mozilla)
    - MarkupSafe: HTML escaping (part of Jinja2)
    - email-validator: Email validation (via Pydantic)
    """
    
    @staticmethod
    def sanitize_html(
        value: str,
        tags: list = None,
        attributes: dict = None,
        strip: bool = True
    ) -> str:
        """
        Sanitize HTML using bleach (industry standard).
        
        Args:
            value: HTML string to sanitize
            tags: Allowed HTML tags (default: none)
            attributes: Allowed attributes per tag (default: none)
            strip: If True, strip tags; if False, escape them
            
        Returns:
            Sanitized HTML string
        
        Example:
            # Strip all HTML
            sanitize_html("<script>alert('xss')</script>")  # Returns: "alert('xss')"
            
            # Allow specific tags
            sanitize_html("<p>Safe</p><script>Bad</script>", tags=['p'])  # Returns: "<p>Safe</p>Bad"
        """
        if not isinstance(value, str):
            return value
        
        # Default: strip all tags (safest)
        allowed_tags = tags or []
        allowed_attributes = attributes or {}
        
        return bleach.clean(
            value,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=strip
        )
    
    @staticmethod
    def escape_html(value: str) -> str:
        """
        Escape HTML entities using MarkupSafe (Jinja2 standard).
        
        This is safer than stripping for user-generated content that might
        contain legitimate angle brackets.
        
        Args:
            value: String to escape
            
        Returns:
            HTML-escaped string
        """
        if not isinstance(value, str):
            return value
        
        return str(escape(value))
    
    @staticmethod
    def sanitize_string(value: str, escape_html_chars: bool = True) -> str:
        """
        Sanitize a string for safe storage and display.
        
        Args:
            value: String to sanitize
            escape_html_chars: If True, escape HTML (recommended)
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value
        
        # Remove null bytes (can cause issues in databases)
        value = value.replace("\x00", "")
        
        # Remove other problematic control characters
        # Keep: \n (newline), \t (tab), \r (carriage return)
        value = "".join(
            char for char in value
            if char.isprintable() or char in ["\n", "\t", "\r"]
        )
        
        # Escape HTML if requested
        if escape_html_chars:
            value = InputSanitizer.escape_html(value)
        
        return value.strip()
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename to prevent directory traversal.
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Safe filename
        """
        # Remove path components
        filename = filename.split("/")[-1].split("\\")[-1]
        
        # Remove dangerous characters, keep alphanumeric, spaces, dots, hyphens, underscores
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Remove leading/trailing dots and spaces
        filename = filename.strip(". ")
        
        # Prevent hidden files
        if filename.startswith("."):
            filename = filename[1:]
        
        # Limit length
        max_filename_length = 255
        if len(filename) > max_filename_length:
            name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
            filename = name[:max_filename_length - len(ext) - 1] + "." + ext if ext else name[:max_filename_length]
        
        return filename or "unnamed"
    
    @staticmethod
    def sanitize_url(url: str, allowed_schemes: list = None) -> Optional[str]:
        """
        Validate and sanitize a URL.
        
        Note: For serious URL validation, consider using the 'validators' library.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed schemes (default: http, https)
            
        Returns:
            Sanitized URL or None if invalid
        """
        if not url:
            return None
        
        allowed_schemes = allowed_schemes or ["http", "https"]
        
        # Basic URL validation
        url_pattern = re.compile(
            r'^(https?|ftp)://'
            r'([a-zA-Z0-9.-]+)'
            r'(:[0-9]+)?'
            r'(/.*)?$',
            re.IGNORECASE
        )
        
        if not url_pattern.match(url):
            return None
        
        # Check scheme
        scheme = url.split("://")[0].lower()
        if scheme not in allowed_schemes:
            return None
        
        return url


class PydanticValidators:
    """
    Reusable Pydantic validators for common patterns.
    
    Use these in your Pydantic models:
    
    Example:
        from pydantic import BaseModel, field_validator
        
        class UserInput(BaseModel):
            username: str
            bio: str
            
            @field_validator('username')
            @classmethod
            def validate_username(cls, v):
                return PydanticValidators.username(v)
            
            @field_validator('bio')
            @classmethod
            def sanitize_bio(cls, v):
                return PydanticValidators.safe_html(v)
    """
    
    @staticmethod
    def username(value: str, min_length: int = 3, max_length: int = 50) -> str:
        """
        Validate username format.
        
        Rules:
        - Alphanumeric, underscores, hyphens only
        - 3-50 characters
        
        Raises:
            ValueError: If username is invalid
        """
        if not value or len(value) < min_length or len(value) > max_length:
            raise ValueError(f"Username must be between {min_length} and {max_length} characters")
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        
        return value.lower()  # Normalize to lowercase
    
    @staticmethod
    def safe_html(value: str, allow_tags: list = None) -> str:
        """
        Sanitize HTML input using bleach.
        
        Default: strips all HTML tags.
        
        Args:
            value: HTML to sanitize
            allow_tags: List of allowed tags (default: strip all)
        """
        return InputSanitizer.sanitize_html(value, tags=allow_tags or [])
    
    @staticmethod
    def safe_text(value: str) -> str:
        """
        Sanitize plain text (escapes HTML, removes control chars).
        """
        return InputSanitizer.sanitize_string(value, escape_html_chars=True)
    
    @staticmethod
    def url(value: str, allowed_schemes: list = None) -> str:
        """
        Validate and sanitize URL.
        
        Raises:
            ValueError: If URL is invalid
        """
        sanitized = InputSanitizer.sanitize_url(value, allowed_schemes)
        if not sanitized:
            raise ValueError("Invalid URL format")
        return sanitized


# Note: CSRF protection for JWT-based APIs
# 
# For APIs using Bearer tokens (JWT in Authorization header), CSRF protection
# is generally not needed because:
# 1. Tokens are not automatically sent by browsers (unlike cookies)
# 2. Attackers cannot access the Authorization header from another domain
# 3. SameSite cookies are not used
#
# However, if you use cookies for token storage, implement CSRF protection:
# - Use the 'starlette-csrf' package
# - Or implement Double Submit Cookie pattern
# - Or use Synchronizer Token pattern
#
# For now, we rely on:
# - Origin/Referer header validation (in security headers middleware)
# - Content-Security-Policy headers
# - CORS configuration
