"""
Request validation and sanitization middleware for enhanced security.
"""

import logging
import re
import html
from typing import Any, Dict, Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import json

from app.core.config import settings

logger = logging.getLogger(__name__)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Request validation and sanitization middleware.
    
    Features:
    - Input sanitization (XSS prevention)
    - SQL injection prevention
    - Path traversal prevention
    - Request size limits
    - Content type validation
    - Character encoding validation
    """
    
    def __init__(
        self,
        app,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB
        enable_xss_protection: bool = True,
        enable_sql_injection_check: bool = True,
        enable_path_traversal_check: bool = True,
        allowed_content_types: list = None
    ):
        super().__init__(app)
        self.max_request_size = max_request_size
        self.enable_xss_protection = enable_xss_protection
        self.enable_sql_injection_check = enable_sql_injection_check
        self.enable_path_traversal_check = enable_path_traversal_check
        self.allowed_content_types = allowed_content_types or [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain"
        ]
        
        # Compile regex patterns for performance
        self.sql_injection_patterns = [
            re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)", re.IGNORECASE),
            re.compile(r"(;|\-\-|\/\*|\*\/|xp_|sp_)", re.IGNORECASE),
            re.compile(r"(\bOR\b.*=.*|1=1|' OR ')", re.IGNORECASE),
            re.compile(r"(UNION.*SELECT)", re.IGNORECASE)
        ]
        
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),  # Event handlers like onclick=
            re.compile(r"<iframe", re.IGNORECASE),
            re.compile(r"<object", re.IGNORECASE),
            re.compile(r"<embed", re.IGNORECASE)
        ]
        
        self.path_traversal_patterns = [
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\"),
            re.compile(r"%2e%2e/", re.IGNORECASE),
            re.compile(r"%2e%2e\\", re.IGNORECASE)
        ]
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Validate and sanitize incoming requests."""
        
        # Skip validation for certain endpoints (health checks, docs)
        if self._should_skip_validation(request.url.path):
            return await call_next(request)
        
        # Validate content type
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
        
        # Check request size
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
        
        # Validate URL path
        if self.enable_path_traversal_check:
            if self._contains_path_traversal(request.url.path):
                logger.error(
                    f"Path traversal attempt detected | "
                    f"path={request.url.path} | "
                    f"client={request.client.host if request.client else 'unknown'}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid request path"
                )
        
        # Validate query parameters
        if request.url.query:
            if self._contains_malicious_content(request.url.query):
                logger.warning(
                    f"Malicious query parameters detected | "
                    f"query={request.url.query[:100]} | "
                    f"path={request.url.path}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid query parameters"
                )
        
        # Validate headers
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
    
    def _contains_path_traversal(self, path: str) -> bool:
        """Check if path contains path traversal attempts."""
        return any(
            pattern.search(path)
            for pattern in self.path_traversal_patterns
        )
    
    def _contains_sql_injection(self, value: str) -> bool:
        """Check if value contains SQL injection attempts."""
        if not self.enable_sql_injection_check:
            return False
        
        return any(
            pattern.search(value)
            for pattern in self.sql_injection_patterns
        )
    
    def _contains_xss(self, value: str) -> bool:
        """Check if value contains XSS attempts."""
        if not self.enable_xss_protection:
            return False
        
        return any(
            pattern.search(value)
            for pattern in self.xss_patterns
        )
    
    def _contains_malicious_content(self, value: str) -> bool:
        """Check if value contains any malicious content."""
        return (
            self._contains_sql_injection(value) or
            self._contains_xss(value) or
            self._contains_path_traversal(value)
        )
    
    def _validate_headers(self, request: Request) -> None:
        """Validate request headers."""
        # Check for excessively long headers
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
        
        # Validate User-Agent (should exist for most legitimate requests)
        if not request.headers.get("user-agent") and request.url.path not in ["/health", "/metrics"]:
            logger.debug(
                f"Request without User-Agent | "
                f"path={request.url.path} | "
                f"client={request.client.host if request.client else 'unknown'}"
            )


class InputSanitizer:
    """
    Utility class for sanitizing user inputs.
    """
    
    @staticmethod
    def sanitize_string(value: str, allow_html: bool = False) -> str:
        """
        Sanitize a string value.
        
        Args:
            value: The string to sanitize
            allow_html: If False, HTML entities will be escaped
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value
        
        # Remove null bytes
        value = value.replace("\x00", "")
        
        # Escape HTML entities if not allowed
        if not allow_html:
            value = html.escape(value)
        
        # Remove control characters except newlines and tabs
        value = "".join(
            char for char in value
            if char.isprintable() or char in ["\n", "\t", "\r"]
        )
        
        return value.strip()
    
    @staticmethod
    def sanitize_dict(data: Dict[str, Any], allow_html: bool = False) -> Dict[str, Any]:
        """
        Recursively sanitize all string values in a dictionary.
        
        Args:
            data: Dictionary to sanitize
            allow_html: If False, HTML entities will be escaped
            
        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = InputSanitizer.sanitize_string(value, allow_html)
            elif isinstance(value, dict):
                sanitized[key] = InputSanitizer.sanitize_dict(value, allow_html)
            elif isinstance(value, list):
                sanitized[key] = [
                    InputSanitizer.sanitize_string(item, allow_html) if isinstance(item, str)
                    else InputSanitizer.sanitize_dict(item, allow_html) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if valid, False otherwise
        """
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        return bool(email_pattern.match(email))
    
    @staticmethod
    def validate_username(username: str, min_length: int = 3, max_length: int = 50) -> bool:
        """
        Validate username format.
        
        Args:
            username: Username to validate
            min_length: Minimum length
            max_length: Maximum length
            
        Returns:
            True if valid, False otherwise
        """
        if not username or len(username) < min_length or len(username) > max_length:
            return False
        
        # Allow alphanumeric, underscores, and hyphens
        username_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
        return bool(username_pattern.match(username))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename to prevent directory traversal and other attacks.
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Sanitized filename
        """
        # Remove path components
        filename = filename.split("/")[-1].split("\\")[-1]
        
        # Remove dangerous characters
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Remove leading/trailing dots and spaces
        filename = filename.strip(". ")
        
        # Limit length
        max_filename_length = 255
        if len(filename) > max_filename_length:
            name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
            filename = name[:max_filename_length - len(ext) - 1] + "." + ext if ext else name[:max_filename_length]
        
        return filename
    
    @staticmethod
    def sanitize_url(url: str, allowed_schemes: list = None) -> Optional[str]:
        """
        Sanitize and validate a URL.
        
        Args:
            url: URL to sanitize
            allowed_schemes: List of allowed URL schemes (default: http, https)
            
        Returns:
            Sanitized URL or None if invalid
        """
        if not url:
            return None
        
        allowed_schemes = allowed_schemes or ["http", "https"]
        
        # Basic URL validation
        url_pattern = re.compile(
            r'^(https?|ftp)://'  # Scheme
            r'([a-zA-Z0-9.-]+)'  # Domain
            r'(:[0-9]+)?'  # Optional port
            r'(/.*)?$',  # Optional path
            re.IGNORECASE
        )
        
        if not url_pattern.match(url):
            return None
        
        # Check scheme
        scheme = url.split("://")[0].lower()
        if scheme not in allowed_schemes:
            return None
        
        return url
    
    @staticmethod
    def strip_dangerous_characters(value: str) -> str:
        """
        Remove potentially dangerous characters from input.
        
        Args:
            value: String to clean
            
        Returns:
            Cleaned string
        """
        # Remove null bytes
        value = value.replace("\x00", "")
        
        # Remove other dangerous control characters
        dangerous_chars = [
            "\x08",  # Backspace
            "\x1b",  # Escape
            "\x7f",  # Delete
        ]
        
        for char in dangerous_chars:
            value = value.replace(char, "")
        
        return value


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF (Cross-Site Request Forgery) protection middleware.
    
    Note: For API-only applications using JWT tokens, CSRF protection
    is less critical but still recommended for state-changing operations.
    """
    
    def __init__(self, app, exempt_paths: list = None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Check CSRF protection for state-changing requests."""
        
        # Skip CSRF check for safe methods
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return await call_next(request)
        
        # Skip for exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        # For Bearer token authentication, verify Origin/Referer header
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            # Check Origin or Referer header
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            
            if not origin and not referer:
                logger.debug(
                    f"CSRF check: No Origin/Referer header | "
                    f"path={request.url.path} | "
                    f"method={request.method}"
                )
        
        # Process request
        response = await call_next(request)
        return response

