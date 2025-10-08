"""
Security headers middleware for enhanced token transmission security.
"""

import logging
from typing import Dict, Any
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from app.core.config import settings

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware to enhance token transmission security.
    
    Adds security headers to protect against various attacks and ensure
    secure token transmission over HTTPS.
    """
    
    def __init__(self, app, **kwargs):
        super().__init__(app)
        self.config = {
            # Strict Transport Security - Force HTTPS
            'hsts_max_age': kwargs.get('hsts_max_age', 31536000),  # 1 year
            'hsts_include_subdomains': kwargs.get('hsts_include_subdomains', True),
            'hsts_preload': kwargs.get('hsts_preload', True),
            
            # Content Security Policy
            'csp_default_src': kwargs.get('csp_default_src', "'self'"),
            'csp_script_src': kwargs.get('csp_script_src', "'self' 'unsafe-inline'"),
            'csp_style_src': kwargs.get('csp_style_src', "'self' 'unsafe-inline'"),
            'csp_img_src': kwargs.get('csp_img_src', "'self' data: https:"),
            'csp_connect_src': kwargs.get('csp_connect_src', "'self'"),
            
            # Other security headers
            'x_content_type_options': kwargs.get('x_content_type_options', 'nosniff'),
            'x_frame_options': kwargs.get('x_frame_options', 'DENY'),
            'x_xss_protection': kwargs.get('x_xss_protection', '1; mode=block'),
            'referrer_policy': kwargs.get('referrer_policy', 'strict-origin-when-cross-origin'),
            'permissions_policy': kwargs.get('permissions_policy', 'geolocation=(), microphone=(), camera=()'),
        }
    
    async def dispatch(self, request: Request, call_next) -> StarletteResponse:
        """Add security headers to all responses."""
        
        # Process the request
        response = await call_next(request)
        
        # Add security headers
        self._add_security_headers(request, response)
        
        # Add token-specific security headers for auth endpoints
        if self._is_auth_endpoint(request.url.path):
            self._add_token_security_headers(request, response)
        
        return response
    
    def _add_security_headers(self, request: Request, response: Response) -> None:
        """Add general security headers."""
        
        # HTTPS Strict Transport Security (only for HTTPS)
        if request.url.scheme == 'https' or settings.app_env == 'production':
            hsts_value = f"max-age={self.config['hsts_max_age']}"
            if self.config['hsts_include_subdomains']:
                hsts_value += "; includeSubDomains"
            if self.config['hsts_preload']:
                hsts_value += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_value
        
        # Content Security Policy
        csp_directives = [
            f"default-src {self.config['csp_default_src']}",
            f"script-src {self.config['csp_script_src']}",
            f"style-src {self.config['csp_style_src']}",
            f"img-src {self.config['csp_img_src']}",
            f"connect-src {self.config['csp_connect_src']}",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
        # X-Content-Type-Options
        response.headers["X-Content-Type-Options"] = self.config['x_content_type_options']
        
        # X-Frame-Options
        response.headers["X-Frame-Options"] = self.config['x_frame_options']
        
        # X-XSS-Protection
        response.headers["X-XSS-Protection"] = self.config['x_xss_protection']
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = self.config['referrer_policy']
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = self.config['permissions_policy']
        
        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Remove server information
        response.headers.pop("Server", None)
        
        # Add custom security header for API
        response.headers["X-API-Version"] = "v1"
        response.headers["X-Powered-By"] = "AuthServer"
    
    def _add_token_security_headers(self, request: Request, response: Response) -> None:
        """Add token-specific security headers for authentication endpoints."""
        
        # Cache Control for token endpoints
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
        # Prevent token caching
        response.headers["Surrogate-Control"] = "no-store"
        
        # CORS security for token endpoints
        if self._is_cors_preflight(request):
            response.headers["Access-Control-Max-Age"] = "86400"  # 24 hours
            response.headers["Vary"] = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        
        # Additional security for OAuth endpoints
        if "/oauth/" in request.url.path:
            response.headers["X-OAuth-Secure"] = "true"
            
        # JWKS endpoint specific headers
        if request.url.path.endswith("jwks.json"):
            response.headers["Cache-Control"] = "public, max-age=3600"  # Cache public keys for 1 hour
            response.headers["X-JWKS-Version"] = "1.0"
    
    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if the path is an authentication-related endpoint."""
        auth_paths = [
            "/api/v1/auth/",
            "/oauth/",
            "/api/v1/oauth/",
            "/.well-known/"
        ]
        return any(auth_path in path for auth_path in auth_paths)
    
    def _is_cors_preflight(self, request: Request) -> bool:
        """Check if this is a CORS preflight request."""
        return (
            request.method == "OPTIONS" and
            "Origin" in request.headers and
            "Access-Control-Request-Method" in request.headers
        )


class TokenTransmissionSecurity:
    """
    Utilities for secure token transmission.
    """
    
    @staticmethod
    def create_secure_cookie_attributes(
        secure: bool = True,
        http_only: bool = True,
        same_site: str = "strict",
        max_age: int = None
    ) -> Dict[str, Any]:
        """
        Create secure cookie attributes for token storage.
        
        Args:
            secure: Whether to set Secure flag (HTTPS only)
            http_only: Whether to set HttpOnly flag (no JavaScript access)
            same_site: SameSite policy ('strict', 'lax', 'none')
            max_age: Cookie expiration in seconds
            
        Returns:
            Dictionary of cookie attributes
        """
        attributes = {
            "secure": secure,
            "httponly": http_only,
            "samesite": same_site
        }
        
        if max_age:
            attributes["max_age"] = max_age
            
        return attributes
    
    @staticmethod
    def validate_token_transmission_security(request: Request) -> Dict[str, bool]:
        """
        Validate security aspects of token transmission.
        
        Returns:
            Dictionary of security validation results
        """
        return {
            "is_https": request.url.scheme == "https",
            "has_user_agent": bool(request.headers.get("User-Agent")),
            "has_origin": bool(request.headers.get("Origin")),
            "has_referer": bool(request.headers.get("Referer")),
            "is_secure_context": request.url.scheme == "https" and not _is_development_environment(),
            "content_type_valid": _is_valid_content_type(request.headers.get("Content-Type", "")),
        }
    
    @staticmethod
    def get_client_fingerprint(request: Request) -> str:
        """
        Generate a client fingerprint for token binding.
        
        Args:
            request: FastAPI request object
            
        Returns:
            SHA-256 hash of client characteristics
        """
        import hashlib
        
        # Collect client characteristics
        characteristics = [
            request.client.host if request.client else "",
            request.headers.get("User-Agent", ""),
            request.headers.get("Accept-Language", ""),
            request.headers.get("Accept-Encoding", ""),
            str(request.url.port or ""),
        ]
        
        # Create fingerprint
        fingerprint_data = "|".join(characteristics)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def _is_development_environment() -> bool:
    """Check if we're in a development environment."""
    return settings.app_env in ["development", "dev", "local"]


def _is_valid_content_type(content_type: str) -> bool:
    """Validate content type for token requests."""
    valid_types = [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data"
    ]
    return any(valid_type in content_type.lower() for valid_type in valid_types)

