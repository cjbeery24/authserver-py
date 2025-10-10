"""
Middleware package for authentication, security, and request processing.
"""

from .auth_middleware import (
    AuthMiddleware,
    OptionalAuthMiddleware,
    require_auth,
    get_current_user,
    get_current_user_or_401,
    get_raw_token,
    get_raw_token_or_401
)

from .security_headers import SecurityHeadersMiddleware
from .logging_middleware import RequestResponseLoggingMiddleware, StructuredLogger
from .validation_middleware import (
    RequestValidationMiddleware,
    InputSanitizer,
    PydanticValidators
)
from .https_redirect import HTTPSEnforcementMiddleware, SecureProxyHeadersMiddleware

__all__ = [
    # Authentication
    "AuthMiddleware",
    "OptionalAuthMiddleware",
    "require_auth",
    "get_current_user",
    "get_current_user_or_401",
    "get_raw_token",
    "get_raw_token_or_401",
    # Security
    "SecurityHeadersMiddleware",
    "HTTPSEnforcementMiddleware",
    "SecureProxyHeadersMiddleware",
    # Logging
    "RequestResponseLoggingMiddleware",
    "StructuredLogger",
    # Validation
    "RequestValidationMiddleware",
    "InputSanitizer",
    "PydanticValidators"
]
