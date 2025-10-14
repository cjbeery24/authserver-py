"""
Centralized error catalog for consistent API error messages and codes.

This module provides standardized error messages, codes, and HTTP status codes
for the authentication server API to ensure consistency across all endpoints.
"""

from enum import Enum
from typing import Dict, Optional
from fastapi import HTTPException, status


class ErrorCode(Enum):
    """Standardized error codes for the authentication API."""
    
    # Authentication errors
    INVALID_CREDENTIALS = "AUTH_001"
    ACCOUNT_DEACTIVATED = "AUTH_002"
    INVALID_MFA_TOKEN = "AUTH_003"
    MFA_NOT_ENABLED = "AUTH_004"
    
    # Token errors
    INVALID_TOKEN = "TOKEN_001"
    EXPIRED_TOKEN = "TOKEN_002"
    BLACKLISTED_TOKEN = "TOKEN_003"
    INVALID_TOKEN_PAYLOAD = "TOKEN_004"
    INVALID_SESSION_TOKEN = "TOKEN_005"
    
    # Registration errors
    USERNAME_TAKEN = "REG_001"
    EMAIL_TAKEN = "REG_002"
    PASSWORD_VALIDATION_FAILED = "REG_003"
    REGISTRATION_FAILED = "REG_004"
    
    # Password reset errors
    INVALID_RESET_TOKEN = "RESET_001"
    EXPIRED_RESET_TOKEN = "RESET_002"
    PASSWORD_RESET_FAILED = "RESET_003"
    
    # Rate limiting errors
    TOO_MANY_LOGIN_ATTEMPTS = "RATE_001"
    TOO_MANY_REFRESH_ATTEMPTS = "RATE_002"
    
    # User management errors
    USER_NOT_FOUND = "USER_001"
    
    # System errors
    INTERNAL_ERROR = "SYS_001"
    DATABASE_ERROR = "SYS_002"
    CLEANUP_FAILED = "SYS_003"


class ErrorMessage:
    """Standardized error messages for consistent API responses."""
    
    # Authentication error messages
    INVALID_CREDENTIALS = "Invalid username or password"
    ACCOUNT_DEACTIVATED = "User account is deactivated"
    INVALID_MFA_TOKEN = "Invalid MFA token"
    MFA_NOT_ENABLED = "MFA is not enabled for this account"
    
    # Token error messages
    INVALID_TOKEN = "Invalid token"
    EXPIRED_TOKEN = "Token has expired"
    BLACKLISTED_TOKEN = "Token has been invalidated"
    INVALID_REFRESH_TOKEN = "Invalid, expired, or blacklisted refresh token"
    INVALID_TOKEN_PAYLOAD = "Invalid token payload"
    INVALID_SESSION_TOKEN = "Invalid or expired session token"
    
    # Registration error messages
    USERNAME_TAKEN = "Username is already registered"
    EMAIL_TAKEN = "Email address is already registered"
    REGISTRATION_FAILED = "User registration failed"
    
    # Password reset error messages
    INVALID_RESET_TOKEN = "Invalid or expired reset token"
    EXPIRED_RESET_TOKEN = "Reset token has expired"
    PASSWORD_RESET_FAILED = "Password reset failed"
    
    # Rate limiting error messages
    TOO_MANY_LOGIN_ATTEMPTS = "Too many failed login attempts. Please try again later"
    TOO_MANY_REFRESH_ATTEMPTS = "Too many failed refresh attempts. Please try again later"
    
    # User management error messages
    USER_NOT_FOUND = "User not found or deactivated"
    
    # System error messages
    INTERNAL_ERROR = "Internal server error"
    DATABASE_ERROR = "Database operation failed"
    CLEANUP_FAILED = "Token cleanup operation failed"


class AuthError:
    """Standardized error responses for the authentication API."""
    
    @staticmethod
    def create_error(
        error_code: ErrorCode,
        message: str,
        status_code: int,
        details: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> HTTPException:
        """
        Create a standardized HTTPException with error code and message.
        
        Args:
            error_code: Standardized error code
            message: Error message
            status_code: HTTP status code
            details: Optional additional details
            headers: Optional HTTP headers
            
        Returns:
            HTTPException: Formatted exception with standardized structure
        """
        error_detail = {
            "error_code": error_code.value,
            "message": message,
        }
        
        if details:
            error_detail["details"] = details
            
        return HTTPException(
            status_code=status_code,
            detail=error_detail,
            headers=headers
        )
    
    # Authentication errors
    @staticmethod
    def invalid_credentials() -> HTTPException:
        """Invalid username or password error."""
        return AuthError.create_error(
            ErrorCode.INVALID_CREDENTIALS,
            ErrorMessage.INVALID_CREDENTIALS,
            status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    @staticmethod
    def account_deactivated() -> HTTPException:
        """Account deactivated error."""
        return AuthError.create_error(
            ErrorCode.ACCOUNT_DEACTIVATED,
            ErrorMessage.ACCOUNT_DEACTIVATED,
            status.HTTP_403_FORBIDDEN
        )
    
    @staticmethod
    def invalid_mfa_token() -> HTTPException:
        """Invalid MFA token error."""
        return AuthError.create_error(
            ErrorCode.INVALID_MFA_TOKEN,
            ErrorMessage.INVALID_MFA_TOKEN,
            status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    @staticmethod
    def mfa_not_enabled() -> HTTPException:
        """MFA not enabled error."""
        return AuthError.create_error(
            ErrorCode.MFA_NOT_ENABLED,
            ErrorMessage.MFA_NOT_ENABLED,
            status.HTTP_400_BAD_REQUEST
        )
    
    # Token errors
    @staticmethod
    def invalid_refresh_token() -> HTTPException:
        """Invalid refresh token error."""
        return AuthError.create_error(
            ErrorCode.INVALID_TOKEN,
            ErrorMessage.INVALID_REFRESH_TOKEN,
            status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    @staticmethod
    def invalid_token_payload() -> HTTPException:
        """Invalid token payload error."""
        return AuthError.create_error(
            ErrorCode.INVALID_TOKEN_PAYLOAD,
            ErrorMessage.INVALID_TOKEN_PAYLOAD,
            status.HTTP_401_UNAUTHORIZED
        )

    @staticmethod
    def invalid_session_token() -> HTTPException:
        """Invalid session token error."""
        return AuthError.create_error(
            ErrorCode.INVALID_SESSION_TOKEN,
            ErrorMessage.INVALID_SESSION_TOKEN,
            status.HTTP_401_UNAUTHORIZED
        )

    # Registration errors
    @staticmethod
    def username_taken() -> HTTPException:
        """Username already registered error."""
        return AuthError.create_error(
            ErrorCode.USERNAME_TAKEN,
            ErrorMessage.USERNAME_TAKEN,
            status.HTTP_409_CONFLICT
        )
    
    @staticmethod
    def email_taken() -> HTTPException:
        """Email already registered error."""
        return AuthError.create_error(
            ErrorCode.EMAIL_TAKEN,
            ErrorMessage.EMAIL_TAKEN,
            status.HTTP_409_CONFLICT
        )
    
    @staticmethod
    def password_validation_failed(details: str) -> HTTPException:
        """Password validation failed error."""
        return AuthError.create_error(
            ErrorCode.PASSWORD_VALIDATION_FAILED,
            "Password validation failed",
            status.HTTP_400_BAD_REQUEST,
            details=details
        )
    
    @staticmethod
    def registration_failed() -> HTTPException:
        """User registration failed error."""
        return AuthError.create_error(
            ErrorCode.REGISTRATION_FAILED,
            ErrorMessage.REGISTRATION_FAILED,
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # Password reset errors
    @staticmethod
    def invalid_reset_token() -> HTTPException:
        """Invalid reset token error."""
        return AuthError.create_error(
            ErrorCode.INVALID_RESET_TOKEN,
            ErrorMessage.INVALID_RESET_TOKEN,
            status.HTTP_400_BAD_REQUEST
        )
    
    @staticmethod
    def expired_reset_token() -> HTTPException:
        """Expired reset token error."""
        return AuthError.create_error(
            ErrorCode.EXPIRED_RESET_TOKEN,
            ErrorMessage.EXPIRED_RESET_TOKEN,
            status.HTTP_400_BAD_REQUEST
        )
    
    @staticmethod
    def password_reset_failed(details: Optional[str] = None) -> HTTPException:
        """Password reset failed error."""
        return AuthError.create_error(
            ErrorCode.PASSWORD_RESET_FAILED,
            ErrorMessage.PASSWORD_RESET_FAILED,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )
    
    # Rate limiting errors
    @staticmethod
    def too_many_login_attempts(failed_count: int, retry_after: int) -> HTTPException:
        """Too many login attempts error."""
        return AuthError.create_error(
            ErrorCode.TOO_MANY_LOGIN_ATTEMPTS,
            ErrorMessage.TOO_MANY_LOGIN_ATTEMPTS,
            status.HTTP_429_TOO_MANY_REQUESTS,
            details=f"{failed_count} failed attempts",
            headers={"Retry-After": str(retry_after)}
        )
    
    @staticmethod
    def too_many_refresh_attempts(failed_count: int, retry_after: int) -> HTTPException:
        """Too many refresh attempts error."""
        return AuthError.create_error(
            ErrorCode.TOO_MANY_REFRESH_ATTEMPTS,
            ErrorMessage.TOO_MANY_REFRESH_ATTEMPTS,
            status.HTTP_429_TOO_MANY_REQUESTS,
            details=f"{failed_count} failed attempts",
            headers={"Retry-After": str(retry_after)}
        )
    
    # User management errors
    @staticmethod
    def user_not_found() -> HTTPException:
        """User not found error."""
        return AuthError.create_error(
            ErrorCode.USER_NOT_FOUND,
            ErrorMessage.USER_NOT_FOUND,
            status.HTTP_401_UNAUTHORIZED
        )
    
    # System errors
    @staticmethod
    def internal_error(details: Optional[str] = None) -> HTTPException:
        """Internal server error."""
        return AuthError.create_error(
            ErrorCode.INTERNAL_ERROR,
            ErrorMessage.INTERNAL_ERROR,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )
    
    @staticmethod
    def cleanup_failed() -> HTTPException:
        """Token cleanup failed error."""
        return AuthError.create_error(
            ErrorCode.CLEANUP_FAILED,
            ErrorMessage.CLEANUP_FAILED,
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
