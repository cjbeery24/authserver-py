"""
Pydantic schemas for authentication API endpoints.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class UserRegistrationRequest(BaseModel):
    """Request model for user registration."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "password": "SecurePass123!"
            }
        }


class UserRegistrationResponse(BaseModel):
    """Response model for user registration."""
    id: int
    username: str
    email: str
    is_active: bool
    created_at: str
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "johndoe",
                "email": "john.doe@example.com",
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "message": "User registered successfully"
            }
        }


class TokenResponse(BaseModel):
    """Response model for token generation."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: int
    username: str

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user_id": 1,
                "username": "johndoe"
            }
        }


class UserResponse(BaseModel):
    """Response model for user information."""
    id: int
    username: str
    email: str
    is_active: bool
    created_at: str

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "johndoe",
                "email": "john.doe@example.com",
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z"
            }
        }


class MFATokenRequest(BaseModel):
    """Request model for MFA token submission during login."""
    username: str
    password: str
    mfa_token: str = Field(..., min_length=6, max_length=8, description="TOTP token or backup code")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "SecurePass123!",
                "mfa_token": "123456"
            }
        }


class MFARequiredResponse(BaseModel):
    """Response when MFA is required for login."""
    mfa_required: bool = True
    user_id: int
    username: str
    session_token: str
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "mfa_required": True,
                "user_id": 1,
                "username": "johndoe",
                "session_token": "abc123def456ghi789xyz",
                "message": "Multi-factor authentication required. Use the session_token with /token/mfa endpoint."
            }
        }


class MFALoginRequest(BaseModel):
    """Request model for MFA login."""
    username: str
    password: str
    mfa_token: str = Field(..., min_length=6, max_length=8)

    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "SecurePass123!",
                "mfa_token": "123456"
            }
        }


class PasswordResetRequest(BaseModel):
    """Request model for password reset."""
    email: EmailStr

    class Config:
        json_schema_extra = {
            "example": {
                "email": "john.doe@example.com"
            }
        }


class PasswordResetConfirmRequest(BaseModel):
    """Request model for password reset confirmation."""
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

    class Config:
        json_schema_extra = {
            "example": {
                "token": "reset_token_here",
                "new_password": "NewSecurePass123!"
            }
        }


class MFAEnableRequest(BaseModel):
    """Request model for enabling MFA."""
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "password": "SecurePass123!"
            }
        }


class MFAEnableResponse(BaseModel):
    """Response model for MFA enable."""
    secret: str
    qr_code_uri: str
    backup_codes: list[str]

    class Config:
        json_schema_extra = {
            "example": {
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code_uri": "otpauth://totp/AuthServer:johndoe?secret=JBSWY3DPEHPK3PXP&issuer=AuthServer",
                "backup_codes": ["abc123def", "456ghi789", "xyz000abc"]
            }
        }


class MFAVerifyRequest(BaseModel):
    """Request model for MFA verification."""
    token: str = Field(..., min_length=6, max_length=8)

    class Config:
        json_schema_extra = {
            "example": {
                "token": "123456"
            }
        }


class MFABackupCodeRequest(BaseModel):
    """Request model for MFA backup code verification."""
    backup_code: str = Field(..., min_length=8, max_length=8)

    class Config:
        json_schema_extra = {
            "example": {
                "backup_code": "abc123def"
            }
        }


class MFASessionRequest(BaseModel):
    """Request model for MFA verification using session token."""
    session_token: str = Field(..., description="Temporary session token from MFA required response")
    mfa_token: str = Field(..., min_length=6, max_length=8, description="TOTP token or backup code")

    class Config:
        json_schema_extra = {
            "example": {
                "session_token": "abc123def456ghi789xyz",
                "mfa_token": "123456"
            }
        }


class TokenRefreshRequest(BaseModel):
    """Request model for token refresh."""
    refresh_token: str = Field(..., description="Refresh token to exchange for new access token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class LogoutResponse(BaseModel):
    """Response for logout endpoint."""
    message: str = Field(..., description="Success message")
    success: bool = Field(default=True, description="Whether logout was successful")
    tokens_invalidated: int = Field(default=1, description="Number of tokens invalidated")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Successfully logged out",
                "success": True,
                "tokens_invalidated": 1
            }
        }


class ErrorResponse(BaseModel):
    """Generic error response model."""
    detail: str
    type: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Username already registered",
                "type": "validation_error"
            }
        }
