"""
Pydantic schemas for password reset functionality.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional


class PasswordResetRequest(BaseModel):
    """Schema for password reset request."""
    email: EmailStr = Field(..., description="Email address of the user requesting password reset")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""
    token: str = Field(..., min_length=1, max_length=255, description="Password reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

    class Config:
        json_schema_extra = {
            "example": {
                "token": "abc123def456ghi789",
                "new_password": "NewSecurePassword123!"
            }
        }


class PasswordResetResponse(BaseModel):
    """Schema for password reset response."""
    message: str = Field(..., description="Success message")
    email_sent: bool = Field(default=True, description="Whether email was sent successfully")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Password reset email sent successfully",
                "email_sent": True
            }
        }


class PasswordResetConfirmResponse(BaseModel):
    """Schema for password reset confirmation response."""
    message: str = Field(..., description="Success message")
    success: bool = Field(default=True, description="Whether password reset was successful")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Password reset successfully",
                "success": True
            }
        }


class PasswordResetTokenInfo(BaseModel):
    """Schema for password reset token information."""
    token: str
    user_id: int
    expires_at: str
    is_valid: bool
    is_used: bool
    is_expired: bool

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "token": "abc123def456ghi789",
                "user_id": 1,
                "expires_at": "2023-12-25T12:00:00Z",
                "is_valid": True,
                "is_used": False,
                "is_expired": False
            }
        }
