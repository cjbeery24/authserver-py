"""
User profile and account management API endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
from typing import Optional
import logging
import json

from app.core.database import get_db
from app.core.config import settings
from app.core.security import PasswordHasher, AuthenticationManager
from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.models.audit_log import AuditLog
from app.middleware import get_current_user_or_401
from pydantic import BaseModel, EmailStr, Field

router = APIRouter()
logger = logging.getLogger(__name__)


# User profile schemas
class UserProfileResponse(BaseModel):
    """Response model for user profile."""
    
    id: int
    username: str
    email: str
    is_active: bool
    created_at: str
    updated_at: str
    mfa_enabled: bool
    has_backup_codes: bool


class UpdateProfileRequest(BaseModel):
    """Request model for updating user profile."""
    
    email: Optional[EmailStr] = Field(None, description="New email address")
    current_password: Optional[str] = Field(None, description="Current password (required for sensitive changes)")


class UpdatePasswordRequest(BaseModel):
    """Request model for updating password."""
    
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")


class UserSecuritySettingsResponse(BaseModel):
    """Response model for user security settings."""
    
    mfa_enabled: bool
    mfa_configured: bool
    backup_codes_count: int
    backup_codes_expired: bool
    password_last_changed: Optional[str] = None
    active_sessions: int


@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Get the current user's profile information.
    
    Includes MFA status and account details.
    """
    # Check MFA status
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    mfa_enabled = False
    has_backup_codes = False
    
    if mfa_secret:
        mfa_enabled = mfa_secret.is_enabled
        if mfa_secret.backup_codes and mfa_secret.backup_codes != "{}":
            backup_codes_dict = json.loads(mfa_secret.backup_codes)
            has_backup_codes = len(backup_codes_dict) > 0
    
    return UserProfileResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat(),
        updated_at=current_user.updated_at.isoformat(),
        mfa_enabled=mfa_enabled,
        has_backup_codes=has_backup_codes
    )


@router.put("/me",
            dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def update_user_profile(
    profile_update: UpdateProfileRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Update the current user's profile.
    
    Requires password verification for sensitive changes.
    """
    changes_made = []
    
    # Update email if provided
    if profile_update.email and profile_update.email != current_user.email:
        # Require password for email change
        if not profile_update.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password required for email change"
            )
        
        if not AuthenticationManager.verify_user_password(current_user, profile_update.current_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
        
        # Check if email is already taken
        existing_email = db.query(User).filter(
            User.email == profile_update.email,
            User.id != current_user.id
        ).first()
        
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address already in use"
            )
        
        current_user.email = profile_update.email
        changes_made.append("email")
    
    if changes_made:
        db.commit()
        db.refresh(current_user)
        
        logger.info(f"User {current_user.id} updated profile: {', '.join(changes_made)}")
        
        return {
            "message": f"Profile updated successfully: {', '.join(changes_made)}",
            "changes": changes_made
        }
    
    return {
        "message": "No changes made",
        "changes": []
    }


@router.put("/me/password",
            dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def update_password(
    request: Request,
    password_update: UpdatePasswordRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Update the current user's password.
    
    Requires current password verification.
    """
    # Verify current password using centralized authentication manager
    if not AuthenticationManager.verify_user_password(current_user, password_update.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid current password"
        )
    
    # Hash new password
    new_password_hash = PasswordHasher.hash_password(
        password_update.new_password,
        current_user.username
    )
    
    current_user.password_hash = new_password_hash
    db.commit()
    
    # Log password change
    AuditLog.log_password_change(
        db_session=db,
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get('User-Agent'),
        success=True
    )
    db.commit()
    
    logger.info(f"Password updated for user {current_user.id}")
    
    return {
        "message": "Password updated successfully"
    }


@router.get("/me/security", response_model=UserSecuritySettingsResponse)
async def get_security_settings(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive security settings and status for the current user.
    
    Includes MFA configuration, backup codes status, and active sessions.
    """
    from app.models.user_token import UserToken
    from datetime import datetime, timezone
    
    # Get MFA status
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    mfa_enabled = False
    mfa_configured = False
    backup_codes_count = 0
    backup_codes_expired = False
    
    if mfa_secret:
        mfa_enabled = mfa_secret.is_enabled
        mfa_configured = bool(mfa_secret.secret)
        backup_codes_expired = mfa_secret.is_backup_codes_expired
        
        if mfa_secret.backup_codes and mfa_secret.backup_codes != "{}":
            backup_codes_dict = json.loads(mfa_secret.backup_codes)
            backup_codes_count = sum(1 for used in backup_codes_dict.values() if not used)
    
    # Count active sessions (tokens)
    active_sessions = db.query(UserToken).filter(
        UserToken.user_id == current_user.id,
        UserToken.is_revoked == False,
        UserToken.expires_at > datetime.now(timezone.utc)
    ).count()
    
    return UserSecuritySettingsResponse(
        mfa_enabled=mfa_enabled,
        mfa_configured=mfa_configured,
        backup_codes_count=backup_codes_count,
        backup_codes_expired=backup_codes_expired,
        password_last_changed=current_user.updated_at.isoformat() if current_user.updated_at else None,
        active_sessions=active_sessions
    )


from pydantic import BaseModel

class DeleteAccountRequest(BaseModel):
    """Request model for account deletion."""
    password: str = Field(..., description="Password for verification")

@router.delete("/me",
              dependencies=[Depends(RateLimiter(times=3, hours=1))])
async def delete_account(
    request: Request,
    delete_data: DeleteAccountRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Delete the current user's account.
    
    This is a permanent action that cannot be undone.
    Requires password verification.
    """
    # Verify password using centralized authentication manager
    if not AuthenticationManager.verify_user_password(current_user, delete_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    # Mark account as inactive instead of deleting (for audit purposes)
    current_user.is_active = False
    db.commit()
    
    # Log account deletion
    AuditLog.log_event(
        db_session=db,
        user_id=current_user.id,
        action="account_delete",
        resource="user",
        resource_id=str(current_user.id),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get('User-Agent'),
        success=True,
        details={"event_type": "user_management", "action_type": "self_delete"}
    )
    db.commit()
    
    logger.warning(f"User account deactivated: {current_user.id}")
    
    return {
        "message": "Account has been deactivated successfully",
        "user_id": current_user.id
    }

