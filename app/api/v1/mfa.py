"""
MFA (Multi-Factor Authentication) management API endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta, timezone
import logging
import json
import qrcode
import io
import base64

from app.core.database import get_db
from app.core.redis import get_redis_dependency
from app.core.config import settings
from app.core.auth import MFAHandler, AuthenticationManager
from app.core.crypto import SecureTokenHasher
from app.core.errors import AuthError
from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.middleware import get_current_user_or_401
from app.schemas.auth import (
    MFAVerifyRequest
)
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger(__name__)


# MFA-specific response models
class MFAQRCodeResponse(BaseModel):
    """Response model for MFA QR code generation."""
    
    qr_code_base64: str = Field(..., description="Base64 encoded QR code image")
    manual_entry_key: str = Field(..., description="Secret key for manual entry")
    issuer: str = Field(..., description="Issuer name")
    account_name: str = Field(..., description="Account name (username or email)")


class MFADisableRequest(BaseModel):
    """Request model for disabling MFA."""
    
    password: str = Field(..., description="User's password for verification")


class MFAStatusResponse(BaseModel):
    """Response model for MFA status."""
    
    enabled: bool = Field(..., description="Whether MFA is enabled")
    has_backup_codes: bool = Field(default=False, description="Whether backup codes exist")
    backup_codes_count: int = Field(default=0, description="Number of unused backup codes")
    backup_codes_expired: bool = Field(default=False, description="Whether backup codes are expired")


class MFABackupCodesResponse(BaseModel):
    """Response model for backup codes."""
    
    backup_codes: list[str] = Field(..., description="List of backup codes")
    expires_at: str = Field(..., description="When backup codes expire")
    message: str = Field(..., description="Important instructions for the user")


class MFAVerifyCodeRequest(BaseModel):
    """Request model for verifying TOTP code during setup."""
    
    totp_code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


@router.get("/status", response_model=MFAStatusResponse)
async def get_mfa_status(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Get MFA status for the current user.
    
    Returns information about whether MFA is enabled and backup code status.
    """
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    if not mfa_secret:
        return MFAStatusResponse(
            enabled=False,
            has_backup_codes=False,
            backup_codes_count=0,
            backup_codes_expired=False
        )
    
    # Count unused backup codes
    backup_codes_dict = json.loads(mfa_secret.backup_codes) if mfa_secret.backup_codes else {}
    unused_codes = sum(1 for used in backup_codes_dict.values() if not used)
    
    return MFAStatusResponse(
        enabled=mfa_secret.is_enabled,
        has_backup_codes=len(backup_codes_dict) > 0,
        backup_codes_count=unused_codes,
        backup_codes_expired=mfa_secret.is_backup_codes_expired
    )


@router.post("/enable/init", response_model=MFAQRCodeResponse,
             dependencies=[Depends(RateLimiter(times=5, minutes=1))])
async def initialize_mfa_setup(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Initialize MFA setup for the user.
    
    Generates a new TOTP secret and returns a QR code for scanning with
    authenticator apps (Google Authenticator, Authy, etc.).
    """
    # Check if MFA is already enabled
    existing_mfa = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id,
        MFASecret.is_enabled == True
    ).first()
    
    if existing_mfa:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled for this user"
        )
    
    # Generate new secret
    secret = MFAHandler.generate_totp_secret()
    
    # Create or update MFA secret record (not enabled yet)
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    if mfa_secret:
        mfa_secret.secret = secret
        mfa_secret.is_enabled = False
    else:
        mfa_secret = MFASecret(
            user_id=current_user.id,
            secret=secret,
            is_enabled=False,
            backup_codes="{}"
        )
        db.add(mfa_secret)
    
    db.commit()
    
    # Generate TOTP URI for QR code
    account_name = current_user.email or current_user.username
    totp_uri = MFAHandler.generate_totp_uri(secret, account_name)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    logger.info(f"MFA setup initialized for user {current_user.id}")
    
    return MFAQRCodeResponse(
        qr_code_base64=qr_code_base64,
        manual_entry_key=secret,
        issuer=settings.mfa_totp_issuer,
        account_name=account_name
    )


@router.post("/enable/verify", response_model=MFABackupCodesResponse,
             dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def complete_mfa_setup(
    mfa_request: MFAVerifyCodeRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Complete MFA setup by verifying a TOTP code.
    
    Once verified, MFA will be enabled and backup codes will be generated.
    """
    # Get the pending MFA secret
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initialized. Call /mfa/enable/init first."
        )
    
    if mfa_secret.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled"
        )
    
    # Verify the TOTP code
    if not MFAHandler.verify_totp(mfa_secret.secret, mfa_request.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Please try again."
        )
    
    # Enable MFA
    mfa_secret.is_enabled = True
    
    # Generate backup codes
    backup_codes = MFAHandler.generate_backup_codes(count=10)
    hashed_codes = {}
    
    for code in backup_codes:
        hashed = SecureTokenHasher.hash_token(code)
        hashed_codes[hashed] = False  # False = not used
    
    mfa_secret.backup_codes = json.dumps(hashed_codes)
    mfa_secret.backup_codes_expiry = MFASecret.get_backup_code_expiry()
    
    db.commit()
    
    logger.info(f"MFA enabled for user {current_user.id}")
    
    return MFABackupCodesResponse(
        backup_codes=backup_codes,
        expires_at=mfa_secret.backup_codes_expiry.isoformat(),
        message="Save these backup codes in a secure location. Each code can only be used once."
    )


@router.post("/disable",
             dependencies=[Depends(RateLimiter(times=5, minutes=1))])
async def disable_mfa(
    disable_request: MFADisableRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Disable MFA for the current user.
    
    Requires password verification for security.
    """
    # Verify password using centralized authentication manager
    if not AuthenticationManager.verify_user_password(current_user, disable_request.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    # Get MFA secret
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id
    ).first()
    
    if not mfa_secret or not mfa_secret.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    # Disable MFA
    mfa_secret.is_enabled = False
    mfa_secret.backup_codes = "{}"
    
    db.commit()
    
    logger.info(f"MFA disabled for user {current_user.id}")
    
    return {
        "message": "MFA has been disabled successfully",
        "enabled": False
    }


@router.post("/backup-codes/regenerate", response_model=MFABackupCodesResponse,
             dependencies=[Depends(RateLimiter(times=3, minutes=60))])
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Regenerate backup codes for the current user.
    
    All previous backup codes will be invalidated.
    """
    # Get MFA secret
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id,
        MFASecret.is_enabled == True
    ).first()
    
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    # Generate new backup codes
    backup_codes = MFAHandler.generate_backup_codes(count=10)
    hashed_codes = {}
    
    for code in backup_codes:
        hashed = SecureTokenHasher.hash_token(code)
        hashed_codes[hashed] = False  # False = not used
    
    mfa_secret.backup_codes = json.dumps(hashed_codes)
    mfa_secret.backup_codes_expiry = MFASecret.get_backup_code_expiry()
    
    db.commit()
    
    logger.info(f"Backup codes regenerated for user {current_user.id}")
    
    return MFABackupCodesResponse(
        backup_codes=backup_codes,
        expires_at=mfa_secret.backup_codes_expiry.isoformat(),
        message="Save these backup codes in a secure location. All previous backup codes have been invalidated."
    )


@router.get("/backup-codes/status")
async def get_backup_codes_status(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Get status of backup codes (without revealing the codes themselves).
    
    Returns count of unused codes and expiration status.
    """
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == current_user.id,
        MFASecret.is_enabled == True
    ).first()
    
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    # Count unused backup codes
    backup_codes_dict = json.loads(mfa_secret.backup_codes) if mfa_secret.backup_codes else {}
    unused_codes = sum(1 for used in backup_codes_dict.values() if not used)
    total_codes = len(backup_codes_dict)
    
    return {
        "total_codes": total_codes,
        "unused_codes": unused_codes,
        "used_codes": total_codes - unused_codes,
        "expired": mfa_secret.is_backup_codes_expired,
        "expires_at": mfa_secret.backup_codes_expiry.isoformat() if mfa_secret.backup_codes_expiry else None
    }


# Emergency MFA Bypass Mechanisms
class MFABypassRequest(BaseModel):
    """Request model for MFA bypass (admin use)."""
    
    user_id: int = Field(..., description="User ID to bypass MFA for")
    reason: str = Field(..., description="Reason for bypass")
    duration_hours: int = Field(default=24, description="Bypass duration in hours", ge=1, le=72)


class MFABypassResponse(BaseModel):
    """Response model for MFA bypass."""
    
    user_id: int
    bypass_token: str = Field(..., description="One-time bypass token")
    expires_at: str
    reason: str


@router.post("/bypass/admin", response_model=MFABypassResponse,
             dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def create_admin_mfa_bypass(
    bypass_request: MFABypassRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Create an emergency MFA bypass token for a user (admin only).
    
    This should only be used in emergency situations when a user loses
    access to their MFA device.
    
    Requires 'mfa:bypass' permission or 'admin' role.
    """
    from app.core.rbac import PermissionChecker
    
    # Check if user has permission to bypass MFA
    has_permission = await PermissionChecker.has_permission(current_user.id, "mfa", "bypass", db)
    has_admin_role = await PermissionChecker.has_role(current_user.id, "admin", db)
    
    if not (has_permission or has_admin_role):
        logger.warning(
            f"Unauthorized MFA bypass attempt by user {current_user.id} "
            f"for user {bypass_request.user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: admin role or mfa:bypass permission required"
        )
    
    logger.warning(
        f"Admin MFA bypass requested by user {current_user.id} "
        f"for user {bypass_request.user_id}, reason: {bypass_request.reason}"
    )
    
    # Verify target user exists
    target_user = db.query(User).filter(User.id == bypass_request.user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Generate bypass token
    from app.core.auth import TokenGenerator
    bypass_token = TokenGenerator.generate_secure_token(length=48)
    
    # Store bypass token in Redis with expiration (redis_client injected via Depends)
    bypass_key = f"mfa_bypass:{bypass_request.user_id}:{SecureTokenHasher.hash_token(bypass_token)[:16]}"
    expiry_seconds = bypass_request.duration_hours * 3600
    
    bypass_data = json.dumps({
        "user_id": bypass_request.user_id,
        "reason": bypass_request.reason,
        "created_by": current_user.id,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    await redis_client.setex(bypass_key, expiry_seconds, bypass_data)
    
    expires_at = datetime.now(timezone.utc) + timedelta(hours=bypass_request.duration_hours)
    
    # Log to audit log
    from app.models.audit_log import AuditLog
    AuditLog.log_event(
        db_session=db,
        user_id=current_user.id,
        action="mfa_bypass_created",
        resource="user",
        resource_id=str(bypass_request.user_id),
        ip_address=None,  # Request object not available in this context
        user_agent=None,
        success=True,
        details={
            "event_type": "security",
            "target_user_id": bypass_request.user_id,
            "reason": bypass_request.reason,
            "duration_hours": bypass_request.duration_hours,
            "expires_at": expires_at.isoformat()
        }
    )
    db.commit()
    
    logger.critical(
        f"MFA bypass created for user {bypass_request.user_id} "
        f"by admin {current_user.id}, expires at {expires_at.isoformat()}"
    )
    
    return MFABypassResponse(
        user_id=bypass_request.user_id,
        bypass_token=bypass_token,
        expires_at=expires_at.isoformat(),
        reason=bypass_request.reason
    )


@router.post("/bypass/validate",
             dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def validate_mfa_bypass(
    bypass_token: str = Form(..., description="MFA bypass token"),
    user_id: int = Form(..., description="User ID"),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Validate an MFA bypass token.
    
    This is used internally during authentication when a user provides
    a bypass token instead of an MFA code.
    """
    # Check if bypass token exists in Redis (redis_client injected via Depends)
    bypass_key = f"mfa_bypass:{user_id}:{SecureTokenHasher.hash_token(bypass_token)[:16]}"
    bypass_data = await redis_client.get(bypass_key)
    
    if not bypass_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired bypass token"
        )
    
    # Parse bypass data
    try:
        bypass_info = json.loads(bypass_data)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid bypass token data"
        )
    
    # Consume the bypass token (one-time use)
    await redis_client.delete(bypass_key)
    
    logger.warning(
        f"MFA bypass token used for user {user_id}, "
        f"created by admin {bypass_info.get('created_by')}"
    )
    
    return {
        "valid": True,
        "message": "MFA bypassed for this login",
        "bypass_reason": bypass_info.get("reason")
    }


# MFA Recovery Procedures
class MFARecoveryRequest(BaseModel):
    """Request model for MFA recovery."""
    
    email: str = Field(..., description="User's email address")
    username: str = Field(..., description="Username")


class MFARecoveryResponse(BaseModel):
    """Response model for MFA recovery initiation."""
    
    message: str
    recovery_initiated: bool
    email_sent: bool


@router.post("/recovery/request", response_model=MFARecoveryResponse,
             dependencies=[Depends(RateLimiter(times=3, hours=1))])
async def request_mfa_recovery(
    recovery_request: MFARecoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Request MFA recovery when user loses access to their MFA device.
    
    Sends a recovery email with instructions and a time-limited recovery token.
    """
    # Find user
    user = db.query(User).filter(
        User.username == recovery_request.username,
        User.email == recovery_request.email,
        User.is_active == True
    ).first()
    
    # Always return success to prevent user enumeration
    if not user:
        logger.warning(f"MFA recovery requested for non-existent user: {recovery_request.username}")
        return MFARecoveryResponse(
            message="If your account exists, recovery instructions have been sent to your email",
            recovery_initiated=False,
            email_sent=False
        )
    
    # Check if MFA is actually enabled
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == user.id,
        MFASecret.is_enabled == True
    ).first()
    
    if not mfa_secret:
        logger.warning(f"MFA recovery requested for user {user.id} without MFA enabled")
        return MFARecoveryResponse(
            message="If your account exists, recovery instructions have been sent to your email",
            recovery_initiated=False,
            email_sent=False
        )
    
    # Generate recovery token
    from app.core.auth import TokenGenerator
    recovery_token = TokenGenerator.generate_secure_token(length=48)
    
    # Store recovery token in Redis (24 hour expiration, redis_client injected via Depends)
    recovery_key = f"mfa_recovery:{user.id}:{SecureTokenHasher.hash_token(recovery_token)[:16]}"
    recovery_data = json.dumps({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "ip_address": request.client.host if request.client else ""
    })
    
    await redis_client.setex(recovery_key, 24 * 3600, recovery_data)  # 24 hours
    
    # TODO: Send recovery email
    # await email_service.send_mfa_recovery_email(user.email, recovery_token)
    
    logger.info(f"MFA recovery initiated for user {user.id}")
    
    return MFARecoveryResponse(
        message="If your account exists, recovery instructions have been sent to your email",
        recovery_initiated=True,
        email_sent=True  # Set to False when email is not actually sent
    )


class MFARecoveryCompleteRequest(BaseModel):
    """Request model for completing MFA recovery."""
    
    recovery_token: str = Field(..., description="Recovery token from email")
    password: str = Field(..., description="Current password for verification")
    action: str = Field(default="disable", description="Action: 'disable' or 'reset'")


@router.post("/recovery/complete",
             dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def complete_mfa_recovery(
    recovery_request: MFARecoveryCompleteRequest,
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Complete MFA recovery using recovery token.
    
    User can choose to:
    - disable: Completely disable MFA
    - reset: Generate new secret and backup codes
    """
    # Validate recovery token (check all users since we don't know which user)
    # redis_client injected via Depends
    recovery_token_hash = SecureTokenHasher.hash_token(recovery_request.recovery_token)[:16]
    
    # Find the recovery token in Redis
    recovery_data = None
    user_id = None
    
    # Try to find the recovery key (we need to scan since we don't know the user_id)
    # This is not ideal but acceptable for recovery scenarios
    # Alternative: Use a secondary mapping in Redis
    
    users = db.query(User).filter(User.is_active == True).all()
    for user in users:
        recovery_key = f"mfa_recovery:{user.id}:{recovery_token_hash}"
        data = await redis_client.get(recovery_key)
        if data:
            recovery_data = json.loads(data)
            user_id = user.id
            await redis_client.delete(recovery_key)  # Consume token
            break
    
    if not recovery_data or not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired recovery token"
        )
    
    # Get user and verify password
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify password using centralized authentication manager
    if not AuthenticationManager.verify_user_password(user, recovery_request.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    # Get MFA secret
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == user_id
    ).first()
    
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    if recovery_request.action == "disable":
        # Disable MFA completely
        mfa_secret.is_enabled = False
        mfa_secret.backup_codes = "{}"
        db.commit()
        
        logger.info(f"MFA disabled via recovery for user {user_id}")
        
        return {
            "message": "MFA has been disabled successfully",
            "action": "disabled"
        }
    
    elif recovery_request.action == "reset":
        # Generate new backup codes but keep secret
        backup_codes = MFAHandler.generate_backup_codes(count=10)
        hashed_codes = {}
        
        for code in backup_codes:
            hashed = SecureTokenHasher.hash_token(code)
            hashed_codes[hashed] = False
        
        mfa_secret.backup_codes = json.dumps(hashed_codes)
        mfa_secret.backup_codes_expiry = MFASecret.get_backup_code_expiry()
        db.commit()
        
        logger.info(f"MFA backup codes reset via recovery for user {user_id}")
        
        return {
            "message": "New backup codes generated successfully",
            "action": "reset",
            "backup_codes": backup_codes,
            "expires_at": mfa_secret.backup_codes_expiry.isoformat()
        }
    
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid action. Must be 'disable' or 'reset'"
        )

