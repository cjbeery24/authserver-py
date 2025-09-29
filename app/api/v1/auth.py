"""
Authentication API endpoints for user registration, login, and token management.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
import logging

from app.core.database import get_db
from app.core.security import (
    TokenManager,
    PasswordHasher,
    PasswordStrength,
    MFAHandler,
    SecurityAudit,
    FailedLoginTracker,
    FailedRefreshTracker,
    TokenGenerator,
    TokenBlacklist,
    SecureTokenHasher
)
from app.core.errors import AuthError
from app.core.redis import get_redis_dependency
from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.models.password_reset import PasswordResetToken
from app.models.user_token import UserToken
from app.models.oauth2_authorization_code import OAuth2AuthorizationCode
from app.models.oauth2_client_token import OAuth2ClientToken
from app.core.config import settings
from sqlalchemy import and_
from app.core.email import email_service
from app.middleware import get_current_user_or_401, get_raw_token_or_401
from app.schemas.auth import (
    UserRegistrationRequest,
    UserRegistrationResponse,
    TokenResponse,
    UserResponse,
    MFATokenRequest,
    MFARequiredResponse,
    LogoutResponse
)
from app.schemas.password_reset import (
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordResetResponse,
    PasswordResetConfirmResponse
)

router = APIRouter()

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Logger
logger = logging.getLogger(__name__)


# Custom rate limiting dependency that uses FailedLoginTracker
async def progressive_rate_limit(
    request: Request,
    redis_client = Depends(get_redis_dependency)
):
    """
    Progressive rate limiting based on failed login attempts.
    Applies stricter limits to IPs with recent failures.
    """
    if not settings.auth_rate_limit_enabled:
        return

    client_ip = request.client.host if request.client else "unknown"
    
    # Check if IP should be rate limited based on failed attempts
    is_limited = await FailedLoginTracker.is_rate_limited(client_ip, redis_client)
    
    if is_limited:
        failed_count = await FailedLoginTracker.get_failed_attempts(client_ip, redis_client)
        penalty_duration = await FailedLoginTracker.get_penalty_duration(client_ip, redis_client)
        raise AuthError.too_many_login_attempts(failed_count, penalty_duration)


# Custom progressive rate limiting for refresh token attempts
async def progressive_refresh_rate_limit(
    request: Request,
    redis_client = Depends(get_redis_dependency)
):
    """
    Progressive rate limiting based on failed refresh token attempts.
    Applies stricter limits to IPs with recent refresh failures.
    """
    if not settings.auth_rate_limit_enabled:
        return

    client_ip = request.client.host if request.client else "unknown"
    
    # Check if IP should be rate limited based on failed refresh attempts
    is_limited = await FailedRefreshTracker.is_rate_limited(client_ip, redis_client)
    
    if is_limited:
        failed_count = await FailedRefreshTracker.get_failed_attempts(client_ip, redis_client)
        penalty_duration = await FailedRefreshTracker.get_penalty_duration(client_ip, redis_client)
        raise AuthError.too_many_refresh_attempts(failed_count, penalty_duration)


# Helper function for authentication logic
async def _authenticate_user(
    request: Request,
    username: str,
    password: str,
    db: Session,
    redis_client,
    mfa_token: Optional[str] = None
) -> tuple[User, bool]:
    """
    Authenticate user with username/password and optional MFA.
    
    Returns:
        tuple: (User object, requires_mfa: bool)
        
    Raises:
        HTTPException: If authentication fails
    """
    # Get client IP for failed login tracking
    client_ip = request.client.host if request.client else "unknown"

    # Find user by username
    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Record failed login attempt
        if settings.auth_rate_limit_enabled:
            await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

        raise AuthError.invalid_credentials()

    # Verify password
    if not PasswordHasher.verify_password(password, user.password_hash):
        # Record failed login attempt
        if settings.auth_rate_limit_enabled:
            await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

        raise AuthError.invalid_credentials()

    # Check if user is active
    if not user.is_active:
        raise AuthError.account_deactivated()

    # Check MFA if enabled for user
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == user.id,
        MFASecret.is_enabled == True
    ).first()

    # If MFA is enabled but no token provided, indicate MFA is required
    if mfa_secret and not mfa_token:
        return user, True  # MFA required

    # If MFA is enabled and token provided, verify it
    if mfa_secret and mfa_token:
        mfa_valid = False

        # Try TOTP verification first
        if MFAHandler.verify_totp(mfa_secret.secret, mfa_token):
            mfa_valid = True
        # Try backup code verification
        elif mfa_secret.validate_backup_code(mfa_token):
            mfa_valid = True
            db.commit()  # Save backup code consumption

        if not mfa_valid:
            # Record failed MFA attempt
            if settings.auth_rate_limit_enabled:
                await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

            raise AuthError.invalid_mfa_token()

    # Reset failed login attempts on successful authentication
    if settings.auth_rate_limit_enabled:
        await FailedLoginTracker.reset_failed_attempts(client_ip, redis_client)

    return user, False  # Authentication successful, no MFA required


async def _create_token_response(
    user: User, 
    db: Session, 
    ip_address: str = None, 
    user_agent: str = None,
    old_refresh_token: str = None,
    redis_client = None
) -> TokenResponse:
    """
    Create token response for authenticated user and store tokens in database.
    
    Args:
        user: User object
        db: Database session
        ip_address: Client IP address
        user_agent: User agent string
        old_refresh_token: Previous refresh token to blacklist (for token rotation)
        redis_client: Redis client for token blacklisting
    """
    token_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email
    }

    tokens = TokenManager.create_token_pair(token_data)

    # Blacklist old refresh token if provided (token rotation security)
    if old_refresh_token and redis_client:
        blacklist_success = await TokenBlacklist.blacklist_token(old_refresh_token, redis_client)
        if blacklist_success:
            logger.info(f"Blacklisted old refresh token for user {user.id} during token rotation")
            
            # Also mark as revoked in database for audit purposes
            await _revoke_token_in_db(
                token=old_refresh_token,
                db=db,
                reason="token_rotation",
                ip_address=ip_address,
                user_agent=user_agent
            )
        else:
            logger.warning(f"Failed to blacklist old refresh token for user {user.id}")

    # Store new tokens in database for tracking
    TokenManager.store_user_tokens(
        db_session=db,
        user_id=user.id,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        ip_address=ip_address,
        user_agent=user_agent
    )

    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens["token_type"],
        expires_in=tokens["expires_in"],
        user_id=user.id,
        username=user.username
    )


async def _revoke_token_in_db(token: str, db: Session, reason: str = "logout", ip_address: str = None, user_agent: str = None) -> bool:
    """Revoke a token in the database by its JTI for audit purposes."""
    jti = SecurityAudit.get_token_jti(token)
    if not jti:
        return False
    
    token_record = db.query(UserToken).filter(UserToken.token_jti == jti).first()
    if token_record and not token_record.is_revoked:
        token_record.revoke(
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.commit()
        return True
    return False


@router.post("/register", response_model=UserRegistrationResponse, status_code=status.HTTP_201_CREATED,
            dependencies=[Depends(RateLimiter(times=settings.auth_registration_per_hour, hours=1))])
async def register_user(
    user_data: UserRegistrationRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.

    - Validates input data
    - Checks for existing username/email
    - Hashes password securely
    - Creates user record
    - Optionally sets up MFA
    """
    # Validate password strength
    try:
        PasswordStrength.validate_password(user_data.password, user_data.username)
    except Exception as e:
        raise AuthError.password_validation_failed(str(e))

    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise AuthError.username_taken()

    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise AuthError.email_taken()

    try:
        # Hash the password
        hashed_password = PasswordHasher.hash_password(user_data.password, user_data.username)

        # Create new user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=hashed_password,
            is_active=True
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Optionally create MFA secret for the user
        if settings.mfa_enabled_by_default:
            try:
                mfa_secret = MFASecret.create_for_user(
                    db_session=db,
                    user_id=new_user.id,
                    generate_secret=True,
                    generate_backup_codes=True
                )
                db.add(mfa_secret)
                db.commit()
            except Exception as e:
                # Log MFA setup failure but don't fail registration
                print(f"Warning: Failed to setup MFA for user {new_user.id}: {e}")

        return UserRegistrationResponse(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            is_active=new_user.is_active,
            created_at=new_user.created_at.isoformat() if new_user.created_at else None,
            message="User registered successfully"
        )

    except Exception as e:
        db.rollback()
        raise AuthError.registration_failed()


@router.post("/token", response_model=Union[TokenResponse, MFARequiredResponse],
            dependencies=[
                Depends(RateLimiter(times=settings.auth_login_per_minute, minutes=1)),
                Depends(progressive_rate_limit)
            ])
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    OAuth2 compatible token endpoint for user authentication.

    - Validates username/password
    - Returns MFA challenge if MFA is enabled
    - Returns tokens if no MFA required
    """
    # Authenticate user (without MFA token)
    user, requires_mfa = await _authenticate_user(
        request=request,
        username=form_data.username,
        password=form_data.password,
        db=db,
        redis_client=redis_client
    )

    # If MFA is required, return MFA challenge
    if requires_mfa:
        return MFARequiredResponse(
            mfa_required=True,
            user_id=user.id,
            username=user.username,
            message="Multi-factor authentication required. Use /token/mfa endpoint with MFA token."
        )

    # No MFA required, return tokens
    return await _create_token_response(
        user=user,
        db=db,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get('User-Agent'),
        redis_client=redis_client
    )


@router.post("/token/mfa", response_model=TokenResponse,
            dependencies=[
                Depends(RateLimiter(times=settings.auth_login_per_minute, minutes=1)),
                Depends(progressive_rate_limit)
            ])
async def verify_mfa_token(
    request: Request,
    mfa_data: MFATokenRequest,
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Verify MFA token and complete authentication.

    - Validates username/password
    - Verifies MFA token (TOTP or backup code)
    - Returns access and refresh tokens
    """
    # Authenticate user with MFA token
    user, requires_mfa = await _authenticate_user(
        request=request,
        username=mfa_data.username,
        password=mfa_data.password,
        db=db,
        redis_client=redis_client,
        mfa_token=mfa_data.mfa_token
    )

    # Check if MFA was actually enabled for this user
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == user.id,
        MFASecret.is_enabled == True
    ).first()

    if not mfa_secret:
        raise AuthError.mfa_not_enabled()

    # Authentication successful, return tokens
    return await _create_token_response(
        user=user,
        db=db,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get('User-Agent'),
        redis_client=redis_client
    )


@router.post("/refresh", response_model=TokenResponse,
            dependencies=[
                Depends(RateLimiter(times=settings.auth_token_refresh_per_hour, hours=1)),
                Depends(progressive_refresh_rate_limit)
            ])
async def refresh_access_token(
    request: Request,
    refresh_token: str,
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Refresh an access token using a valid refresh token.

    - Validates refresh token with progressive rate limiting
    - Issues new access token
    - Maintains user session
    - Tracks failed refresh attempts for security
    """
    # Get client IP for failed refresh tracking
    client_ip = request.client.host if request.client else "unknown"

    # Validate refresh token (now checks blacklist)
    payload = await TokenManager.verify_token(refresh_token, "refresh", redis_client)
    if not payload:
        # Record failed refresh attempt
        if settings.auth_rate_limit_enabled:
            await FailedRefreshTracker.record_failed_attempt(client_ip, redis_client)
        
        logger.warning(f"Failed refresh token attempt from IP: {client_ip}")
        raise AuthError.invalid_refresh_token()

    # Token revocation is now checked in verify_token() via Redis blacklist

    user_id = int(payload.get("sub"))
    if not user_id:
        raise AuthError.invalid_token_payload()

    # Verify user still exists and is active
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise AuthError.user_not_found()

    # Create new token pair with token rotation (blacklist old refresh token)
    token_response = await _create_token_response(
        user=user,
        db=db,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get('User-Agent'),
        old_refresh_token=refresh_token,  # Blacklist the used refresh token
        redis_client=redis_client
    )

    # Reset failed refresh attempts on successful refresh
    if settings.auth_rate_limit_enabled:
        await FailedRefreshTracker.reset_failed_attempts(client_ip, redis_client)

    logger.info(f"Token refresh successful for user {user_id} from IP: {client_ip} (old token blacklisted)")

    return token_response


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    request: Request,
    current_user: User = Depends(get_current_user_or_401)
):
    """
    Get current authenticated user information.

    - Uses authentication middleware for automatic token validation
    - Returns user profile data from middleware context
    """
    # User is already validated by middleware and available in current_user
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat() if current_user.created_at else None
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user_or_401),
    token: str = Depends(get_raw_token_or_401),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Logout endpoint - invalidates the current access token.

    - Uses authentication middleware for user validation
    - Blacklists the current access token
    - Logs the logout event
    - Returns success confirmation
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    try:
        # User is already validated by middleware
        user_id = current_user.id


        # Blacklist the access token in Redis for immediate effect
        token_blacklisted = await TokenBlacklist.blacklist_token(token, redis_client)

        # Also mark the token as revoked in the database for audit purposes
        db_token_revoked = await _revoke_token_in_db(
            token=token,
            db=db,
            reason="single_logout",
            ip_address=client_ip,
            user_agent=request.headers.get('User-Agent')
        )

        if token_blacklisted:
            logger.info(f"User {user_id} logged out successfully from IP: {client_ip} (Redis: {token_blacklisted}, DB: {db_token_revoked})")
            return LogoutResponse(
                message="Successfully logged out",
                success=True,
                tokens_invalidated=1
            )
        else:
            logger.warning(f"Failed to blacklist token for user {user_id} from IP: {client_ip}")
            # Even if blacklisting fails, we consider the logout successful from user's perspective
            # The token will expire naturally
            return LogoutResponse(
                message="Logged out (token will expire naturally)",
                success=True,
                tokens_invalidated=0
            )

    except Exception as e:
        logger.error(f"Error during logout for IP {client_ip}: {str(e)}")
        # Don't fail the logout request due to internal errors
        # The token will expire naturally if there's an issue
        return LogoutResponse(
            message="Logged out (token will expire naturally)",
            success=True,
            tokens_invalidated=0
        )


@router.post("/logout-all", response_model=LogoutResponse)
async def logout_all_devices(
    request: Request,
    current_user: User = Depends(get_current_user_or_401),
    token: str = Depends(get_raw_token_or_401),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Logout from all devices - invalidates all tokens for the current user.

    - Uses authentication middleware for user validation
    - Blacklists all active tokens for the user
    - Forces logout from all devices/sessions
    - Logs the logout event
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    try:
        # User is already validated by middleware
        user_id = current_user.id
        user = current_user

        # Blacklist the current token first
        await TokenBlacklist.blacklist_token(token, redis_client)

        # Blacklist all user tokens using Redis
        tokens_blacklisted = await TokenBlacklist.blacklist_all_user_tokens(
            user_id=user_id,
            redis_client=redis_client,
            db_session=db
        )

        # Also mark all user tokens as revoked in database for audit purposes
        db_tokens_revoked = UserToken.revoke_user_tokens(
            db_session=db,
            user_id=user_id,
            reason="logout_all",
            ip_address=client_ip,
            user_agent=request.headers.get('User-Agent')
        )

        # Invalidate all password reset tokens for the user as well
        existing_reset_tokens = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.is_used == False
        ).all()

        for reset_token in existing_reset_tokens:
            reset_token.mark_as_used(ip_address=client_ip, user_agent=request.headers.get('User-Agent'))

        db.commit()

        logger.info(f"User {user_id} logged out from all devices from IP: {client_ip}, blacklisted {tokens_blacklisted} tokens, marked {db_tokens_revoked} as revoked in DB")

        return LogoutResponse(
            message="Successfully logged out from all devices",
            success=True,
            tokens_invalidated=tokens_blacklisted
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during logout-all for IP {client_ip}: {str(e)}")
        # Don't fail the logout request due to internal errors
        return LogoutResponse(
            message="Logged out from all devices (some tokens may remain active)",
            success=True,
            tokens_invalidated=0
        )


@router.post("/password-reset/request", response_model=PasswordResetResponse,
            dependencies=[Depends(RateLimiter(times=3, hours=1))])
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """
    Request password reset via email.

    - Validates email exists
    - Generates secure reset token
    - Sends password reset email
    - Rate limited to 3 requests per hour
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    # Find user by email
    user = db.query(User).filter(User.email == reset_request.email).first()
    
    # Always return success message for security (don't reveal if email exists)
    # This prevents email enumeration attacks
    success_message = "If an account with that email exists, a password reset link has been sent."
    
    if not user:
        # Log attempt for monitoring
        logger.warning(f"Password reset requested for non-existent email: {reset_request.email} from IP: {client_ip}")
        return PasswordResetResponse(
            message=success_message,
            email_sent=False
        )

    if not user.is_active:
        # Log attempt for monitoring
        logger.warning(f"Password reset requested for inactive user: {user.id} from IP: {client_ip}")
        return PasswordResetResponse(
            message=success_message,
            email_sent=False
        )

    try:
        # Generate secure reset token
        reset_token = TokenGenerator.generate_reset_token()
        
        # Invalidate any existing reset tokens for this user
        existing_tokens = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.is_used == False
        ).all()
        
        for token in existing_tokens:
            token.mark_as_used(ip_address=client_ip, user_agent=request.headers.get('User-Agent'))
        
        # Create new reset token
        password_reset_token = PasswordResetToken.create_reset_token(
            user_id=user.id,
            token=reset_token,
            expiry_hours=settings.password_reset_token_expire_hours
        )
        
        db.add(password_reset_token)
        db.commit()
        
        # Send password reset email
        email_sent = await email_service.send_password_reset_email(
            email=user.email,
            username=user.username,
            reset_token=reset_token
        )
        
        if email_sent:
            logger.info(f"Password reset email sent successfully to user {user.id} from IP: {client_ip}")
        else:
            logger.error(f"Failed to send password reset email to user {user.id}")
        
        return PasswordResetResponse(
            message=success_message,
            email_sent=email_sent
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error processing password reset request for {reset_request.email}: {str(e)}")
        return PasswordResetResponse(
            message=success_message,
            email_sent=False
        )


@router.post("/password-reset/confirm", response_model=PasswordResetConfirmResponse,
            dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def confirm_password_reset(
    request: Request,
    reset_confirm: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """
    Confirm password reset with token and new password.

    - Validates reset token
    - Checks token expiration
    - Validates new password strength
    - Updates user password
    - Sends confirmation email
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    # Find valid reset token using secure hash verification
    reset_token = PasswordResetToken.find_by_token(db, reset_confirm.token)

    if not reset_token:
        logger.warning(f"Invalid password reset token attempt from IP: {client_ip}")
        raise AuthError.invalid_reset_token()

    if reset_token.is_expired:
        logger.warning(f"Expired password reset token attempt for user {reset_token.user_id} from IP: {client_ip}")
        raise AuthError.expired_reset_token()

    # Get the user
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user or not user.is_active:
        logger.warning(f"Password reset attempt for invalid/inactive user {reset_token.user_id} from IP: {client_ip}")
        raise AuthError.invalid_reset_token()

    try:
        # Validate new password strength
        PasswordStrength.validate_password(reset_confirm.new_password, user.username)
        
        # Hash the new password
        new_password_hash = PasswordHasher.hash_password(reset_confirm.new_password, user.username)
        
        # Update user password
        user.password_hash = new_password_hash
        user.updated_at = datetime.now(timezone.utc)
        
        # Mark reset token as used
        reset_token.mark_as_used(
            ip_address=client_ip,
            user_agent=request.headers.get('User-Agent')
        )
        
        db.commit()
        
        # Send password changed notification email
        await email_service.send_password_changed_notification(
            email=user.email,
            username=user.username
        )
        
        logger.info(f"Password reset completed successfully for user {user.id} from IP: {client_ip}")
        
        return PasswordResetConfirmResponse(
            message="Password reset successfully",
            success=True
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error confirming password reset for user {reset_token.user_id}: {str(e)}")
        
        if "Password validation failed" in str(e):
            raise AuthError.password_validation_failed(str(e))
        
        raise AuthError.password_reset_failed()


@router.post("/admin/cleanup-tokens", response_model=dict)
async def cleanup_expired_tokens(
    db: Session = Depends(get_db)
):
    """
    Admin endpoint to cleanup expired and revoked tokens.

    This endpoint removes tokens that are both expired and either:
    - Revoked tokens
    - Tokens older than the cleanup threshold (30 days by default)

    Returns cleanup statistics.
    """
    try:
        # Cleanup expired tokens
        tokens_cleaned = UserToken.cleanup_expired_tokens(db_session=db)

        # Also cleanup expired password reset tokens
        password_reset_cleaned = PasswordResetToken.cleanup_expired_tokens(db_session=db)

        # Also cleanup expired OAuth2 authorization codes
        auth_codes_cleaned = OAuth2AuthorizationCode.cleanup_expired_codes(db_session=db)

        # Also cleanup expired OAuth2 client tokens
        client_tokens_cleaned = OAuth2ClientToken.cleanup_expired_tokens(db_session=db)

        # Also cleanup expired OAuth2 tokens (access and refresh tokens)
        from app.core.oauth import create_authorization_server
        server = create_authorization_server(db)
        oauth2_tokens_cleaned = server.validator.cleanup_expired_tokens(days_old=30)

        db.commit()

        logger.info(f"Token cleanup completed: {tokens_cleaned} user tokens, {password_reset_cleaned} password reset tokens, {auth_codes_cleaned} authorization codes, {client_tokens_cleaned} client tokens, {oauth2_tokens_cleaned} OAuth2 tokens")

        return {
            "message": "Token cleanup completed successfully",
            "user_tokens_cleaned": tokens_cleaned,
            "password_reset_tokens_cleaned": password_reset_cleaned,
            "authorization_codes_cleaned": auth_codes_cleaned,
            "client_tokens_cleaned": client_tokens_cleaned,
            "oauth2_tokens_cleaned": oauth2_tokens_cleaned,
            "total_cleaned": tokens_cleaned + password_reset_cleaned + auth_codes_cleaned + client_tokens_cleaned + oauth2_tokens_cleaned
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error during token cleanup: {str(e)}")
        raise AuthError.cleanup_failed()
