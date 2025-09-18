"""
Authentication API endpoints for user registration, login, and token management.
"""

from datetime import timedelta
from typing import Optional, Union
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    TokenManager,
    PasswordHasher,
    PasswordStrength,
    MFAHandler,
    SecurityAudit,
    FailedLoginTracker
)
from app.core.redis import get_redis
from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.core.config import settings
from app.schemas.auth import (
    UserRegistrationRequest,
    UserRegistrationResponse,
    TokenResponse,
    UserResponse,
    MFATokenRequest,
    MFARequiredResponse
)

router = APIRouter()

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Custom rate limiting dependency that uses FailedLoginTracker
async def progressive_rate_limit(request: Request):
    """
    Progressive rate limiting based on failed login attempts.
    Applies stricter limits to IPs with recent failures.
    """
    if not settings.auth_rate_limit_enabled:
        return

    client_ip = request.client.host if request.client else "unknown"
    redis_client = await get_redis()
    
    # Check if IP should be rate limited based on failed attempts
    is_limited = await FailedLoginTracker.is_rate_limited(client_ip, redis_client)
    
    if is_limited:
        failed_count = await FailedLoginTracker.get_failed_attempts(client_ip, redis_client)
        penalty_duration = await FailedLoginTracker.get_penalty_duration(client_ip, redis_client)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again later. ({failed_count} failures)",
            headers={"Retry-After": str(penalty_duration)}
        )


# Helper function for authentication logic
async def _authenticate_user(
    request: Request,
    username: str,
    password: str,
    db: Session,
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
            redis_client = await get_redis()
            await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password
    if not PasswordHasher.verify_password(password, user.password_hash):
        # Record failed login attempt
        if settings.auth_rate_limit_enabled:
            redis_client = await get_redis()
            await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )

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
                redis_client = await get_redis()
                await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Reset failed login attempts on successful authentication
    if settings.auth_rate_limit_enabled:
        redis_client = await get_redis()
        await FailedLoginTracker.reset_failed_attempts(client_ip, redis_client)

    return user, False  # Authentication successful, no MFA required


def _create_token_response(user: User) -> TokenResponse:
    """Create token response for authenticated user."""
    token_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email
    }

    tokens = TokenManager.create_token_pair(token_data)

    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens["token_type"],
        expires_in=tokens["expires_in"],
        user_id=user.id,
        username=user.username
    )


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
        PasswordStrength.validate_password(user_data.password)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {str(e)}"
        )

    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered"
        )

    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    try:
        # Hash the password
        hashed_password = PasswordHasher.hash_password(user_data.password)

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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user"
        )


@router.post("/token", response_model=Union[TokenResponse, MFARequiredResponse],
            dependencies=[
                Depends(RateLimiter(times=settings.auth_login_per_minute, minutes=1)),
                Depends(progressive_rate_limit)
            ])
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
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
        db=db
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
    return _create_token_response(user)


@router.post("/token/mfa", response_model=TokenResponse,
            dependencies=[
                Depends(RateLimiter(times=settings.auth_login_per_minute, minutes=1)),
                Depends(progressive_rate_limit)
            ])
async def verify_mfa_token(
    request: Request,
    mfa_data: MFATokenRequest,
    db: Session = Depends(get_db)
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
        mfa_token=mfa_data.mfa_token
    )

    # Check if MFA was actually enabled for this user
    mfa_secret = db.query(MFASecret).filter(
        MFASecret.user_id == user.id,
        MFASecret.is_enabled == True
    ).first()

    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not enabled for this account"
        )

    # Authentication successful, return tokens
    return _create_token_response(user)


@router.post("/refresh", response_model=TokenResponse,
            dependencies=[Depends(RateLimiter(times=settings.auth_token_refresh_per_hour, hours=1))])
async def refresh_access_token(
    request: Request,
    refresh_token: str,
    db: Session = Depends(get_db)
):
    """
    Refresh an access token using a valid refresh token.

    - Validates refresh token
    - Issues new access token
    - Maintains user session
    """
    # Validate refresh token
    payload = TokenManager.verify_token(refresh_token, "refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload.get("sub"))
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    # Verify user still exists and is active
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated"
        )

    # Create new token pair
    token_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email
    }

    tokens = TokenManager.create_token_pair(token_data)

    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens["token_type"],
        expires_in=tokens["expires_in"],
        user_id=user.id,
        username=user.username
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Get current authenticated user information.

    - Validates access token
    - Returns user profile data
    """
    # Validate access token
    payload = TokenManager.verify_token(token, "access")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload.get("sub"))
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    # Get user data
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated"
        )

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None
    )
