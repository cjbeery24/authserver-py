"""
Authentication utilities for the authentication server.

This module provides all authentication-related operations including:
- Password strength validation and hashing
- Multi-factor authentication (TOTP and backup codes)
- MFA session management
- User authentication logic
"""

import secrets
import string
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any
from passlib.context import CryptContext
import pyotp
import json

from app.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordValidationError(Exception):
    """Exception raised when password validation fails."""
    pass


class PasswordStrength:
    """Password strength validation utilities."""

    @staticmethod
    def validate_password(password: str, username: str = None) -> Tuple[bool, str]:
        """Validate password strength according to configured requirements."""
        if len(password) < settings.password_min_length:
            return False, f"Password must be at least {settings.password_min_length} characters long"

        if settings.password_require_uppercase and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if settings.password_require_lowercase and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if settings.password_require_digits and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        if settings.password_require_special_chars and not any(c in settings.special_characters for c in password):
            return False, "Password must contain at least one special character"

        # Additional security checks
        if settings.password_check_common_patterns:
            # Check for sequential characters
            if PasswordStrength._has_sequential_chars(password):
                return False, "Password must not contain sequential characters (e.g., 'abc', '123')"

            # Check for repeated characters
            if PasswordStrength._has_repeated_chars(password):
                return False, "Password must not contain too many repeated characters"

        # Check if password is too similar to username
        if username and PasswordStrength._is_similar_to_username(password, username):
            return False, "Password must not be too similar to your username"

        return True, "Password meets strength requirements"

    @staticmethod
    def _has_sequential_chars(password: str, threshold: int = 3) -> bool:
        """Check for sequential characters (e.g., 'abc', '123', 'xyz')."""
        password_lower = password.lower()

        # Check for sequential letters
        for i in range(len(password_lower) - threshold + 1):
            seq = password_lower[i:i+threshold]
            if len(seq) == threshold:
                # Check if all characters are consecutive in alphabet
                if all(ord(seq[j+1]) - ord(seq[j]) == 1 for j in range(threshold-1)):
                    return True

        # Check for sequential digits
        for i in range(len(password) - threshold + 1):
            seq = password[i:i+threshold]
            if seq.isdigit():
                # Check if digits are consecutive
                if all(int(seq[j+1]) - int(seq[j]) == 1 for j in range(threshold-1)):
                    return True

        return False

    @staticmethod
    def _has_repeated_chars(password: str, threshold: int = 3) -> bool:
        """Check for too many repeated characters."""
        for i in range(len(password) - threshold + 1):
            if all(c == password[i] for c in password[i:i+threshold]):
                return True
        return False

    @staticmethod
    def _is_similar_to_username(password: str, username: str) -> bool:
        """Check if password is too similar to username."""
        if not username or len(username) < 3:
            return False

        password_lower = password.lower()
        username_lower = username.lower()

        # Check if username is contained in password
        if username_lower in password_lower:
            return True

        # Check if password contains significant portion of username
        username_chars = set(username_lower)
        password_chars = set(password_lower)

        # If more than 80% of username characters are in password, it's suspicious
        if len(username_chars.intersection(password_chars)) / len(username_chars) > 0.8:
            return True

        return False

    @staticmethod
    def calculate_strength_score(password: str) -> int:
        """Calculate a password strength score (0-100)."""
        score = 0

        # Length scoring
        if len(password) >= settings.password_min_length:
            score += 20
        if len(password) >= settings.password_strong_length:
            score += 10
        if len(password) >= settings.password_very_strong_length:
            score += 10

        # Character variety scoring
        if any(c.isupper() for c in password):
            score += 15
        if any(c.islower() for c in password):
            score += 15
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in settings.special_characters for c in password):
            score += 15

        # Bonus for additional complexity
        unique_chars = len(set(password))
        if unique_chars >= settings.password_unique_chars_threshold:
            score += 10

        return min(100, score)


class TokenGenerator:
    """Secure token generation utilities."""

    @staticmethod
    def generate_secure_token(length: int = None) -> str:
        """Generate a cryptographically secure random token."""
        if length is None:
            length = settings.default_token_length
        if length < 1:
            raise ValueError("Token length must be positive")
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_reset_token() -> str:
        """Generate a password reset token."""
        return secrets.token_urlsafe(settings.reset_token_length)

    @staticmethod
    def generate_verification_code(length: int = None) -> str:
        """Generate a numeric verification code."""
        if length is None:
            length = settings.verification_code_length
        if length < 1:
            raise ValueError("Verification code length must be positive")
        return ''.join(secrets.choice(string.digits) for _ in range(length))


class MFAHandler:
    """Multi-factor authentication utilities."""

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """Verify a TOTP token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    @staticmethod
    def generate_totp_uri(secret: str, username: str) -> str:
        """Generate TOTP URI for QR code generation."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=settings.mfa_totp_issuer
        )

    @staticmethod
    def generate_backup_codes(count: int = None) -> List[str]:
        """Generate backup codes for MFA recovery."""
        if count is None:
            count = settings.mfa_backup_codes_count
        if count < 1:
            raise ValueError("Backup code count must be positive")
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(settings.mfa_backup_code_length))
            codes.append(code)
        return codes


class MFASessionManager:
    """MFA session management for temporary authentication sessions."""

    # Session TTL in seconds (5 minutes)
    MFA_SESSION_TTL = 300

    @staticmethod
    def get_session_key(session_token: str) -> str:
        """Generate Redis key for MFA session."""
        return f"mfa_session:{session_token}"

    @staticmethod
    async def create_mfa_session(user_id: int, username: str, client_ip: str, user_agent: str, redis_client) -> str:
        """
        Create a temporary MFA session for user authentication.

        Args:
            user_id: User ID
            username: Username
            client_ip: Client IP address
            user_agent: User agent string
            redis_client: Redis client instance

        Returns:
            Session token string
        """
        # Generate secure session token
        session_token = TokenGenerator.generate_secure_token()

        # Store session data
        session_data = {
            "user_id": user_id,
            "username": username,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        key = MFASessionManager.get_session_key(session_token)

        try:
            # Store session in Redis with expiration
            await redis_client.setex(
                key,
                MFASessionManager.MFA_SESSION_TTL,
                json.dumps(session_data)
            )

            logger.info(f"Created MFA session for user {user_id} from IP {client_ip}")
            return session_token

        except Exception as e:
            logger.error(f"Failed to create MFA session for user {user_id}: {e}")
            raise

    @staticmethod
    async def get_mfa_session(session_token: str, redis_client) -> Optional[dict]:
        """
        Retrieve MFA session data.

        Args:
            session_token: Session token
            redis_client: Redis client instance

        Returns:
            Session data dict or None if not found/expired
        """
        key = MFASessionManager.get_session_key(session_token)

        try:
            session_data = await redis_client.get(key)
            if session_data:
                return json.loads(session_data)
            return None

        except Exception as e:
            logger.error(f"Failed to retrieve MFA session {session_token}: {e}")
            return None

    @staticmethod
    async def delete_mfa_session(session_token: str, redis_client) -> bool:
        """
        Delete MFA session (used after successful MFA verification).

        Args:
            session_token: Session token
            redis_client: Redis client instance

        Returns:
            True if deleted successfully
        """
        key = MFASessionManager.get_session_key(session_token)

        try:
            deleted = await redis_client.delete(key)
            if deleted:
                logger.debug(f"Deleted MFA session {session_token}")
            return deleted > 0

        except Exception as e:
            logger.error(f"Failed to delete MFA session {session_token}: {e}")
            return False


class AuthenticationManager:
    """
    Centralized authentication logic for user login and verification.

    This class consolidates authentication logic that was previously duplicated
    across multiple endpoints, providing a single source of truth for:
    - User lookup and validation
    - Password verification
    - MFA checking (TOTP and backup codes)
    - Failed login tracking
    - Account status verification
    """

    @staticmethod
    async def authenticate_user(
        username: str,
        password: str,
        db_session,
        redis_client=None,
        mfa_token: Optional[str] = None,
        client_ip: str = "unknown"
    ) -> Tuple[Optional[Any], bool, Optional[str]]:
        """
        Authenticate a user with username/password and optional MFA.

        This method handles the complete authentication flow including:
        - User lookup
        - Password verification
        - Account status checking
        - MFA validation (if enabled)
        - Failed login tracking

        Args:
            username: Username to authenticate
            password: Password to verify
            db_session: Database session (injected)
            redis_client: Redis client for rate limiting (injected, optional)
            mfa_token: MFA token (TOTP or backup code, optional)
            client_ip: Client IP address for security logging

        Returns:
            Tuple of (User object or None, requires_mfa: bool, error_message: str or None)

        Examples:
            # Without MFA
            user, requires_mfa, error = await AuthenticationManager.authenticate_user(
                "john", "password123", db, redis_client
            )
            if error:
                raise HTTPException(401, error)
            if requires_mfa:
                return {"mfa_required": True}
            # user is authenticated

            # With MFA
            user, requires_mfa, error = await AuthenticationManager.authenticate_user(
                "john", "password123", db, redis_client, mfa_token="123456"
            )
        """
        from app.models.user import User
        from app.models.mfa_secret import MFASecret
        from .audit import FailedLoginTracker

        # Find user by username
        user = db_session.query(User).filter(User.username == username).first()

        if not user:
            # Record failed login attempt
            if redis_client and settings.auth_rate_limit_enabled:
                await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

            return None, False, "Invalid credentials"

        # Verify password
        if not pwd_context.verify(password, user.password_hash):
            # Record failed login attempt
            if redis_client and settings.auth_rate_limit_enabled:
                await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

            return None, False, "Invalid credentials"

        # Check if user account is active
        if not user.is_active:
            return None, False, "Account is deactivated"

        # Check MFA if enabled for user
        mfa_secret = db_session.query(MFASecret).filter(
            MFASecret.user_id == user.id,
            MFASecret.is_enabled == True
        ).first()

        # If MFA is enabled but no token provided, indicate MFA is required
        if mfa_secret and not mfa_token:
            return user, True, None  # MFA required

        # If MFA is enabled and token provided, verify it
        if mfa_secret and mfa_token:
            mfa_valid = await AuthenticationManager._verify_mfa_token(
                mfa_secret,
                mfa_token,
                db_session
            )

            if not mfa_valid:
                # Record failed MFA attempt
                if redis_client and settings.auth_rate_limit_enabled:
                    await FailedLoginTracker.record_failed_attempt(client_ip, redis_client)

                return None, False, "Invalid MFA token"

        # Reset failed login attempts on successful authentication
        if redis_client and settings.auth_rate_limit_enabled:
            await FailedLoginTracker.reset_failed_attempts(client_ip, redis_client)

        # Authentication successful
        return user, False, None

    @staticmethod
    async def _verify_mfa_token(mfa_secret, mfa_token: str, db_session) -> bool:
        """
        Verify MFA token (TOTP or backup code).

        Args:
            mfa_secret: MFASecret model instance
            mfa_token: Token to verify
            db_session: Database session for backup code consumption

        Returns:
            True if valid, False otherwise
        """
        # Try TOTP verification first
        if MFAHandler.verify_totp(mfa_secret.secret, mfa_token):
            return True

        # Try backup code verification
        if mfa_secret.validate_backup_code(mfa_token):
            db_session.commit()  # Save backup code consumption
            return True

        return False

    @staticmethod
    def verify_password_only(username: str, password: str, db_session) -> Optional[Any]:
        """
        Verify username and password only (no MFA check).

        Useful for operations that require password confirmation
        but don't need full authentication flow.

        Args:
            username: Username to verify
            password: Password to verify
            db_session: Database session (injected)

        Returns:
            User object if credentials valid, None otherwise

        Example:
            user = AuthenticationManager.verify_password_only("john", "pass", db)
            if not user:
                raise HTTPException(401, "Invalid credentials")
        """
        from app.models.user import User

        # Find user
        user = db_session.query(User).filter(User.username == username).first()

        if not user:
            return None

        # Verify password
        if not pwd_context.verify(password, user.password_hash):
            return None

        # Check if active
        if not user.is_active:
            return None

        return user

    @staticmethod
    def verify_user_password(user, password: str) -> bool:
        """
        Verify a user's password.

        Simpler method for when you already have the user object.

        Args:
            user: User object
            password: Password to verify

        Returns:
            True if password is valid

        Example:
            if not AuthenticationManager.verify_user_password(current_user, password):
                raise HTTPException(400, "Invalid password")
        """
        return pwd_context.verify(password, user.password_hash)

    @staticmethod
    def is_user_active(user) -> bool:
        """
        Check if user account is active.

        Args:
            user: User object

        Returns:
            True if active
        """
        return bool(user and user.is_active)

