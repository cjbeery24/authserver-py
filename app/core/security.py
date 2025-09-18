import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from passlib.context import CryptContext
from jose import JWTError, jwt
import pyotp
import logging
import hashlib
import base64

from app.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenManager:
    """Utilities for JWT token creation and verification."""

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)

        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)

        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            if payload.get("type") != token_type:
                return None
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None


class PasswordValidationError(Exception):
    """Exception raised when password validation fails."""
    pass


class PasswordStrength:
    """Password strength validation utilities."""

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
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

        return True, "Password meets strength requirements"

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


class PasswordHasher:
    """Password hashing utilities using bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password with strength validation."""
        is_valid, message = PasswordStrength.validate_password(password)
        if not is_valid:
            raise PasswordValidationError(message)
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """Check if password hash needs to be updated."""
        return pwd_context.needs_update(hashed_password)


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


class PKCEHandler:
    """PKCE utilities for OAuth 2.0."""

    @staticmethod
    def generate_code_verifier(length: int = None) -> str:
        """Generate PKCE code verifier."""
        if length is None:
            length = secrets.randbelow(
                settings.pkce_code_verifier_max_length - settings.pkce_code_verifier_min_length + 1
            ) + settings.pkce_code_verifier_min_length
        if length < settings.pkce_code_verifier_min_length or length > settings.pkce_code_verifier_max_length:
            raise ValueError(f"Code verifier length must be between {settings.pkce_code_verifier_min_length} and {settings.pkce_code_verifier_max_length}")
        return secrets.token_urlsafe(length)[:length]

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Generate PKCE code challenge from verifier."""
        sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
        return code_challenge


class SecurityAudit:
    """Security auditing utilities."""

    @staticmethod
    def sanitize_input(input_string: str, max_length: int = None) -> str:
        """Sanitize user input to prevent injection attacks."""
        if not input_string:
            return ""
        max_length = max_length or settings.max_input_length
        sanitized = "".join(c for c in input_string if c.isprintable())
        return sanitized[:max_length]

    @staticmethod
    def is_suspicious_activity(ip_address: str, user_agent: str,
                             recent_attempts: int, time_window_minutes: int = None) -> bool:
        """Check if activity looks suspicious (e.g., brute force attempts)."""
        time_window_minutes = time_window_minutes or settings.suspicious_activity_time_window
        suspicious_indicators = []
        if recent_attempts > settings.max_failed_attempts:
            suspicious_indicators.append("too_many_attempts")
        if not user_agent or len(user_agent) < settings.min_user_agent_length:
            suspicious_indicators.append("suspicious_user_agent")
        if ip_address in settings.suspicious_ips:
            suspicious_indicators.append("suspicious_ip")
        return len(suspicious_indicators) > 0

    @staticmethod
    def get_rate_limit_key(identifier: str, action: str, window: str = "minute") -> str:
        """Generate rate limit key for Redis."""
        if window == "minute":
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        elif window == "hour":
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        elif window == "day":
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        else:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        return f"rate_limit:{identifier}:{action}:{window}:{timestamp}"

    @staticmethod
    def get_security_headers() -> dict[str, str]:
        """Get security headers for responses."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains" if not settings.debug else "",
        }