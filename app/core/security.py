"""
Security utilities for authentication and authorization.
"""

import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Union
from passlib.context import CryptContext
from jose import JWTError, jwt
import pyotp
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.jwt_refresh_token_expire_days)
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt

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

# Password utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength according to configured requirements."""
    if len(password) < settings.password_min_length:
        return False, f"Password must be at least {settings.password_min_length} characters long"
    
    if settings.password_require_uppercase and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if settings.password_require_lowercase and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if settings.password_require_digits and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    if settings.password_require_special_chars and not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets strength requirements"

# MFA utilities
def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()

def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def generate_totp_uri(secret: str, username: str) -> str:
    """Generate TOTP URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=username,
        issuer_name=settings.mfa_totp_issuer
    )

def generate_backup_codes(count: int = None) -> list[str]:
    """Generate backup codes for MFA recovery."""
    if count is None:
        count = settings.mfa_backup_codes_count
    
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric codes
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        codes.append(code)
    
    return codes

# Random token generation
def generate_random_token(length: int = 32) -> str:
    """Generate a random token of specified length."""
    return secrets.token_urlsafe(length)

def generate_random_string(length: int = 16) -> str:
    """Generate a random alphanumeric string."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# PKCE utilities for OAuth 2.0
def generate_code_verifier(length: int = None) -> str:
    """Generate PKCE code verifier."""
    if length is None:
        length = secrets.randbelow(
            settings.pkce_code_verifier_max_length - settings.pkce_code_verifier_min_length + 1
        ) + settings.pkce_code_verifier_min_length
    
    return secrets.token_urlsafe(length)[:length]

def generate_code_challenge(code_verifier: str) -> str:
    """Generate PKCE code challenge from verifier."""
    import hashlib
    import base64
    
    sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
    return code_challenge

# Rate limiting utilities
def get_rate_limit_key(identifier: str, action: str, window: str = "minute") -> str:
    """Generate rate limit key for Redis."""
    if window == "minute":
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M")
    elif window == "hour":
        timestamp = datetime.utcnow().strftime("%Y%m%d%H")
    elif window == "day":
        timestamp = datetime.utcnow().strftime("%Y%m%d")
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M")
    
    return f"rate_limit:{identifier}:{action}:{window}:{timestamp}"

# Security headers
def get_security_headers() -> dict[str, str]:
    """Get security headers for responses."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains" if not settings.debug else "",
    }
