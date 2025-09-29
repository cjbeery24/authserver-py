import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
import pyotp
import logging
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json

from app.core.config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RSAKeyManager:
    """RSA key management for JWT signing and JWKS generation."""
    
    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate RSA private/public key pair.
        
        Args:
            key_size: RSA key size in bits (default: 2048)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Get public key and serialize to PEM format
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    @staticmethod
    def get_signing_key() -> str:
        """
        Get the appropriate signing key based on algorithm.
        
        Returns:
            Signing key (private key for RS256, secret for HS256)
        """
        if settings.jwt_algorithm.startswith('RS'):
            if not settings.jwt_private_key:
                raise ValueError("JWT_PRIVATE_KEY environment variable is required for RS256 algorithm")
            return settings.jwt_private_key
        else:
            # Fall back to HMAC for backward compatibility
            return settings.jwt_secret_key
    
    @staticmethod
    def get_verification_key() -> str:
        """
        Get the appropriate verification key based on algorithm.
        
        Returns:
            Verification key (public key for RS256, secret for HS256)
        """
        if settings.jwt_algorithm.startswith('RS'):
            if not settings.jwt_public_key:
                raise ValueError("JWT_PUBLIC_KEY environment variable is required for RS256 algorithm")
            return settings.jwt_public_key
        else:
            # Fall back to HMAC for backward compatibility
            return settings.jwt_secret_key
    
    @staticmethod
    def public_key_to_jwk(public_key_pem: str, key_id: str) -> Dict[str, Any]:
        """
        Convert RSA public key PEM to JWK (JSON Web Key) format.
        
        Args:
            public_key_pem: Public key in PEM format
            key_id: Key identifier
            
        Returns:
            JWK dictionary
        """
        # Load public key from PEM
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Extract RSA public key numbers
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format
        def int_to_base64url(value: int) -> str:
            # Convert integer to bytes
            byte_length = (value.bit_length() + 7) // 8
            value_bytes = value.to_bytes(byte_length, 'big')
            # Base64url encode
            return base64.urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')
        
        return {
            "kty": "RSA",           # Key type
            "use": "sig",           # Key use (signature)
            "alg": "RS256",         # Algorithm
            "kid": key_id,          # Key ID
            "n": int_to_base64url(public_numbers.n),  # Modulus
            "e": int_to_base64url(public_numbers.e)   # Exponent
        }
    
    @staticmethod
    def get_jwks() -> Dict[str, Any]:
        """
        Generate JWKS (JSON Web Key Set) for the current public key.
        
        Returns:
            JWKS dictionary
        """
        if not settings.jwt_public_key:
            raise ValueError("JWT_PUBLIC_KEY environment variable is required for JWKS generation")
        
        jwk = RSAKeyManager.public_key_to_jwk(settings.jwt_public_key, settings.jwt_key_id)
        
        return {
            "keys": [jwk]
        }


class TokenManager:
    """Utilities for JWT token creation and verification."""

    @staticmethod
    def create_id_token(user_data: dict, client_id: str, nonce: str = None, expires_delta: Optional[timedelta] = None, auth_time: Optional[datetime] = None) -> str:
        """
        Create an OpenID Connect ID token.
        
        Args:
            user_data: Dictionary containing user information (sub, email, etc.)
            client_id: OAuth2 client ID (audience)
            nonce: Optional nonce value from authorization request
            expires_delta: Custom expiration time
            auth_time: Time when user authentication occurred
            
        Returns:
            Signed JWT ID token
        """
        now = datetime.now(timezone.utc)
        
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
        
        # Standard OpenID Connect claims
        to_encode = {
            "iss": settings.oidc_issuer_url,  # Issuer
            "sub": str(user_data.get("sub", user_data.get("user_id"))),  # Subject (user ID)
            "aud": client_id,  # Audience (client ID)
            "exp": expire,  # Expiration time
            "iat": now,  # Issued at
            "type": "id_token"  # Token type for our internal use
        }
        
        # Add nonce if provided (CSRF protection)
        if nonce:
            to_encode["nonce"] = nonce
            
        # Add auth_time if provided
        if auth_time:
            to_encode["auth_time"] = int(auth_time.timestamp())
        else:
            to_encode["auth_time"] = int(now.timestamp())
            
        # Add optional user claims based on available user data and scopes
        if "email" in user_data and user_data["email"]:
            to_encode["email"] = user_data["email"]
            to_encode["email_verified"] = user_data.get("email_verified", True)
            
        if "name" in user_data and user_data["name"]:
            to_encode["name"] = user_data["name"]
            
        if "username" in user_data and user_data["username"]:
            to_encode["preferred_username"] = user_data["username"]
            
        if "given_name" in user_data and user_data["given_name"]:
            to_encode["given_name"] = user_data["given_name"]
            
        if "family_name" in user_data and user_data["family_name"]:
            to_encode["family_name"] = user_data["family_name"]
            
        # Add Key ID to header for JWKS support
        headers = {}
        if settings.jwt_algorithm.startswith('RS'):
            headers["kid"] = settings.jwt_key_id
        
        # Generate JWT ID token using appropriate key
        signing_key = RSAKeyManager.get_signing_key()
        encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=settings.jwt_algorithm, headers=headers)
        return encoded_jwt

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, include_jti: bool = True) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)

        to_encode.update({"exp": expire, "type": "access"})

        # Include JTI (JWT ID) for token tracking if requested
        if include_jti:
            jti = secrets.token_hex(16)  # Generate unique JTI
            to_encode.update({"jti": jti})

        # Add Key ID to header for JWKS support
        headers = {}
        if settings.jwt_algorithm.startswith('RS'):
            headers["kid"] = settings.jwt_key_id

        # Use appropriate signing key
        signing_key = RSAKeyManager.get_signing_key()
        encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=settings.jwt_algorithm, headers=headers)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None, include_jti: bool = True) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)

        to_encode.update({"exp": expire, "type": "refresh"})

        # Include JTI (JWT ID) for token tracking if requested
        if include_jti:
            jti = secrets.token_hex(16)  # Generate unique JTI
            to_encode.update({"jti": jti})

        # Add Key ID to header for JWKS support
        headers = {}
        if settings.jwt_algorithm.startswith('RS'):
            headers["kid"] = settings.jwt_key_id

        # Use appropriate signing key
        signing_key = RSAKeyManager.get_signing_key()
        encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=settings.jwt_algorithm, headers=headers)
        return encoded_jwt

    @staticmethod
    async def verify_id_token(token: str, client_id: str = None, nonce: str = None, redis_client = None) -> Optional[dict]:
        """
        Verify and decode an OpenID Connect ID token.
        
        Args:
            token: JWT ID token to verify
            client_id: Expected client ID (audience)
            nonce: Expected nonce value
            redis_client: Redis client for blacklist checking
            
        Returns:
            Decoded token payload if valid, None otherwise
        """
        try:
            # Use appropriate verification key
            verification_key = RSAKeyManager.get_verification_key()
            payload = jwt.decode(token, verification_key, algorithms=[settings.jwt_algorithm])
            
            # Verify token type
            if payload.get("type") != "id_token":
                logger.warning("Token verification failed: not an ID token")
                return None
                
            # Verify issuer
            if payload.get("iss") != settings.oidc_issuer_url:
                logger.warning(f"ID token verification failed: invalid issuer {payload.get('iss')}")
                return None
                
            # Verify audience (client_id) if provided
            if client_id and payload.get("aud") != client_id:
                logger.warning(f"ID token verification failed: invalid audience {payload.get('aud')}, expected {client_id}")
                return None
                
            # Verify nonce if provided
            if nonce and payload.get("nonce") != nonce:
                logger.warning("ID token verification failed: nonce mismatch")
                return None
                
            # Check if token is blacklisted (if redis client is provided)
            if redis_client:
                if await TokenBlacklist.is_token_blacklisted(token, redis_client):
                    jti = payload.get("jti", "unknown")
                    logger.warning(f"Attempt to use blacklisted ID token with JTI: {jti}")
                    return None

            return payload
        except JWTError as e:
            logger.warning(f"ID token verification failed: {e}")
            return None

    @staticmethod
    async def verify_token(token: str, token_type: str = "access", redis_client = None) -> Optional[dict]:
        """Verify and decode a JWT token."""
        try:
            # Use appropriate verification key
            verification_key = RSAKeyManager.get_verification_key()
            payload = jwt.decode(token, verification_key, algorithms=[settings.jwt_algorithm])
            if payload.get("type") != token_type:
                return None

            # Check if token is blacklisted by JTI (if redis client is provided)
            if redis_client:
                if await TokenBlacklist.is_token_blacklisted(token, redis_client):
                    jti = payload.get("jti", "unknown")
                    logger.warning(f"Attempt to use blacklisted token with JTI: {jti}")
                    return None

            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None

    @staticmethod
    def decode_token(token: str) -> Optional[dict]:
        """Decode a JWT token without verification (for introspection)."""
        try:
            # Decode without verification for token introspection
            payload = jwt.decode(token, key="", options={"verify_signature": False, "verify_exp": False})
            return payload
        except JWTError:
            return None

    @staticmethod
    def is_token_expired(token: str) -> bool:
        """Check if a JWT token is expired."""
        try:
            # Use appropriate verification key
            verification_key = RSAKeyManager.get_verification_key()
            payload = jwt.decode(token, verification_key, algorithms=[settings.jwt_algorithm])
            exp = payload.get("exp")
            if not exp:
                return False
            return datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc)
        except JWTError:
            return True

    @staticmethod
    def get_token_expiration(token: str) -> Optional[datetime]:
        """Get token expiration time."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            exp = payload.get("exp")
            if exp:
                return datetime.fromtimestamp(exp, tz=timezone.utc)
            return None
        except JWTError:
            return None

    @staticmethod
    async def refresh_access_token(refresh_token: str, redis_client = None) -> Optional[str]:
        """Create a new access token from a valid refresh token."""
        payload = await TokenManager.verify_token(refresh_token, "refresh", redis_client)
        if not payload:
            return None

        # Remove token-specific claims
        user_data = {k: v for k, v in payload.items() if k not in ["exp", "type", "iat", "nbf"]}
        return TokenManager.create_access_token(user_data)

    @staticmethod
    def create_token_pair(user_data: dict) -> dict:
        """Create both access and refresh tokens for a user."""
        access_token = TokenManager.create_access_token(user_data)
        refresh_token = TokenManager.create_refresh_token(user_data)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,  # seconds
        }

    @staticmethod
    def create_oauth2_token_response(user_data: dict, client_id: str, scopes: List[str], nonce: str = None, auth_time: Optional[datetime] = None) -> dict:
        """
        Create OAuth2/OIDC token response with ID token when openid scope is present.
        
        Args:
            user_data: Dictionary containing user information
            client_id: OAuth2 client ID
            scopes: List of granted scopes
            nonce: Optional nonce from authorization request
            auth_time: Time when user authentication occurred
            
        Returns:
            Token response dictionary
        """
        # Create standard access and refresh tokens
        access_token = TokenManager.create_access_token(user_data)
        refresh_token = TokenManager.create_refresh_token(user_data)
        
        response = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,  # seconds
            "scope": " ".join(scopes) if scopes else ""
        }
        
        # Add ID token if openid scope is present
        if "openid" in scopes:
            id_token = TokenManager.create_id_token(
                user_data=user_data,
                client_id=client_id,
                nonce=nonce,
                auth_time=auth_time
            )
            response["id_token"] = id_token
            
        return response

    @staticmethod
    def get_token_metadata(token: str) -> Optional[dict]:
        """Get token metadata without full payload."""
        payload = TokenManager.decode_token(token)
        if not payload:
            return None

        return {
            "user_id": payload.get("sub"),
            "token_type": payload.get("type"),
            "issued_at": payload.get("iat"),
            "expires_at": payload.get("exp"),
            "is_expired": TokenManager.is_token_expired(token),
        }


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


class PasswordHasher:
    """Password hashing utilities using bcrypt."""

    @staticmethod
    def hash_password(password: str, username: str = None) -> str:
        """Hash a password with strength validation."""
        is_valid, message = PasswordStrength.validate_password(password, username)
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


class ClientSecretHasher:
    """Client secret hashing utilities using bcrypt (no strength validation)."""

    @staticmethod
    def hash_secret(secret: str) -> str:
        """Hash a client secret without validation."""
        return pwd_context.hash(secret)

    @staticmethod
    def verify_secret(plain_secret: str, hashed_secret: str) -> bool:
        """Verify a client secret against its hash."""
        return pwd_context.verify(plain_secret, hashed_secret)
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
    def get_token_jti(token: str) -> Optional[str]:
        """Extract JTI (JWT ID) from a token."""
        payload = TokenManager.decode_token(token)
        if payload:
            return payload.get("jti")
        return None

    @staticmethod
    def get_token_expiry(token: str) -> Optional[datetime]:
        """Get token expiry time from the token itself."""
        payload = TokenManager.decode_token(token)
        if payload and payload.get("exp"):
            return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        return None

    @staticmethod
    def store_user_tokens(
        db_session,
        user_id: int,
        access_token: str,
        refresh_token: str,
        ip_address: str = None,
        user_agent: str = None
    ):
        """Store issued tokens in the database for tracking."""
        from app.models.user_token import UserToken

        access_jti = TokenManager.get_token_jti(access_token)
        refresh_jti = TokenManager.get_token_jti(refresh_token)

        access_expiry = TokenManager.get_token_expiry(access_token)
        refresh_expiry = TokenManager.get_token_expiry(refresh_token)

        # Store access token record
        if access_jti and access_expiry:
            access_token_record = UserToken.create_token_record(
                user_id=user_id,
                token_jti=access_jti,
                token_type="access",
                expires_at=access_expiry,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db_session.add(access_token_record)

        # Store refresh token record
        if refresh_jti and refresh_expiry:
            refresh_token_record = UserToken.create_token_record(
                user_id=user_id,
                token_jti=refresh_jti,
                token_type="refresh",
                expires_at=refresh_expiry,
                ip_address=ip_address,
                user_agent=user_agent
            )
            db_session.add(refresh_token_record)

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


class FailedLoginTracker:
    """Track failed login attempts for progressive rate limiting."""

    @staticmethod
    def get_penalty_key(ip_address: str) -> str:
        """Generate Redis key for failed login tracking."""
        return f"failed_login_penalty:{ip_address}"

    @staticmethod
    async def record_failed_attempt(ip_address: str, redis_client) -> int:
        """Record a failed login attempt and return current count."""
        key = FailedLoginTracker.get_penalty_key(ip_address)
        # Increment counter and set expiry
        count = await redis_client.incr(key)
        await redis_client.expire(key, settings.auth_failed_login_penalty_minutes * 60)  # Convert to seconds
        return count

    @staticmethod
    async def get_failed_attempts(ip_address: str, redis_client) -> int:
        """Get number of failed attempts for an IP."""
        key = FailedLoginTracker.get_penalty_key(ip_address)
        count = await redis_client.get(key)
        return int(count) if count else 0

    @staticmethod
    async def reset_failed_attempts(ip_address: str, redis_client):
        """Reset failed attempts counter after successful login."""
        key = FailedLoginTracker.get_penalty_key(ip_address)
        await redis_client.delete(key)

    @staticmethod
    async def is_rate_limited(ip_address: str, redis_client) -> bool:
        """Check if IP should be rate limited based on failed attempts."""
        failed_count = await FailedLoginTracker.get_failed_attempts(ip_address, redis_client)

        # Progressive blocking thresholds based on failed attempts
        if failed_count >= 10:
            return True  # Block after 10+ failures
        elif failed_count >= 5:
            return True  # Block after 5+ failures  
        elif failed_count >= 3:
            # Block after 3+ failures but with shorter penalty
            return True

        return False  # Allow requests with < 3 failures

    @staticmethod
    async def get_penalty_duration(ip_address: str, redis_client) -> int:
        """Get penalty duration in seconds based on failed attempts."""
        failed_count = await FailedLoginTracker.get_failed_attempts(ip_address, redis_client)
        
        if failed_count >= 10:
            return settings.auth_failed_login_penalty_minutes * 60 * 4  # 4x penalty
        elif failed_count >= 5:
            return settings.auth_failed_login_penalty_minutes * 60 * 2  # 2x penalty
        elif failed_count >= 3:
            return settings.auth_failed_login_penalty_minutes * 60  # Normal penalty
        
        return 0


class FailedRefreshTracker:
    """Track failed refresh token attempts for progressive rate limiting."""

    @staticmethod
    def get_penalty_key(ip_address: str) -> str:
        """Generate Redis key for failed refresh tracking."""
        return f"failed_refresh_penalty:{ip_address}"

    @staticmethod
    async def record_failed_attempt(ip_address: str, redis_client) -> int:
        """Record a failed refresh attempt and return current count."""
        key = FailedRefreshTracker.get_penalty_key(ip_address)
        # Increment counter and set expiry
        count = await redis_client.incr(key)
        await redis_client.expire(key, settings.auth_failed_login_penalty_minutes * 60)  # Same as login penalty
        return count

    @staticmethod
    async def get_failed_attempts(ip_address: str, redis_client) -> int:
        """Get number of failed refresh attempts for an IP."""
        key = FailedRefreshTracker.get_penalty_key(ip_address)
        count = await redis_client.get(key)
        return int(count) if count else 0

    @staticmethod
    async def reset_failed_attempts(ip_address: str, redis_client):
        """Reset failed refresh attempts counter after successful refresh."""
        key = FailedRefreshTracker.get_penalty_key(ip_address)
        await redis_client.delete(key)

    @staticmethod
    async def is_rate_limited(ip_address: str, redis_client) -> bool:
        """Check if IP should be rate limited based on failed refresh attempts."""
        failed_count = await FailedRefreshTracker.get_failed_attempts(ip_address, redis_client)

        # Progressive blocking thresholds (more aggressive than login)
        if failed_count >= 5:
            return True  # Block after 5+ failures (stricter than login)
        elif failed_count >= 3:
            return True  # Block after 3+ failures

        return False  # Allow requests with < 3 failures

    @staticmethod
    async def get_penalty_duration(ip_address: str, redis_client) -> int:
        """Get penalty duration in seconds based on failed refresh attempts."""
        failed_count = await FailedRefreshTracker.get_failed_attempts(ip_address, redis_client)
        
        if failed_count >= 5:
            return settings.auth_failed_login_penalty_minutes * 60 * 3  # 3x penalty
        elif failed_count >= 3:
            return settings.auth_failed_login_penalty_minutes * 60 * 2  # 2x penalty
        
        return 0


class SecureTokenHasher:
    """Secure hashing utilities for tokens and backup codes."""

    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash a token using SHA-256 with salt for secure storage.

        Args:
            token: The token to hash

        Returns:
            str: Hexadecimal hash of the token
        """
        if not token:
            raise ValueError("Token cannot be empty")

        # Use the configured security salt
        salt = settings.security_salt
        if not salt:
            raise ValueError("Security salt is not configured")

        # Combine salt and token
        salt_bytes = salt.encode('utf-8')
        token_bytes = token.encode('utf-8')
        salted_token = salt_bytes + token_bytes

        # Hash using SHA-256
        hash_obj = hashlib.sha256(salted_token)
        return hash_obj.hexdigest()

    @staticmethod
    def verify_token_hash(token: str, stored_hash: str) -> bool:
        """
        Verify a token against its stored hash.

        Args:
            token: The plain token to verify
            stored_hash: The stored hash to compare against

        Returns:
            bool: True if token matches the hash
        """
        if not token or not stored_hash:
            return False

        computed_hash = SecureTokenHasher.hash_token(token)
        return computed_hash == stored_hash

    @staticmethod
    def hash_backup_codes(codes: list) -> dict:
        """
        Hash a list of backup codes.

        Args:
            codes: List of plain backup codes

        Returns:
            dict: Dictionary mapping hashed codes to their original values (for validation)
        """
        if not codes:
            return {}

        hashed_codes = {}
        for code in codes:
            if not code:
                continue
            # Hash each code and map it to the original for validation
            hashed_codes[SecureTokenHasher.hash_token(code)] = code

        return hashed_codes

    @staticmethod
    def verify_backup_code_hash(code: str, hashed_codes: dict) -> tuple[bool, str]:
        """
        Verify a backup code against stored hashes.

        Args:
            code: The plain backup code to verify
            hashed_codes: Dictionary of hashed codes mapping to original codes

        Returns:
            tuple: (is_valid, original_code) - original_code is empty if invalid
        """
        if not code or not hashed_codes:
            return False, ""

        computed_hash = SecureTokenHasher.hash_token(code)
        if computed_hash in hashed_codes:
            return True, hashed_codes[computed_hash]

        return False, ""

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """
        Generate a cryptographically secure salt.

        Args:
            length: Length of the salt in bytes

        Returns:
            str: Hexadecimal representation of the salt
        """
        salt_bytes = secrets.token_bytes(length)
        return salt_bytes.hex()


class TokenBlacklist:
    """Token blacklist for secure logout and token invalidation using JTI-only storage."""

    @staticmethod
    def get_blacklist_key(jti: str) -> str:
        """Generate Redis key for JTI blacklist."""
        return f"token_blacklist_jti:{jti}"

    @staticmethod
    async def blacklist_token(token: str, redis_client, expiry_seconds: int = None) -> bool:
        """
        Add token to blacklist by JTI with expiration.

        Args:
            token: The token to blacklist (JTI will be extracted)
            redis_client: Redis client instance
            expiry_seconds: Custom expiry time, defaults to token's remaining TTL

        Returns:
            bool: True if successfully blacklisted
        """
        # Extract JTI from token
        payload = TokenManager.decode_token(token)
        if not payload or not payload.get("jti"):
            logger.warning("Cannot blacklist token: no JTI found")
            return False

        jti = payload["jti"]
        key = TokenBlacklist.get_blacklist_key(jti)

        if expiry_seconds is None:
            # Get token's remaining TTL from the token itself
            if payload.get("exp"):
                expiry_seconds = int(payload["exp"] - datetime.now(timezone.utc).timestamp())
                # Ensure minimum of 1 second and maximum of 30 days
                expiry_seconds = max(1, min(expiry_seconds, 30 * 24 * 60 * 60))
            else:
                # Fallback to default expiry if no exp claim
                expiry_seconds = 24 * 60 * 60  # 24 hours

        if expiry_seconds > 0:
            await redis_client.setex(key, expiry_seconds, "blacklisted")
            logger.debug(f"Blacklisted token JTI: {jti} for {expiry_seconds} seconds")
            return True

        return False

    @staticmethod
    async def is_token_blacklisted(token: str, redis_client) -> bool:
        """
        Check if token is blacklisted by JTI.

        Args:
            token: Token to check (JTI will be extracted)
            redis_client: Redis client instance

        Returns:
            bool: True if token is blacklisted
        """
        # Extract JTI from token
        payload = TokenManager.decode_token(token)
        if not payload or not payload.get("jti"):
            return False

        jti = payload["jti"]
        return await TokenBlacklist.is_token_blacklisted_by_jti(jti, redis_client)

    @staticmethod
    async def blacklist_token_by_jti(jti: str, redis_client, expiry_seconds: int) -> bool:
        """
        Blacklist a token by its JTI directly.

        Args:
            jti: The JWT ID to blacklist
            redis_client: Redis client instance
            expiry_seconds: Expiry time in seconds

        Returns:
            bool: True if successfully blacklisted
        """
        if not jti:
            return False

        key = TokenBlacklist.get_blacklist_key(jti)
        if expiry_seconds > 0:
            await redis_client.setex(key, expiry_seconds, "blacklisted")
            logger.debug(f"Blacklisted JTI: {jti} for {expiry_seconds} seconds")
            return True
        return False

    @staticmethod
    async def blacklist_all_user_tokens(user_id: int, redis_client, db_session) -> int:
        """
        Blacklist all active tokens for a user by reading from database and blacklisting each.

        Args:
            user_id: User ID whose tokens should be blacklisted
            redis_client: Redis client instance
            db_session: Database session to fetch active tokens

        Returns:
            int: Number of tokens blacklisted
        """
        from app.models.user_token import UserToken
        from sqlalchemy import and_

        # Get all active (non-revoked, non-expired) tokens for the user
        active_tokens = db_session.query(UserToken).filter(
            and_(
                UserToken.user_id == user_id,
                UserToken.is_revoked == False,
                UserToken.expires_at > datetime.now(timezone.utc)
            )
        ).all()

        blacklisted_count = 0
        for token_record in active_tokens:
            # Calculate remaining TTL for this token
            remaining_seconds = int((token_record.expires_at - datetime.now(timezone.utc)).total_seconds())
            if remaining_seconds > 0:
                # Use the new blacklist_token_by_jti method for consistency
                success = await TokenBlacklist.blacklist_token_by_jti(
                    token_record.token_jti, 
                    redis_client, 
                    remaining_seconds
                )
                if success:
                    blacklisted_count += 1

        logger.info(f"Blacklisted {blacklisted_count} tokens for user {user_id}")
        return blacklisted_count

    @staticmethod
    async def is_token_blacklisted_by_jti(jti: str, redis_client) -> bool:
        """
        Check if token is blacklisted by JTI.

        Args:
            jti: JWT ID to check
            redis_client: Redis client instance

        Returns:
            bool: True if token JTI is blacklisted
        """
        if not jti:
            return False
            
        jti_key = f"token_blacklist_jti:{jti}"
        result = await redis_client.get(jti_key)
        return result is not None

    @staticmethod
    async def cleanup_expired_blacklist(redis_client):
        """
        Cleanup expired blacklist entries.
        Redis handles this automatically with EXPIRE, so this is mainly for monitoring.
        """
        # Redis automatically expires keys, so this is just for logging/metrics
        logger.debug("Token blacklist cleanup completed (Redis handles expiration automatically)")


# Enhanced utility functions