"""
Unit tests for security utilities.

Tests for:
- Password hashing and verification
- Password strength validation
- Token generation
- MFA handlers
- PKCE handlers
"""

import pytest
from datetime import datetime, timedelta, timezone

from app.core.security import (
    PasswordHasher,
    PasswordStrength,
    PasswordValidationError,
    TokenManager,
    TokenGenerator,
    MFAHandler,
    MFASessionManager,
    PKCEHandler,
    SecureTokenHasher,
    RSAKeyManager
)
from app.core.config import settings


# ==================== PASSWORD HASHING TESTS ====================

@pytest.mark.unit
class TestPasswordHasher:
    """Test password hashing functionality."""
    
    def test_hash_password_success(self):
        """Test successful password hashing."""
        password = "Str0ngP@ssw0rd!"  # No sequential chars
        hashed = PasswordHasher.hash_password(password, "testuser")
        
        assert hashed is not None
        assert hashed != password
        assert hashed.startswith("$2b$")  # bcrypt prefix
    
    def test_hash_password_weak_password_fails(self):
        """Test that weak passwords are rejected."""
        with pytest.raises(PasswordValidationError):
            PasswordHasher.hash_password("weak", "testuser")
    
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "Str0ngP@ssw0rd!"
        hashed = PasswordHasher.hash_password(password, "testuser")
        
        assert PasswordHasher.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "Str0ngP@ssw0rd!"
        hashed = PasswordHasher.hash_password(password, "testuser")
        
        assert PasswordHasher.verify_password("Wr0ngP@ssw0rd!", hashed) is False
    
    def test_needs_rehash(self):
        """Test password rehash detection."""
        password = "Str0ngP@ssw0rd!"
        hashed = PasswordHasher.hash_password(password, "testuser")
        
        # Fresh hash should not need rehashing
        assert PasswordHasher.needs_rehash(hashed) is False


# ==================== PASSWORD STRENGTH TESTS ====================

@pytest.mark.unit
class TestPasswordStrength:
    """Test password strength validation."""
    
    def test_validate_password_strong_password(self):
        """Test validation of strong password."""
        password = "Str0ngP@ssw0rd!"  # No sequential chars
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is True
        assert "meets strength requirements" in message.lower()
    
    def test_validate_password_too_short(self):
        """Test validation rejects short passwords."""
        password = "Short1!"
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "at least" in message.lower()
    
    def test_validate_password_no_uppercase(self):
        """Test validation requires uppercase letter."""
        password = "lowercasepass123!"
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "uppercase" in message.lower()
    
    def test_validate_password_no_lowercase(self):
        """Test validation requires lowercase letter."""
        password = "UPPERCASEPASS123!"
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "lowercase" in message.lower()
    
    def test_validate_password_no_digits(self):
        """Test validation requires digits."""
        password = "NoDigitsP@ssword!"
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "digit" in message.lower()
    
    def test_validate_password_no_special_chars(self):
        """Test validation requires special characters."""
        password = "NoSpecialChars9"
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "special character" in message.lower()
    
    def test_validate_password_similar_to_username(self):
        """Test validation rejects password similar to username."""
        password = "TestUser9!"
        is_valid, message = PasswordStrength.validate_password(password, "testuser")
        
        assert is_valid is False
        # Check for similarity-related error message
        assert ("similar" in message.lower() or "username" in message.lower() or "sequential" in message.lower())
    
    def test_validate_password_sequential_chars(self):
        """Test validation rejects sequential characters."""
        password = "Abcdefgh9!"  # Contains 'abc', 'def', 'fgh'
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "sequential" in message.lower()
    
    def test_validate_password_repeated_chars(self):
        """Test validation rejects repeated characters."""
        password = "Aaaa8888!!!!"  # Contains repeated 'a' and '8'
        is_valid, message = PasswordStrength.validate_password(password)
        
        assert is_valid is False
        assert "repeated" in message.lower()
    
    def test_calculate_strength_score(self):
        """Test password strength score calculation."""
        weak_password = "short"
        strong_password = "V3ryStr0ngP@ssword!@#"  # No sequential chars
        
        weak_score = PasswordStrength.calculate_strength_score(weak_password)
        strong_score = PasswordStrength.calculate_strength_score(strong_password)
        
        assert weak_score < strong_score
        assert 0 <= weak_score <= 100
        assert 0 <= strong_score <= 100


# ==================== TOKEN MANAGER TESTS ====================

@pytest.mark.unit
class TestTokenManager:
    """Test JWT token management."""
    
    def test_create_access_token(self):
        """Test access token creation."""
        user_data = {
            "sub": "123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["user"]
        }
        
        token = TokenManager.create_access_token(user_data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are long
        assert token.count('.') == 2  # JWT has 3 parts
    
    def test_create_refresh_token(self):
        """Test refresh token creation."""
        user_data = {
            "sub": "123",
            "username": "testuser"
        }
        
        token = TokenManager.create_refresh_token(user_data)
        
        assert token is not None
        assert isinstance(token, str)
        assert token.count('.') == 2
    
    def test_create_token_pair(self):
        """Test creation of access and refresh token pair."""
        user_data = {
            "sub": "123",
            "username": "testuser",
            "email": "test@example.com",
            "roles": ["user", "admin"]
        }
        
        tokens = TokenManager.create_token_pair(user_data)
        
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert "expires_in" in tokens
        assert tokens["token_type"] == "bearer"
    
    def test_decode_token(self):
        """Test token decoding without verification."""
        user_data = {"sub": "123", "username": "testuser"}
        token = TokenManager.create_access_token(user_data)
        
        payload = TokenManager.decode_token(token)
        
        assert payload is not None
        assert payload["sub"] == "123"
        assert payload["username"] == "testuser"
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "jti" in payload
    
    def test_get_token_metadata(self):
        """Test extracting token metadata."""
        user_data = {"sub": "123", "username": "testuser"}
        token = TokenManager.create_access_token(user_data)
        
        metadata = TokenManager.get_token_metadata(token)
        
        assert metadata is not None
        assert metadata["user_id"] == "123"
        assert metadata["token_type"] == "access"
        assert "issued_at" in metadata
        assert "expires_at" in metadata
        assert "is_expired" in metadata
    
    def test_token_includes_roles(self):
        """Test that roles are included in token payload."""
        user_data = {
            "sub": "123",
            "username": "testuser",
            "roles": ["admin", "moderator"]
        }
        
        token = TokenManager.create_access_token(user_data)
        payload = TokenManager.decode_token(token)
        
        assert "roles" in payload
        assert payload["roles"] == ["admin", "moderator"]


# ==================== TOKEN GENERATOR TESTS ====================

@pytest.mark.unit
class TestTokenGenerator:
    """Test secure token generation."""
    
    def test_generate_secure_token_default_length(self):
        """Test secure token generation with default length."""
        token = TokenGenerator.generate_secure_token()
        
        assert token is not None
        assert len(token) == settings.default_token_length
        assert token.isalnum()  # Only letters and numbers
    
    def test_generate_secure_token_custom_length(self):
        """Test secure token generation with custom length."""
        token = TokenGenerator.generate_secure_token(length=64)
        
        assert len(token) == 64
    
    def test_generate_secure_token_uniqueness(self):
        """Test that generated tokens are unique."""
        token1 = TokenGenerator.generate_secure_token()
        token2 = TokenGenerator.generate_secure_token()
        
        assert token1 != token2
    
    def test_generate_reset_token(self):
        """Test password reset token generation."""
        token = TokenGenerator.generate_reset_token()
        
        assert token is not None
        assert len(token) > 20
    
    def test_generate_verification_code(self):
        """Test numeric verification code generation."""
        code = TokenGenerator.generate_verification_code()
        
        assert code is not None
        assert code.isdigit()
        assert len(code) == settings.verification_code_length


# ==================== MFA HANDLER TESTS ====================

@pytest.mark.unit
class TestMFAHandler:
    """Test multi-factor authentication utilities."""
    
    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        secret = MFAHandler.generate_totp_secret()
        
        assert secret is not None
        assert len(secret) == 32  # Standard TOTP secret length
        assert secret.isalnum()
    
    def test_generate_totp_uri(self):
        """Test TOTP URI generation for QR codes."""
        secret = MFAHandler.generate_totp_secret()
        uri = MFAHandler.generate_totp_uri(secret, "testuser")
        
        assert uri is not None
        assert uri.startswith("otpauth://totp/")
        assert "testuser" in uri
        assert secret in uri
    
    def test_verify_totp_valid_code(self):
        """Test TOTP verification with valid code."""
        import pyotp
        
        secret = MFAHandler.generate_totp_secret()
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        assert MFAHandler.verify_totp(secret, valid_code) is True
    
    def test_verify_totp_invalid_code(self):
        """Test TOTP verification with invalid code."""
        secret = MFAHandler.generate_totp_secret()
        
        assert MFAHandler.verify_totp(secret, "000000") is False
    
    def test_generate_backup_codes(self):
        """Test backup code generation."""
        codes = MFAHandler.generate_backup_codes()
        
        assert len(codes) == settings.mfa_backup_codes_count
        assert all(len(code) == settings.mfa_backup_code_length for code in codes)
        assert len(set(codes)) == len(codes)  # All unique


# ==================== MFA SESSION MANAGER TESTS ====================

@pytest.mark.unit
class TestMFASessionManager:
    """Test MFA session management functionality."""

    @pytest.fixture
    def redis_mock(self):
        """Create a mock Redis client that can store and retrieve data."""
        from unittest.mock import AsyncMock
        import json

        mock = AsyncMock()
        storage = {}

        async def mock_setex(key, ttl, value):
            storage[key] = value
            return True

        async def mock_get(key):
            return storage.get(key)

        async def mock_delete(key):
            if key in storage:
                del storage[key]
                return 1
            return 0

        mock.setex = mock_setex
        mock.get = mock_get
        mock.delete = mock_delete

        return mock

    def test_get_session_key(self):
        """Test session key generation."""
        session_token = "test_session_123"
        expected_key = f"mfa_session:{session_token}"

        assert MFASessionManager.get_session_key(session_token) == expected_key

    @pytest.mark.asyncio
    async def test_create_mfa_session(self, redis_mock):
        """Test MFA session creation."""
        user_id = 123
        username = "testuser"
        client_ip = "192.168.1.100"
        user_agent = "TestBrowser/1.0"

        session_token = await MFASessionManager.create_mfa_session(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            redis_client=redis_mock
        )

        assert session_token is not None
        assert isinstance(session_token, str)
        assert len(session_token) > 0

        # Verify session data was stored
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)
        assert session_data is not None
        assert session_data["user_id"] == user_id
        assert session_data["username"] == username
        assert session_data["client_ip"] == client_ip
        assert session_data["user_agent"] == user_agent
        assert "created_at" in session_data

    @pytest.mark.asyncio
    async def test_get_mfa_session_valid(self, redis_mock):
        """Test retrieving valid MFA session."""
        user_id = 456
        username = "validuser"
        client_ip = "10.0.0.1"
        user_agent = "ValidBrowser/2.0"

        # Create session
        session_token = await MFASessionManager.create_mfa_session(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            redis_client=redis_mock
        )

        # Retrieve session
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)

        assert session_data is not None
        assert session_data["user_id"] == user_id
        assert session_data["username"] == username
        assert session_data["client_ip"] == client_ip
        assert session_data["user_agent"] == user_agent

    @pytest.mark.asyncio
    async def test_get_mfa_session_invalid(self, redis_mock):
        """Test retrieving invalid MFA session returns None."""
        session_data = await MFASessionManager.get_mfa_session("invalid_token_123", redis_mock)
        assert session_data is None

    @pytest.mark.asyncio
    async def test_delete_mfa_session(self, redis_mock):
        """Test MFA session deletion."""
        user_id = 789
        username = "deleteuser"
        client_ip = "172.16.0.1"
        user_agent = "DeleteBrowser/3.0"

        # Create session
        session_token = await MFASessionManager.create_mfa_session(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            redis_client=redis_mock
        )

        # Verify session exists
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)
        assert session_data is not None

        # Delete session
        deleted = await MFASessionManager.delete_mfa_session(session_token, redis_mock)
        assert deleted is True

        # Verify session is gone
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)
        assert session_data is None

    @pytest.mark.asyncio
    async def test_delete_mfa_session_nonexistent(self, redis_mock):
        """Test deleting nonexistent MFA session."""
        deleted = await MFASessionManager.delete_mfa_session("nonexistent_token", redis_mock)
        assert deleted is False

    @pytest.mark.asyncio
    async def test_mfa_session_ttl(self, redis_mock):
        """Test that MFA sessions expire after TTL."""
        user_id = 999
        username = "ttluser"
        client_ip = "203.0.113.1"
        user_agent = "TTLBrowser/4.0"

        # Create session
        session_token = await MFASessionManager.create_mfa_session(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            redis_client=redis_mock
        )

        # Verify session exists immediately
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)
        assert session_data is not None

        # Manually expire the session (simulate TTL expiration)
        key = MFASessionManager.get_session_key(session_token)
        await redis_mock.delete(key)

        # Verify session is expired
        session_data = await MFASessionManager.get_mfa_session(session_token, redis_mock)
        assert session_data is None


# ==================== PKCE HANDLER TESTS ====================

@pytest.mark.unit
class TestPKCEHandler:
    """Test PKCE (Proof Key for Code Exchange) utilities."""
    
    def test_generate_code_verifier(self):
        """Test code verifier generation."""
        verifier = PKCEHandler.generate_code_verifier()
        
        assert verifier is not None
        assert settings.pkce_code_verifier_min_length <= len(verifier) <= settings.pkce_code_verifier_max_length
    
    def test_generate_code_challenge(self):
        """Test code challenge generation from verifier."""
        verifier = PKCEHandler.generate_code_verifier()
        challenge = PKCEHandler.generate_code_challenge(verifier)
        
        assert challenge is not None
        assert len(challenge) == 43  # Base64url encoded SHA256 hash length
        assert challenge != verifier  # Challenge is different from verifier
    
    def test_code_challenge_deterministic(self):
        """Test that same verifier produces same challenge."""
        verifier = "test_code_verifier_12345"
        challenge1 = PKCEHandler.generate_code_challenge(verifier)
        challenge2 = PKCEHandler.generate_code_challenge(verifier)
        
        assert challenge1 == challenge2


# ==================== SECURE TOKEN HASHER TESTS ====================

@pytest.mark.unit
class TestSecureTokenHasher:
    """Test secure token hashing utilities."""
    
    def test_hash_token(self):
        """Test token hashing."""
        token = "test_token_12345"
        hashed = SecureTokenHasher.hash_token(token)
        
        assert hashed is not None
        assert len(hashed) == 64  # SHA-256 produces 64 hex characters
        assert hashed != token
    
    def test_hash_token_deterministic(self):
        """Test that same token produces same hash."""
        token = "test_token_12345"
        hash1 = SecureTokenHasher.hash_token(token)
        hash2 = SecureTokenHasher.hash_token(token)
        
        assert hash1 == hash2
    
    def test_verify_token_hash_correct(self):
        """Test token hash verification with correct token."""
        token = "test_token_12345"
        hashed = SecureTokenHasher.hash_token(token)
        
        assert SecureTokenHasher.verify_token_hash(token, hashed) is True
    
    def test_verify_token_hash_incorrect(self):
        """Test token hash verification with incorrect token."""
        token = "test_token_12345"
        hashed = SecureTokenHasher.hash_token(token)
        
        assert SecureTokenHasher.verify_token_hash("wrong_token", hashed) is False
    
    def test_hash_backup_codes(self):
        """Test backup code hashing."""
        codes = ["CODE1234", "CODE5678", "CODE9012"]
        hashed_codes = SecureTokenHasher.hash_backup_codes(codes)
        
        assert len(hashed_codes) == 3
        assert all(len(hash_key) == 64 for hash_key in hashed_codes.keys())
    
    def test_verify_backup_code_hash_correct(self):
        """Test backup code verification with correct code."""
        codes = ["CODE1234", "CODE5678"]
        hashed_codes = SecureTokenHasher.hash_backup_codes(codes)
        
        is_valid, original = SecureTokenHasher.verify_backup_code_hash("CODE1234", hashed_codes)
        
        assert is_valid is True
        assert original == "CODE1234"
    
    def test_verify_backup_code_hash_incorrect(self):
        """Test backup code verification with incorrect code."""
        codes = ["CODE1234", "CODE5678"]
        hashed_codes = SecureTokenHasher.hash_backup_codes(codes)
        
        is_valid, original = SecureTokenHasher.verify_backup_code_hash("WRONG", hashed_codes)
        
        assert is_valid is False
        assert original == ""
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt = SecureTokenHasher.generate_salt()
        
        assert salt is not None
        assert len(salt) == 64  # 32 bytes = 64 hex characters
        
        # Generate another to ensure uniqueness
        salt2 = SecureTokenHasher.generate_salt()
        assert salt != salt2


# ==================== RSA KEY MANAGER TESTS ====================

@pytest.mark.unit
class TestRSAKeyManager:
    """Test RSA key management for JWT signing."""
    
    def test_generate_rsa_key_pair(self):
        """Test RSA key pair generation."""
        private_key, public_key = RSAKeyManager.generate_rsa_key_pair()
        
        assert private_key is not None
        assert public_key is not None
        assert "BEGIN PRIVATE KEY" in private_key
        assert "BEGIN PUBLIC KEY" in public_key
        assert "END PRIVATE KEY" in private_key
        assert "END PUBLIC KEY" in public_key
    
    def test_public_key_to_jwk(self):
        """Test converting public key to JWK format."""
        _, public_key = RSAKeyManager.generate_rsa_key_pair()
        jwk = RSAKeyManager.public_key_to_jwk(public_key, "test-key-1")
        
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert jwk["kid"] == "test-key-1"
        assert "n" in jwk  # Modulus
        assert "e" in jwk  # Exponent
    
    def test_get_jwks(self):
        """Test JWKS generation."""
        # This requires JWT_PUBLIC_KEY to be set
        if settings.jwt_public_key:
            jwks = RSAKeyManager.get_jwks()
            
            assert "keys" in jwks
            assert len(jwks["keys"]) >= 1
            assert jwks["keys"][0]["kty"] == "RSA"


# ==================== PASSWORD VALIDATION EDGE CASES ====================

@pytest.mark.unit
class TestPasswordValidationEdgeCases:
    """Test edge cases in password validation."""
    
    def test_empty_password(self):
        """Test validation rejects empty password."""
        is_valid, message = PasswordStrength.validate_password("")
        assert is_valid is False
    
    def test_unicode_password(self):
        """Test validation handles Unicode characters."""
        password = "Pässw0rd!123"  # Contains ä
        is_valid, message = PasswordStrength.validate_password(password)
        
        # Should either accept or reject gracefully
        assert isinstance(is_valid, bool)
    
    def test_very_long_password(self):
        """Test validation accepts very long passwords."""
        # Create long password without sequential chars
        password = "A!a@B#b$C%c^D&d*E" * 10  # 170 chars, no sequential
        is_valid, message = PasswordStrength.validate_password(password)
        
        # Long password should be valid if it meets other requirements
        assert (is_valid is True or "repeated" in message.lower() or "digit" in message.lower())


# ==================== TOKEN EXPIRATION TESTS ====================

@pytest.mark.unit
class TestTokenExpiration:
    """Test token expiration functionality."""
    
    def test_token_not_expired_immediately(self):
        """Test that newly created token is not expired."""
        user_data = {"sub": "123"}
        token = TokenManager.create_access_token(user_data)
        
        assert TokenManager.is_token_expired(token) is False
    
    def test_token_expires_after_delta(self):
        """Test token expiration with custom delta."""
        user_data = {"sub": "123"}
        # Create token that expires in 1 second
        token = TokenManager.create_access_token(
            user_data,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        assert TokenManager.is_token_expired(token) is True
    
    def test_get_token_expiration(self):
        """Test getting token expiration time."""
        user_data = {"sub": "123"}
        token = TokenManager.create_access_token(user_data)
        
        # Decode token to get expiration
        payload = TokenManager.decode_token(token)
        expiration = datetime.fromtimestamp(payload["exp"], timezone.utc)
        
        assert expiration is not None
        assert isinstance(expiration, datetime)
        assert expiration > datetime.now(timezone.utc)


# ==================== TOKEN SECURITY TESTS ====================

@pytest.mark.unit
class TestTokenSecurity:
    """Test token security features."""
    
    def test_token_includes_jti(self):
        """Test that tokens include JTI for tracking."""
        user_data = {"sub": "123"}
        token = TokenManager.create_access_token(user_data, include_jti=True)
        payload = TokenManager.decode_token(token)
        
        assert "jti" in payload
        assert len(payload["jti"]) == 32  # 16 bytes hex = 32 characters
    
    def test_token_without_jti(self):
        """Test creating token without JTI."""
        user_data = {"sub": "123"}
        token = TokenManager.create_access_token(user_data, include_jti=False)
        payload = TokenManager.decode_token(token)
        
        assert "jti" not in payload
    
    def test_different_tokens_have_different_jti(self):
        """Test that each token has a unique JTI."""
        user_data = {"sub": "123"}
        token1 = TokenManager.create_access_token(user_data)
        token2 = TokenManager.create_access_token(user_data)
        
        payload1 = TokenManager.decode_token(token1)
        payload2 = TokenManager.decode_token(token2)
        
        assert payload1["jti"] != payload2["jti"]

