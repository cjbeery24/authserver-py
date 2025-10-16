"""
Cryptographic utilities for the authentication server.

This module provides all cryptographic operations including:
- RSA key management for JWT signing
- AES encryption for token storage
- Password and secret hashing
- Secure token hashing for backup codes
"""

import secrets
import string
import logging
import hashlib
import base64
from typing import Optional, Tuple, Dict, Any, List
from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

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
            logger.debug(f"Using RS256 verification key, length: {len(settings.jwt_public_key)}")
            return settings.jwt_public_key
        else:
            # Fall back to HMAC for backward compatibility
            logger.debug("Using HS256 verification key")
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


class TokenEncryption:
    """
    AES encryption utilities for securing sensitive token data in database storage.

    This class provides symmetric encryption for tokens that need to be stored
    in the database but should remain encrypted at rest.
    """

    @staticmethod
    def _derive_key(password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
            backend=default_backend()
        )
        return kdf.derive(password)

    @staticmethod
    def encrypt_token(token: str, encryption_key: Optional[str] = None) -> str:
        """
        Encrypt a token for secure database storage.

        Args:
            token: Plain text token to encrypt
            encryption_key: Optional custom encryption key (uses settings if not provided)

        Returns:
            Base64 encoded encrypted token with salt and IV
        """
        if not token:
            return ""

        # Use provided key or fall back to settings
        password = (encryption_key or settings.security_salt).encode('utf-8')

        # Generate random salt and IV
        salt = os.urandom(16)  # 128-bit salt
        iv = os.urandom(16)    # 128-bit IV for AES

        # Derive encryption key
        key = TokenEncryption._derive_key(password, salt)

        # Encrypt the token
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Pad token to multiple of 16 bytes (AES block size)
        token_bytes = token.encode('utf-8')
        padding_length = 16 - (len(token_bytes) % 16)
        padded_token = token_bytes + bytes([padding_length] * padding_length)

        # Encrypt
        encrypted_token = encryptor.update(padded_token) + encryptor.finalize()

        # Combine salt + iv + encrypted_token and encode as base64
        combined = salt + iv + encrypted_token
        return base64.b64encode(combined).decode('utf-8')

    @staticmethod
    def decrypt_token(encrypted_token: str, encryption_key: Optional[str] = None) -> Optional[str]:
        """
        Decrypt a token from database storage.

        Args:
            encrypted_token: Base64 encoded encrypted token
            encryption_key: Optional custom encryption key (uses settings if not provided)

        Returns:
            Decrypted plain text token or None if decryption fails
        """
        if not encrypted_token:
            return None

        try:
            # Use provided key or fall back to settings
            password = (encryption_key or settings.security_salt).encode('utf-8')

            # Decode from base64
            combined = base64.b64decode(encrypted_token.encode('utf-8'))

            # Extract salt, IV, and encrypted data
            salt = combined[:16]
            iv = combined[16:32]
            encrypted_data = combined[32:]

            # Derive decryption key
            key = TokenEncryption._derive_key(password, salt)

            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_token = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            padding_length = padded_token[-1]
            if padding_length > 16:
                return None  # Invalid padding

            token = padded_token[:-padding_length].decode('utf-8')
            return token

        except Exception as e:
            logger.error(f"Token decryption failed: {str(e)}")
            return None

    @staticmethod
    def is_encrypted(token_data: str) -> bool:
        """Check if token data appears to be encrypted (base64 with correct length)."""
        if not token_data:
            return False
        try:
            decoded = base64.b64decode(token_data.encode('utf-8'))
            # Encrypted tokens should have at least salt(16) + iv(16) + some data
            return len(decoded) >= 48
        except Exception:
            return False


class PasswordHasher:
    """Password hashing utilities using bcrypt."""

    @staticmethod
    def hash_password(password: str, username: str = None) -> str:
        """Hash a password with strength validation."""
        # Import here to avoid circular imports
        from .auth import PasswordStrength, PasswordValidationError
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

