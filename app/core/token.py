"""
Token management utilities for the authentication server.

This module provides all token-related operations including:
- JWT token creation and verification
- Token binding for enhanced security
- Token rotation and lifecycle management
- Token blacklisting for secure logout
- Token security validation and risk assessment
"""

import secrets
import string
import logging
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List, Dict, Any
from jose import JWTError, jwt
import json

from app.core.config import settings

logger = logging.getLogger(__name__)


class TokenBinding:
    """
    Token binding utilities to tie tokens to specific clients/sessions.

    Implements RFC 8473-style token binding for enhanced security.
    """

    @staticmethod
    def create_binding_info(request, additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create token binding information from request context.

        Args:
            request: FastAPI request object
            additional_data: Optional additional binding data

        Returns:
            Dictionary containing binding information
        """
        from app.middleware.security_headers import TokenTransmissionSecurity

        binding_info = {
            "client_fingerprint": TokenTransmissionSecurity.get_client_fingerprint(request),
            "ip_address": request.client.host if request.client else "",
            "user_agent_hash": hashlib.sha256(
                request.headers.get("User-Agent", "").encode()
            ).hexdigest()[:16],  # First 16 chars for storage efficiency
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Add optional additional binding data
        if additional_data:
            binding_info.update(additional_data)

        return binding_info

    @staticmethod
    def create_binding_signature(binding_info: Dict[str, Any], secret_key: str) -> str:
        """
        Create a binding signature for the binding information.

        Args:
            binding_info: Binding information dictionary
            secret_key: Secret key for signing

        Returns:
            HMAC signature of binding information
        """

        # Create canonical representation of binding info
        canonical_data = "|".join([
            binding_info.get("client_fingerprint", ""),
            binding_info.get("ip_address", ""),
            binding_info.get("user_agent_hash", ""),
            binding_info.get("timestamp", "")
        ])

        # Create HMAC signature
        signature = hmac.new(
            secret_key.encode(),
            canonical_data.encode(),
            hashlib.sha256
        ).hexdigest()

        return signature

    @staticmethod
    def verify_token_binding(
        token_binding_info: Dict[str, Any],
        current_request,
        secret_key: str,
        tolerance_seconds: int = 300  # 5 minutes tolerance
    ) -> bool:
        """
        Verify token binding against current request.

        Args:
            token_binding_info: Binding info from token
            current_request: Current FastAPI request
            secret_key: Secret key for verification
            tolerance_seconds: Time tolerance for binding verification

        Returns:
            True if binding is valid, False otherwise
        """
        try:
            # Skip binding verification in development or if disabled
            if not settings.token_binding_enabled or settings.app_env in ["development", "dev", "local"]:
                logger.debug("Token binding verification skipped (disabled or development environment)")
                return True

            # Skip binding for testing tools (Postman, curl, etc.) if configured
            if settings.token_binding_skip_testing_tools:
                user_agent = current_request.headers.get("User-Agent", "").lower()
                testing_tools = ["postman", "insomnia", "curl", "httpie", "python-requests", "axios", "thunder client"]
                if any(tool in user_agent for tool in testing_tools):
                    logger.debug(f"Token binding verification skipped for testing tool: {user_agent}")
                    return True

            # Create current binding info
            current_binding = TokenBinding.create_binding_info(current_request)

            # Verify client fingerprint (most important)
            if current_binding["client_fingerprint"] != token_binding_info.get("client_fingerprint"):
                logger.warning("Token binding failed: client fingerprint mismatch")
                return False

            # Verify IP address (with some tolerance for mobile/proxy scenarios)
            if settings.token_binding_strict_ip:
                if current_binding["ip_address"] != token_binding_info.get("ip_address"):
                    logger.warning("Token binding failed: IP address mismatch")
                    return False

            # Verify user agent hash
            if current_binding["user_agent_hash"] != token_binding_info.get("user_agent_hash"):
                logger.warning("Token binding failed: user agent mismatch")
                return False

            # Verify binding signature
            expected_signature = TokenBinding.create_binding_signature(token_binding_info, secret_key)
            if not hmac.compare_digest(expected_signature, token_binding_info.get("signature", "")):
                logger.warning("Token binding failed: invalid signature")
                return False

            # Verify timestamp (prevent replay attacks)
            try:
                binding_time = datetime.fromisoformat(token_binding_info.get("timestamp", ""))
                current_time = datetime.now(timezone.utc)
                time_diff = abs((current_time - binding_time).total_seconds())

                if time_diff > tolerance_seconds:
                    logger.warning(f"Token binding failed: timestamp too old ({time_diff}s)")
                    return False
            except ValueError:
                logger.warning("Token binding failed: invalid timestamp format")
                return False

            return True

        except Exception as e:
            logger.error(f"Token binding verification error: {str(e)}")
            return False

    @staticmethod
    def add_binding_to_token_payload(payload: Dict[str, Any], binding_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add binding information to JWT token payload.

        Args:
            payload: JWT payload dictionary
            binding_info: Token binding information

        Returns:
            Updated payload with binding information
        """
        # Add binding info in a compact format
        payload["binding"] = {
            "fp": binding_info.get("client_fingerprint", "")[:32],  # Truncate for size
            "ip": binding_info.get("ip_address", ""),
            "ua": binding_info.get("user_agent_hash", ""),
            "ts": binding_info.get("timestamp", ""),
            "sig": binding_info.get("signature", "")
        }

        return payload


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
            "exp": int(expire.timestamp()),  # Expiration time
            "iat": int(now.timestamp()),  # Issued at
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
        from .crypto import RSAKeyManager
        signing_key = RSAKeyManager.get_signing_key()
        encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=settings.jwt_algorithm, headers=headers)
        return encoded_jwt

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, include_jti: bool = True) -> str:
        """
        Create a JWT access token.

        The data dict should include user information and optionally 'roles' (list of role names).
        Roles will be included in the token payload for authorization by consuming applications.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)

        to_encode.update({"exp": int(expire.timestamp()), "type": "access"})

        # Include JTI (JWT ID) for token tracking if requested
        if include_jti:
            jti = secrets.token_hex(16)  # Generate unique JTI
            to_encode.update({"jti": jti})

        # Add Key ID to header for JWKS support
        headers = {}
        if settings.jwt_algorithm.startswith('RS'):
            headers["kid"] = settings.jwt_key_id

        # Use appropriate signing key
        from .crypto import RSAKeyManager
        signing_key = RSAKeyManager.get_signing_key()
        encoded_jwt = jwt.encode(to_encode, signing_key, algorithm=settings.jwt_algorithm, headers=headers)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None, include_jti: bool = True) -> str:
        """
        Create a JWT refresh token.

        The data dict should include user information and optionally 'roles' (list of role names).
        Roles are included in refresh tokens so they can be propagated when refreshing access tokens.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)

        to_encode.update({"exp": int(expire.timestamp()), "type": "refresh"})

        # Include JTI (JWT ID) for token tracking if requested
        if include_jti:
            jti = secrets.token_hex(16)  # Generate unique JTI
            to_encode.update({"jti": jti})

        # Add Key ID to header for JWKS support
        headers = {}
        if settings.jwt_algorithm.startswith('RS'):
            headers["kid"] = settings.jwt_key_id

        # Use appropriate signing key
        from .crypto import RSAKeyManager
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
            from .crypto import RSAKeyManager
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
            from .crypto import RSAKeyManager
            verification_key = RSAKeyManager.get_verification_key()
            logger.debug(f"Verifying JWT token with algorithm: {settings.jwt_algorithm}")
            payload = jwt.decode(token, verification_key, algorithms=[settings.jwt_algorithm])
            logger.debug(f"JWT decoded successfully, token type: {payload.get('type')}")
            logger.debug(f"Token payload: {payload}")
            if payload.get("type") != token_type:
                logger.warning(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
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
            from .crypto import RSAKeyManager
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
            "token_type": "Bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,  # seconds
        }

    @staticmethod
    def create_oauth2_token_response(user_data: dict, client_id: str, scopes: List[str], nonce: str = None, auth_time: Optional[datetime] = None) -> dict:
        """
        Create OAuth2/OIDC token response with ID token when openid scope is present.

        Args:
            user_data: Dictionary containing user information (should include 'roles' list)
            client_id: OAuth2 client ID
            scopes: List of granted scopes
            nonce: Optional nonce from authorization request
            auth_time: Time when user authentication occurred

        Returns:
            Token response dictionary
        """
        # Create access token
        access_token = TokenManager.create_access_token(user_data)

        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,  # seconds
            "scope": " ".join(scopes) if scopes else ""
        }

        # Only include refresh token if user_data is not empty (i.e., not client_credentials grant)
        # Client credentials grant should NOT receive refresh tokens per RFC 6749
        if user_data:
            refresh_token = TokenManager.create_refresh_token(user_data)
            response["refresh_token"] = refresh_token

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


class TokenRotation:
    """
    Token rotation and lifecycle management utilities.
    """

    @staticmethod
    async def rotate_refresh_token(
        old_refresh_token: str,
        user_id: int,
        db_session,
        redis_client,
        request=None
    ) -> Optional[Dict[str, str]]:
        """
        Rotate a refresh token, invalidating the old one and creating a new one.

        Args:
            old_refresh_token: Current refresh token to rotate
            user_id: User ID for the new token
            db_session: Database session
            redis_client: Redis client for blacklisting
            request: Optional request context for binding

        Returns:
            Dictionary with new access and refresh tokens, or None if rotation fails
        """
        try:
            # Verify the old refresh token
            payload = TokenManager.decode_token(old_refresh_token)
            if not payload or payload.get("type") != "refresh":
                logger.warning("Token rotation failed: invalid refresh token")
                return None

            # Check if token is expired
            if TokenManager.is_token_expired(old_refresh_token):
                logger.warning("Token rotation failed: refresh token expired")
                return None

            # Verify user ID matches
            if int(payload.get("sub", 0)) != user_id:
                logger.warning("Token rotation failed: user ID mismatch")
                return None

            # Blacklist the old refresh token
            blacklist_success = await TokenBlacklist.blacklist_token(old_refresh_token, redis_client)
            if not blacklist_success:
                logger.warning("Token rotation failed: could not blacklist old token")
                return None

            # Get user data for new tokens
            from app.models.user import User
            user = db_session.query(User).filter(User.id == user_id).first()
            if not user or not user.is_active:
                logger.warning("Token rotation failed: user not found or inactive")
                return None

            # Get user roles for inclusion in token
            from app.core.rbac import PermissionChecker
            user_roles = await PermissionChecker.get_user_roles(user.id, db_session)

            # Create new token pair with roles
            user_data = {
                "sub": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user_roles]  # Include roles in token
            }

            new_tokens = TokenManager.create_token_pair(user_data)

            # Store new tokens in database
            from .audit import SecurityAudit
            SecurityAudit.store_user_tokens(
                db_session=db_session,
                user_id=user.id,
                access_token=new_tokens["access_token"],
                refresh_token=new_tokens["refresh_token"],
                ip_address=request.client.host if request and request.client else None,
                user_agent=request.headers.get('User-Agent') if request else None
            )

            logger.info(f"Successfully rotated refresh token for user {user_id}")
            return new_tokens

        except Exception as e:
            logger.error(f"Token rotation error: {str(e)}")
            return None

    @staticmethod
    async def cleanup_expired_tokens(db_session, days_old: int = 30) -> Dict[str, int]:
        """
        Clean up expired tokens from database.

        Args:
            db_session: Database session
            days_old: Remove tokens expired for this many days

        Returns:
            Dictionary with cleanup statistics
        """
        from app.models.user_token import UserToken
        from app.models.oauth2_token import OAuth2Token
        from app.models.oauth2_client_token import OAuth2ClientToken
        from app.models.oauth2_authorization_code import OAuth2AuthorizationCode
        from app.models.password_reset import PasswordResetToken

        cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_old)
        stats = {
            "user_tokens": 0,
            "oauth2_tokens": 0,
            "client_tokens": 0,
            "authorization_codes": 0,
            "password_reset_tokens": 0
        }

        try:
            # Clean up expired user tokens
            expired_user_tokens = db_session.query(UserToken).filter(
                UserToken.expires_at < datetime.now(timezone.utc),
                UserToken.created_at < cutoff_time
            )
            stats["user_tokens"] = expired_user_tokens.count()
            expired_user_tokens.delete()

            # Clean up expired OAuth2 tokens
            expired_oauth2_tokens = db_session.query(OAuth2Token).filter(
                OAuth2Token.expires_at < datetime.now(timezone.utc),
                OAuth2Token.created_at < cutoff_time
            )
            stats["oauth2_tokens"] = expired_oauth2_tokens.count()
            expired_oauth2_tokens.delete()

            # Clean up expired client tokens
            stats["client_tokens"] = OAuth2ClientToken.cleanup_expired_tokens(db_session, days_old)

            # Clean up expired authorization codes (these should be short-lived anyway)
            expired_auth_codes = db_session.query(OAuth2AuthorizationCode).filter(
                OAuth2AuthorizationCode.expires_at < datetime.now(timezone.utc),
                OAuth2AuthorizationCode.created_at < cutoff_time
            )
            stats["authorization_codes"] = expired_auth_codes.count()
            expired_auth_codes.delete()

            # Clean up expired password reset tokens
            expired_reset_tokens = db_session.query(PasswordResetToken).filter(
                PasswordResetToken.expires_at < datetime.now(timezone.utc),
                PasswordResetToken.created_at < cutoff_time
            )
            stats["password_reset_tokens"] = expired_reset_tokens.count()
            expired_reset_tokens.delete()

            # Commit all deletions
            db_session.commit()

            total_cleaned = sum(stats.values())
            if total_cleaned > 0:
                logger.info(f"Token cleanup completed: {total_cleaned} tokens removed")

            return stats

        except Exception as e:
            logger.error(f"Token cleanup error: {str(e)}")
            db_session.rollback()
            return stats

    @staticmethod
    async def revoke_all_user_tokens(user_id: int, db_session, redis_client, reason: str = "user_action") -> int:
        """
        Revoke all tokens for a specific user.

        Args:
            user_id: User ID to revoke tokens for
            db_session: Database session
            redis_client: Redis client for blacklisting
            reason: Reason for revocation

        Returns:
            Number of tokens revoked
        """
        from app.models.user_token import UserToken

        try:
            # Get all active tokens for the user
            active_tokens = db_session.query(UserToken).filter(
                UserToken.user_id == user_id,
                UserToken.is_revoked == False,
                UserToken.expires_at > datetime.now(timezone.utc)
            ).all()

            revoked_count = 0

            for token_record in active_tokens:
                # Mark as revoked in database
                token_record.is_revoked = True
                token_record.revoked_at = datetime.now(timezone.utc)
                token_record.revoked_reason = reason

                # Add to blacklist in Redis (if we had the actual token value)
                # Note: We store JTI in database, but need the full token for blacklisting
                # This is a design trade-off for security vs functionality

                revoked_count += 1

            if revoked_count > 0:
                db_session.commit()
                logger.info(f"Revoked {revoked_count} tokens for user {user_id}, reason: {reason}")

            return revoked_count

        except Exception as e:
            logger.error(f"Error revoking user tokens: {str(e)}")
            db_session.rollback()
            return 0

    @staticmethod
    def should_rotate_token(token_age_seconds: int, max_age_seconds: int = None) -> bool:
        """
        Determine if a token should be rotated based on age.

        Args:
            token_age_seconds: Age of the token in seconds
            max_age_seconds: Maximum age before rotation (defaults to half of refresh token lifetime)

        Returns:
            True if token should be rotated
        """
        if max_age_seconds is None:
            # Default to half of refresh token lifetime
            max_age_seconds = (settings.jwt_refresh_token_expire_days * 24 * 60 * 60) // 2

        return token_age_seconds >= max_age_seconds


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


class TokenSecurityManager:
    """
    Centralized token security validation and risk assessment.

    This class consolidates security validation logic for tokens,
    providing reusable methods for:
    - Token transmission security validation
    - Security score calculation
    - Security recommendations generation
    - User risk assessment
    """

    @staticmethod
    def validate_transmission_security(request) -> Dict[str, bool]:
        """
        Validate security aspects of token transmission.

        Analyzes the request to check various security aspects like HTTPS,
        headers, and secure context.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary of security validation results

        Example:
            results = TokenSecurityManager.validate_transmission_security(request)
            if not results["is_https"]:
                logger.warning("Token transmitted over HTTP!")
        """
        from app.middleware.security_headers import TokenTransmissionSecurity
        return TokenTransmissionSecurity.validate_token_transmission_security(request)

    @staticmethod
    def calculate_security_score(validation_results: Dict[str, bool], request) -> int:
        """
        Calculate overall security score based on validation results.

        Score ranges from 0-100:
        - 80-100: Excellent security
        - 60-79: Good security
        - 40-59: Moderate security
        - 0-39: Poor security

        Args:
            validation_results: Results from validate_transmission_security()
            request: FastAPI request object for additional checks

        Returns:
            Security score (0-100)

        Example:
            results = TokenSecurityManager.validate_transmission_security(request)
            score = TokenSecurityManager.calculate_security_score(results, request)
            if score < 60:
                logger.warning(f"Low security score: {score}")
        """
        score = 0

        # HTTPS check (30 points) - Most important
        if validation_results.get("is_https", False):
            score += 30

        # Secure context (20 points)
        if validation_results.get("is_secure_context", False):
            score += 20

        # Valid content type (15 points)
        if validation_results.get("content_type_valid", False):
            score += 15

        # User agent present (10 points)
        if validation_results.get("has_user_agent", False):
            score += 10

        # Origin header present (10 points)
        if validation_results.get("has_origin", False):
            score += 10

        # Referer header present (10 points)
        if validation_results.get("has_referer", False):
            score += 10

        # Additional security headers (5 points)
        security_headers = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]
        if any(header in request.headers for header in security_headers):
            score += 5

        return min(score, 100)

    @staticmethod
    def generate_security_recommendations(
        validation_results: Dict[str, bool],
        request
    ) -> list[str]:
        """
        Generate security recommendations based on validation results.

        Args:
            validation_results: Results from validate_transmission_security()
            request: FastAPI request object

        Returns:
            List of security recommendations

        Example:
            results = TokenSecurityManager.validate_transmission_security(request)
            recommendations = TokenSecurityManager.generate_security_recommendations(results, request)
            for rec in recommendations:
                logger.info(f"Security recommendation: {rec}")
        """
        recommendations = []

        # Critical recommendations
        if not validation_results.get("is_https", False):
            recommendations.append("⚠️ CRITICAL: Use HTTPS for all token transmission")

        # Important recommendations
        if not validation_results.get("has_user_agent", False):
            recommendations.append("Include proper User-Agent header in requests")

        if not validation_results.get("has_origin", False):
            recommendations.append("Include Origin header for CORS validation")

        if not validation_results.get("content_type_valid", False):
            recommendations.append("Use valid Content-Type headers (application/json, application/x-www-form-urlencoded)")

        if not validation_results.get("is_secure_context", False):
            recommendations.append("Ensure requests are made from secure context (HTTPS environment)")

        # General best practices (always show)
        recommendations.extend([
            "Regularly rotate refresh tokens",
            "Enable token binding for enhanced security",
            "Monitor for unusual access patterns",
            "Use short-lived access tokens"
        ])

        return recommendations

    @staticmethod
    def calculate_user_risk_score(user, active_tokens: int, security_events: list) -> int:
        """
        Calculate risk score for a user based on various factors.

        Score ranges from 0-100:
        - 0-30: Low risk
        - 31-60: Moderate risk
        - 61-80: High risk
        - 81-100: Very high risk

        Args:
            user: User object
            active_tokens: Number of active tokens
            security_events: List of recent security events

        Returns:
            Risk score (0-100)

        Example:
            risk = TokenSecurityManager.calculate_user_risk_score(
                user, active_tokens=15, security_events=events
            )
            if risk > 60:
                # Trigger additional security measures
        """
        risk_score = 0

        # Base risk (10 points)
        risk_score += 10

        # Active tokens risk (more tokens = higher risk)
        if active_tokens > 10:
            risk_score += 20
        elif active_tokens > 5:
            risk_score += 10

        # Recent security events risk
        failed_attempts = sum(
            1 for event in security_events
            if "failed" in event.get("action", "").lower() or
               not event.get("success", True)
        )
        if failed_attempts > 5:
            risk_score += 30
        elif failed_attempts > 2:
            risk_score += 15

        # Account age (newer accounts have slightly higher risk)
        if hasattr(user, 'created_at') and user.created_at:
            if user.created_at > datetime.now(timezone.utc) - timedelta(days=7):
                risk_score += 10

        # Different IP addresses in recent events (account sharing or compromise)
        unique_ips = set(
            event.get("ip_address", "")
            for event in security_events
            if event.get("ip_address")
        )
        if len(unique_ips) > 5:
            risk_score += 15
        elif len(unique_ips) > 3:
            risk_score += 10

        # Suspicious activities
        suspicious_actions = ["mfa_disable", "password_change", "role_change"]
        suspicious_count = sum(
            1 for event in security_events
            if any(action in event.get("action", "").lower() for action in suspicious_actions)
        )
        if suspicious_count > 3:
            risk_score += 10

        return min(risk_score, 100)

    @staticmethod
    def get_client_fingerprint(request) -> str:
        """
        Generate a client fingerprint for token binding.

        Args:
            request: FastAPI request object

        Returns:
            SHA-256 hash of client characteristics
        """
        from app.middleware.security_headers import TokenTransmissionSecurity
        return TokenTransmissionSecurity.get_client_fingerprint(request)


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
        import hashlib
        import base64
        sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
        return code_challenge
