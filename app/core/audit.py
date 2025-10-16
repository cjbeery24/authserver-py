"""
Security auditing and rate limiting utilities for the authentication server.

This module provides security auditing, rate limiting, and monitoring utilities including:
- Input sanitization and suspicious activity detection
- Failed login/refresh attempt tracking
- Security headers and token storage
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.core.config import settings

logger = logging.getLogger(__name__)


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
        from .token import TokenManager
        payload = TokenManager.decode_token(token)
        if payload:
            return payload.get("jti")
        return None

    @staticmethod
    def get_token_expiry(token: str) -> Optional[datetime]:
        """Get token expiry time from the token itself."""
        from .token import TokenManager
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

        access_jti = SecurityAudit.get_token_jti(access_token)
        refresh_jti = SecurityAudit.get_token_jti(refresh_token)

        access_expiry = SecurityAudit.get_token_expiry(access_token)
        refresh_expiry = SecurityAudit.get_token_expiry(refresh_token)

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

