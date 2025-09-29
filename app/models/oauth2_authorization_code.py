"""
OAuth 2.0 Authorization Code model for storing authorization codes securely.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class OAuth2AuthorizationCode(BaseModel):
    """
    OAuth 2.0 Authorization Code model for secure storage of authorization codes.

    This model stores authorization codes temporarily to enable secure OAuth 2.0 flows.
    Codes are automatically expired and cleaned up to prevent replay attacks.
    """

    __tablename__ = "oauth2_authorization_codes"

    __table_args__ = (
        Index('idx_oauth2_auth_code_client', 'client_id'),
        Index('idx_oauth2_auth_code_code', 'code', unique=True),
        Index('idx_oauth2_auth_code_expires', 'expires_at'),
        Index('idx_oauth2_auth_code_user', 'user_id'),
    )

    client_id = Column(String(255), ForeignKey("oauth2_clients.client_id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Nullable for client credentials
    code = Column(String(255), unique=True, nullable=False, index=True)
    redirect_uri = Column(Text, nullable=False)
    scope = Column(Text, nullable=True)  # JSON string of granted scopes
    expires_at = Column(DateTime, nullable=False, index=True)

    # PKCE fields
    code_challenge = Column(Text, nullable=True)
    code_challenge_method = Column(String(10), nullable=True)  # 'S256' or 'plain'
    
    # OpenID Connect fields
    nonce = Column(String(255), nullable=True)  # For ID token security

    # Relationships
    client = relationship("OAuth2Client", backref="authorization_codes")
    user = relationship("User", backref="authorization_codes")

    @property
    def is_expired(self) -> bool:
        """Check if the authorization code has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if the authorization code is still active."""
        return not self.is_expired

    def get_scopes(self):
        """Get list of scopes from JSON string."""
        import json
        try:
            return json.loads(self.scope) if self.scope else []
        except (json.JSONDecodeError, TypeError):
            return []

    def set_scopes(self, scope_list):
        """Set scopes as JSON string."""
        import json
        self.scope = json.dumps(scope_list) if scope_list else None

    @classmethod
    def create_authorization_code(
        cls,
        client_id: str,
        user_id: int = None,
        code: str = None,
        redirect_uri: str = None,
        scope: list = None,
        expires_at: datetime = None,
        code_challenge: str = None,
        code_challenge_method: str = None,
        nonce: str = None
    ):
        """Create a new authorization code record."""
        if expires_at is None:
            from datetime import timedelta
            from app.core.config import settings
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.oauth2_authorization_code_expire_minutes)

        code_record = cls(
            client_id=client_id,
            user_id=user_id,
            code=code,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce
        )

        if scope:
            code_record.set_scopes(scope)

        return code_record

    @classmethod
    def cleanup_expired_codes(cls, db_session, minutes_old: int = 60) -> int:
        """
        Remove expired authorization codes older than specified minutes.

        Returns the number of codes cleaned up.
        """
        from datetime import timedelta
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_old)

        # Delete expired codes that are also older than the cutoff
        expired_codes = db_session.query(cls).filter(
            cls.expires_at < datetime.now(timezone.utc)
        )

        deleted_count = expired_codes.count()
        expired_codes.delete()

        return deleted_count

    def __repr__(self):
        return f"<OAuth2AuthorizationCode(code='{self.code[:10]}...', client_id='{self.client_id}', expired={self.is_expired})>"
