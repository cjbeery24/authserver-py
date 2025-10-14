"""
OAuth 2.0 Token model for storing access and refresh tokens.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel
from app.core.config import settings


class OAuth2Token(BaseModel):
    """OAuth 2.0 Token model for storing access and refresh tokens."""

    __tablename__ = "oauth2_tokens"

    client_id = Column(Integer, ForeignKey("oauth2_clients.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Nullable for client credentials flow
    token_type = Column(String(50), nullable=False)  # "access" or "refresh"
    access_token = Column(Text, nullable=True, index=True)  # Only for access tokens
    refresh_token = Column(Text, nullable=True, index=True)  # Only for refresh tokens
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    scope = Column(Text, nullable=True)  # JSON string of granted scopes

    # Additional indexes for performance optimization
    __table_args__ = (
        # Composite index for token lookup by client and type
        Index('idx_oauth2_token_client_type', 'client_id', 'token_type'),
        # Index for token cleanup queries (expired tokens)
        Index('idx_oauth2_token_created', 'created_at'),
    )

    # Relationships
    client = relationship("OAuth2Client", backref="oauth_tokens")
    user = relationship("User", backref="oauth_tokens")

    def __repr__(self):
        return f"<OAuth2Token(id={self.id}, client_id={self.client_id}, token_type='{self.token_type}')>"

    @property
    def is_expired(self):
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_access_token(self):
        """Check if this is an access token."""
        return self.token_type == "access"

    @property
    def is_refresh_token(self):
        """Check if this is a refresh token."""
        return self.token_type == "refresh"
    
    def set_access_token(self, token: str):
        """Set access token with optional encryption."""
        if settings.encrypt_tokens_in_db:
            from app.core.security import TokenEncryption
            self.access_token = TokenEncryption.encrypt_token(token)
        else:
            self.access_token = token
    
    def get_access_token(self) -> str:
        """Get access token with optional decryption."""
        if not self.access_token:
            return None
        
        if settings.encrypt_tokens_in_db:
            from app.core.security import TokenEncryption
            return TokenEncryption.decrypt_token(self.access_token)
        else:
            return self.access_token
    
    def set_refresh_token(self, token: str):
        """Set refresh token with optional encryption."""
        if settings.encrypt_tokens_in_db:
            from app.core.security import TokenEncryption
            self.refresh_token = TokenEncryption.encrypt_token(token)
        else:
            self.refresh_token = token
    
    def get_refresh_token(self) -> str:
        """Get refresh token with optional decryption."""
        if not self.refresh_token:
            return None
            
        if settings.encrypt_tokens_in_db:
            from app.core.security import TokenEncryption
            return TokenEncryption.decrypt_token(self.refresh_token)
        else:
            return self.refresh_token

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
    def create_access_token(cls, client_id, user_id=None, scopes=None, expires_at=None):
        """Create an access token record."""
        if expires_at is None:
            from datetime import timedelta
            from app.core.config import settings
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.oauth2_access_token_expire_minutes)

        token = cls(
            client_id=client_id,
            user_id=user_id,
            token_type="access",
            expires_at=expires_at
        )
        if scopes:
            token.set_scopes(scopes)
        return token

    @classmethod
    def create_refresh_token(cls, client_id, user_id=None, scopes=None, expires_at=None):
        """Create a refresh token record."""
        if expires_at is None:
            from datetime import timedelta
            from app.core.config import settings
            expires_at = datetime.now(timezone.utc) + timedelta(days=settings.oauth2_refresh_token_expire_days)

        token = cls(
            client_id=client_id,
            user_id=user_id,
            token_type="refresh",
            expires_at=expires_at
        )
        if scopes:
            token.set_scopes(scopes)
        return token
