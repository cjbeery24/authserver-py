"""
OAuth 2.0 Token model for storing access and refresh tokens.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class OAuth2Token(BaseModel):
    """OAuth 2.0 Token model for storing access and refresh tokens."""

    __tablename__ = "oauth2_tokens"

    client_id = Column(Integer, ForeignKey("oauth2_clients.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Nullable for client credentials flow
    token_type = Column(String(50), nullable=False)  # "access" or "refresh"
    access_token = Column(Text, nullable=True, index=True)  # Only for access tokens
    refresh_token = Column(Text, nullable=True, index=True)  # Only for refresh tokens
    expires_at = Column(DateTime, nullable=False, index=True)
    scope = Column(Text, nullable=True)  # JSON string of granted scopes

    # Relationships
    client = relationship("OAuth2Client", backref="tokens")
    user = relationship("User", backref="tokens")

    def __repr__(self):
        return f"<OAuth2Token(id={self.id}, client_id={self.client_id}, token_type='{self.token_type}')>"

    @property
    def is_expired(self):
        """Check if token is expired."""
        return datetime.utcnow() > self.expires_at

    @property
    def is_access_token(self):
        """Check if this is an access token."""
        return self.token_type == "access"

    @property
    def is_refresh_token(self):
        """Check if this is a refresh token."""
        return self.token_type == "refresh"

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
            expires_at = datetime.utcnow() + timedelta(minutes=30)  # Default 30 minutes

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
            expires_at = datetime.utcnow() + timedelta(days=7)  # Default 7 days

        token = cls(
            client_id=client_id,
            user_id=user_id,
            token_type="refresh",
            expires_at=expires_at
        )
        if scopes:
            token.set_scopes(scopes)
        return token
