"""
OAuth 2.0 Client Token model for storing registration access tokens.
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy import event

from app.models.base import BaseModel
from app.core.crypto import SecureTokenHasher


class OAuth2ClientToken(BaseModel):
    """
    OAuth 2.0 Client Token model for managing client registration tokens.

    This model stores tokens used for client management operations like
    updating or deleting registered clients.
    """

    __tablename__ = "oauth2_client_tokens"

    __table_args__ = (
        Index('idx_oauth2_client_token_client', 'client_id'),
        Index('idx_oauth2_client_token_type', 'token_type'),
        Index('idx_oauth2_client_token_expires', 'expires_at'),
    )

    client_id = Column(Integer, ForeignKey("oauth2_clients.id"), nullable=False, index=True)
    token = Column(String(255), nullable=False, unique=True, index=True)
    token_type = Column(String(50), nullable=False, default="registration")  # "registration", "access", etc.
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration

    # Relationships
    client = relationship("OAuth2Client", backref="client_tokens")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Store plain token temporarily, will be hashed before save
        self._plain_token = kwargs.get('token')
        # Set default expiration (1 year for registration tokens)
        if 'expires_at' not in kwargs or kwargs.get('expires_at') is None:
            if self.token_type == "registration":
                self.expires_at = datetime.now(timezone.utc) + timedelta(days=365)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if token is active."""
        return not self.is_expired

    @classmethod
    def verify_token(cls, db_session, token_value: str, token_type: str = "registration"):
        """
        Verify a token and return the associated client.

        Args:
            db_session: Database session
            token_value: Plain token value to verify
            token_type: Type of token to verify

        Returns:
            OAuth2ClientToken instance if valid, None otherwise
        """
        # Hash the token for comparison
        hashed_token = SecureTokenHasher.hash_token(token_value)

        # Find token in database
        token_record = db_session.query(cls).filter(
            cls.token == hashed_token,
            cls.token_type == token_type,
            cls.expires_at > datetime.now(timezone.utc)
        ).first()

        return token_record

    @classmethod
    def cleanup_expired_tokens(cls, db_session, days_old: int = 30) -> int:
        """
        Remove expired tokens older than specified days.

        Returns the number of tokens cleaned up.
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_old)

        # Delete expired tokens that are also older than the cutoff
        expired_tokens = db_session.query(cls).filter(
            cls.expires_at < datetime.now(timezone.utc)
        )

        if days_old > 0:
            expired_tokens = expired_tokens.filter(cls.created_at < cutoff_time)

        deleted_count = expired_tokens.count()
        expired_tokens.delete()

        return deleted_count

    @property
    def plain_token(self) -> str:
        """Get the plain token (for responses only, not stored)."""
        return getattr(self, '_plain_token', None)

    def __repr__(self):
        return f"<OAuth2ClientToken(client_id={self.client_id}, token_type='{self.token_type}', expired={self.is_expired})>"


# Event listener to hash token before insert
@event.listens_for(OAuth2ClientToken, 'before_insert')
def hash_token_before_insert(mapper, connection, target):
    """Hash the token before inserting into database."""
    if hasattr(target, '_plain_token') and target._plain_token:
        target.token = SecureTokenHasher.hash_token(target._plain_token)
