"""
User token model for tracking issued tokens and enabling selective invalidation.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class UserToken(BaseModel):
    """
    Model for tracking user tokens to enable selective invalidation.

    This model stores metadata about issued tokens without storing the actual
    token values (for security). It enables features like:
    - Logout from all devices
    - Token revocation
    - Audit logging of token usage
    """

    __tablename__ = "user_tokens"

    __table_args__ = (
        Index('idx_user_tokens_user_id', 'user_id'),
        Index('idx_user_tokens_token_type', 'token_type'),
        Index('idx_user_tokens_expires_at', 'expires_at'),
        Index('idx_user_tokens_user_type', 'user_id', 'token_type'),
        Index('idx_user_tokens_user_created', 'user_id', 'created_at'),
        # Composite index for active token queries (most common query pattern)
        Index('idx_user_tokens_active', 'user_id', 'is_revoked', 'expires_at'),
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID claim
    token_type = Column(String(50), nullable=False, index=True)  # 'access' or 'refresh'
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String(255), nullable=True)

    # Audit information
    issued_ip = Column(String(45), nullable=True)  # Support IPv4 and IPv6
    issued_user_agent = Column(Text, nullable=True)
    revoked_ip = Column(String(45), nullable=True)
    revoked_user_agent = Column(Text, nullable=True)

    # Relationship
    user = relationship("User", back_populates="user_tokens")

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if the token is active (not expired and not revoked)."""
        return not self.is_expired and not self.is_revoked

    def revoke(self, reason: str = None, ip_address: str = None, user_agent: str = None):
        """Mark the token as revoked."""
        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)
        if reason:
            self.revoked_reason = reason
        if ip_address:
            self.revoked_ip = ip_address
        if user_agent:
            self.revoked_user_agent = user_agent[:500]  # Truncate if too long

    @classmethod
    def create_token_record(
        cls,
        user_id: int,
        token_jti: str,
        token_type: str,
        expires_at: datetime,
        ip_address: str = None,
        user_agent: str = None
    ):
        """Create a new token record."""
        return cls(
            user_id=user_id,
            token_jti=token_jti,
            token_type=token_type,
            expires_at=expires_at,
            issued_ip=ip_address,
            issued_user_agent=user_agent[:500] if user_agent else None
        )

    @classmethod
    def revoke_user_tokens(
        cls,
        db_session,
        user_id: int,
        reason: str = "logout_all",
        ip_address: str = None,
        user_agent: str = None
    ) -> int:
        """
        Revoke all active tokens for a user.

        Returns the number of tokens revoked.
        """
        from sqlalchemy import and_

        # Find all active tokens for the user
        active_tokens = db_session.query(cls).filter(
            and_(
                cls.user_id == user_id,
                cls.is_revoked == False,
                cls.expires_at > datetime.now(timezone.utc)
            )
        ).all()

        # Revoke each token
        revoked_count = 0
        for token in active_tokens:
            token.revoke(reason, ip_address, user_agent)
            revoked_count += 1

        return revoked_count

    @classmethod
    def cleanup_expired_tokens(cls, db_session, days_old: int = 30) -> int:
        """
        Remove expired and revoked tokens older than specified days.

        Returns the number of tokens cleaned up.
        """
        cutoff_date = datetime.now(timezone.utc)
        # Remove tokens that are both expired AND older than the cutoff
        expired_cutoff = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        # Delete tokens that are:
        # 1. Expired AND revoked, OR
        # 2. Expired and older than cleanup threshold
        from sqlalchemy import or_, and_

        expired_revoked = db_session.query(cls).filter(
            and_(
                cls.expires_at < cutoff_date,
                cls.is_revoked == True
            )
        )

        expired_old = db_session.query(cls).filter(
            and_(
                cls.expires_at < expired_cutoff,
                cls.created_at < expired_cutoff
            )
        )

        total_deleted = expired_revoked.count() + expired_old.count()
        expired_revoked.delete()
        expired_old.delete()

        return total_deleted

    def __repr__(self):
        return f"<UserToken(user_id={self.user_id}, token_type='{self.token_type}', is_revoked={self.is_revoked}, expires_at={self.expires_at})>"
