"""
Password reset token model for secure password reset functionality.
"""

from datetime import datetime, timedelta, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class PasswordResetToken(BaseModel):
    """
    Model for storing password reset tokens.
    
    This model stores secure tokens for password reset functionality,
    with expiration times and usage tracking.
    """
    __tablename__ = "password_reset_tokens"

    __table_args__ = (
        Index('idx_password_reset_token_hash', 'token_hash'),
        Index('idx_password_reset_user_created', 'user_id', 'created_at'),
        Index('idx_password_reset_expires', 'expires_at'),
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 hash
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(String(45), nullable=True)  # Support both IPv4 and IPv6
    user_agent = Column(String(500), nullable=True)

    # Relationship
    user = relationship("User", back_populates="password_reset_tokens")

    @property
    def is_expired(self) -> bool:
        """Check if the reset token has expired."""
        now = datetime.now(timezone.utc)
        # Ensure both datetimes are timezone-aware for comparison
        if self.expires_at.tzinfo is None:
            # If expires_at is naive, assume it's UTC
            expires_at_utc = self.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_utc = self.expires_at
        return now > expires_at_utc

    @property
    def is_valid(self) -> bool:
        """Check if the reset token is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired

    def mark_as_used(self, ip_address: str = None, user_agent: str = None):
        """Mark the token as used with optional tracking information."""
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)
        if ip_address:
            self.ip_address = ip_address
        if user_agent:
            self.user_agent = user_agent[:500]  # Truncate if too long

    @classmethod
    def create_reset_token(cls, user_id: int, token: str, expiry_hours: int = 1):
        """
        Create a new password reset token.
        
        Args:
            user_id: ID of the user requesting password reset
            token: Secure reset token (will be hashed before storage)
            expiry_hours: Hours until token expires (default: 1 hour)
        
        Returns:
            PasswordResetToken: New reset token instance
        """
        from app.core.crypto import SecureTokenHasher
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
        token_hash = SecureTokenHasher.hash_token(token)
        
        return cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            is_used=False
        )

    @classmethod
    def find_by_token(cls, db_session, token: str):
        """
        Find a password reset token by its plain text value.
        
        Args:
            db_session: Database session
            token: Plain text token to search for
            
        Returns:
            PasswordResetToken: Token instance if found and valid, None otherwise
        """
        from app.core.crypto import SecureTokenHasher
        
        if not token:
            return None
            
        token_hash = SecureTokenHasher.hash_token(token)
        
        return db_session.query(cls).filter(
            cls.token_hash == token_hash,
            cls.is_used == False
        ).first()

    def verify_token(self, token: str) -> bool:
        """
        Verify if the provided token matches this reset token.
        
        Args:
            token: Plain text token to verify
            
        Returns:
            bool: True if token matches and is valid
        """
        from app.core.crypto import SecureTokenHasher
        
        if not token or self.is_used or self.is_expired:
            return False
            
        return SecureTokenHasher.verify_token_hash(token, self.token_hash)

    @classmethod
    def cleanup_expired_tokens(cls, db_session):
        """Remove expired password reset tokens from the database."""
        cutoff_time = datetime.now(timezone.utc)
        expired_tokens = db_session.query(cls).filter(
            cls.expires_at < cutoff_time
        )
        count = expired_tokens.count()
        expired_tokens.delete()
        return count

    def __repr__(self):
        return f"<PasswordResetToken(user_id={self.user_id}, expires_at={self.expires_at}, is_used={self.is_used})>"
