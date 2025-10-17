"""
User model for authentication and authorization.
"""

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Index, func
from sqlalchemy.orm import relationship

from app.models.base import Base


class User(Base):
    """User model for authentication and authorization."""
    
    __tablename__ = "users"
    
    # Additional indexes for performance optimization
    __table_args__ = (
        # Index for filtering active users
        Index('idx_user_is_active', 'is_active'),
        # Composite index for active user queries with time filtering
        Index('idx_user_active_created', 'is_active', 'created_at'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")
    user_tokens = relationship("UserToken", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"

