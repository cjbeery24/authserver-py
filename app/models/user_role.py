"""
UserRole junction table for many-to-many user-role relationships.
"""

from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint, Index

from app.models.base import BaseModel


class UserRole(BaseModel):
    """Junction table for user-role many-to-many relationships."""

    __tablename__ = "user_roles"

    # Constraints and indexes for performance optimization
    __table_args__ = (
        # Unique constraint to prevent duplicate user-role assignments
        UniqueConstraint('user_id', 'role_id', name='unique_user_role'),
        # Composite index for role-based user lookups
        Index('idx_user_role_role_user', 'role_id', 'user_id'),
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)

    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"
