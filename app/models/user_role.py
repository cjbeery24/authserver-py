"""
UserRole junction table for many-to-many user-role relationships.
"""

from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint

from app.models.base import BaseModel


class UserRole(BaseModel):
    """Junction table for user-role many-to-many relationships."""

    __tablename__ = "user_roles"

    # Unique constraint to prevent duplicate user-role assignments
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='unique_user_role'),
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)

    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"
