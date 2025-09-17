"""
RolePermission junction table for many-to-many role-permission relationships.
"""

from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint, Index

from app.models.base import BaseModel


class RolePermission(BaseModel):
    """Junction table for role-permission many-to-many relationships."""

    __tablename__ = "role_permissions"

    # Constraints and indexes for performance optimization
    __table_args__ = (
        # Unique constraint to prevent duplicate role-permission assignments
        UniqueConstraint('role_id', 'permission_id', name='unique_role_permission'),
        # Composite index for permission-based role lookups
        Index('idx_role_permission_perm_role', 'permission_id', 'role_id'),
    )

    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False, index=True)

    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"
