"""
Permission model for RBAC (Role-Based Access Control).
"""

from sqlalchemy import Column, String, UniqueConstraint, Index

from app.models.base import BaseModel
from app.models.mixins import TimestampMixin


class Permission(BaseModel, TimestampMixin):
    """Permission model for RBAC."""

    __tablename__ = "permissions"

    # Unique constraint and composite index for resource:action lookups
    __table_args__ = (
        UniqueConstraint('resource', 'action', name='unique_resource_action'),
        # Composite index for queries filtering by both resource and action
        Index('idx_permission_resource_action', 'resource', 'action'),
    )

    resource = Column(String(100), index=True, nullable=False)
    action = Column(String(50), index=True, nullable=False)

    def __repr__(self):
        return f"<Permission(id={self.id}, resource='{self.resource}', action='{self.action}')>"

    @property
    def permission_string(self):
        """Return permission as resource:action format."""
        return f"{self.resource}:{self.action}"
