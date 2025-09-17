"""
Permission model for RBAC (Role-Based Access Control).
"""

from sqlalchemy import Column, String, UniqueConstraint

from app.models.base import BaseModel


class Permission(BaseModel):
    """Permission model for RBAC."""

    __tablename__ = "permissions"

    # Unique constraint to prevent duplicate resource:action combinations
    __table_args__ = (
        UniqueConstraint('resource', 'action', name='unique_resource_action'),
    )

    resource = Column(String(100), index=True, nullable=False)
    action = Column(String(50), nullable=False)

    def __repr__(self):
        return f"<Permission(id={self.id}, resource='{self.resource}', action='{self.action}')>"

    @property
    def permission_string(self):
        """Return permission as resource:action format."""
        return f"{self.resource}:{self.action}"
