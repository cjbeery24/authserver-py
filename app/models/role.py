"""
Role model for RBAC (Role-Based Access Control).
"""

from sqlalchemy import Column, String, Text

from app.models.base import BaseModel


class Role(BaseModel):
    """Role model for RBAC."""

    __tablename__ = "roles"

    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}')>"
