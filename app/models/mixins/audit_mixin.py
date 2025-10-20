"""
Audit mixin for created_by and updated_by fields.
"""

from sqlalchemy import Column, String
from sqlalchemy.ext.declarative import declared_attr


class AuditMixin:
    """Mixin for audit fields."""

    @declared_attr
    def created_by(cls):
        return Column(String(255), nullable=True)

    @declared_attr
    def updated_by(cls):
        return Column(String(255), nullable=True)
