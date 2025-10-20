"""
Soft delete mixin for deleted_at and is_deleted fields.
"""

from sqlalchemy import Column, DateTime, Boolean
from sqlalchemy.ext.declarative import declared_attr


class SoftDeleteMixin:
    """Mixin for soft delete functionality."""

    @declared_attr
    def deleted_at(cls):
        return Column(DateTime(timezone=True), nullable=True)

    @declared_attr
    def is_deleted(cls):
        return Column(Boolean, default=False, nullable=False)
