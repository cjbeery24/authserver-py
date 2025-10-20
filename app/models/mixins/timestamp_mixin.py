"""
Timestamp mixin for created_at and updated_at fields.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.sql import func


class TimestampMixin:
    """Mixin for timestamp fields."""

    @declared_attr
    def created_at(cls):
        return Column(DateTime(timezone=True), server_default=func.now(), default=lambda: datetime.now(timezone.utc), nullable=False)

    @declared_attr
    def updated_at(cls):
        return Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            default=lambda: datetime.now(timezone.utc),
            nullable=False
        )
