"""
Base SQLAlchemy models with common fields and utilities.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, String, Text, Boolean
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.sql import func

from app.core.database import Base

class TimestampMixin:
    """Mixin for timestamp fields."""
    
    @declared_attr
    def created_at(cls):
        return Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    @declared_attr
    def updated_at(cls):
        return Column(
            DateTime(timezone=True), 
            server_default=func.now(), 
            onupdate=func.now(), 
            nullable=False
        )

class SoftDeleteMixin:
    """Mixin for soft delete functionality."""
    
    @declared_attr
    def deleted_at(cls):
        return Column(DateTime(timezone=True), nullable=True)
    
    @declared_attr
    def is_deleted(cls):
        return Column(Boolean, default=False, nullable=False)

class AuditMixin:
    """Mixin for audit fields."""
    
    @declared_attr
    def created_by(cls):
        return Column(String(255), nullable=True)
    
    @declared_attr
    def updated_by(cls):
        return Column(String(255), nullable=True)

class BaseModel(Base, TimestampMixin):
    """Base model with common fields."""
    
    __abstract__ = True
    
    @declared_attr
    def id(cls):
        return Column(Integer, primary_key=True, index=True)
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    def update_from_dict(self, data: dict):
        """Update model from dictionary."""
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

class UUIDBaseModel(Base, TimestampMixin):
    """Base model with UUID primary key."""
    
    __abstract__ = True
    
    @declared_attr
    def id(cls):
        return Column(String(36), primary_key=True, index=True)
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    def update_from_dict(self, data: dict):
        """Update model from dictionary."""
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
