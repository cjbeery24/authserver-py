"""
Base SQLAlchemy models with common fields and utilities.
"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declared_attr

from app.core.database import Base

class BaseModel(Base):
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

class UUIDBaseModel(Base):
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
