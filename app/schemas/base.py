"""
Base schemas with common fields and utilities.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class BaseSchema(BaseModel):
    """Base schema with common configuration."""
    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )

class TimestampSchema(BaseSchema):
    """Schema with timestamp fields."""
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

class IDSchema(BaseSchema):
    """Schema with ID field."""
    id: Optional[int] = Field(None, description="Unique identifier")

class UUIDSchema(BaseSchema):
    """Schema with UUID field."""
    id: Optional[str] = Field(None, description="Unique identifier (UUID)")

class PaginationSchema(BaseSchema):
    """Schema for pagination parameters."""
    page: int = Field(1, ge=1, description="Page number")
    size: int = Field(20, ge=1, le=100, description="Page size")
    total: Optional[int] = Field(None, description="Total number of items")

class PaginatedResponseSchema(BaseSchema):
    """Schema for paginated responses."""
    items: list = Field(description="List of items")
    pagination: PaginationSchema = Field(description="Pagination information")

class MessageSchema(BaseSchema):
    """Schema for simple message responses."""
    message: str = Field(description="Response message")
    type: Optional[str] = Field(None, description="Message type (success, error, warning, info)")

class ErrorSchema(BaseSchema):
    """Schema for error responses."""
    detail: str = Field(description="Error detail")
    type: str = Field(description="Error type")
    code: Optional[str] = Field(None, description="Error code")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

class SuccessSchema(BaseSchema):
    """Schema for success responses."""
    success: bool = Field(True, description="Success status")
    message: str = Field(description="Success message")
    data: Optional[dict] = Field(None, description="Response data")
