"""
OAuth 2.0 Client model for OpenID Connect applications.
"""

from sqlalchemy import Column, String, Text, Boolean
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class OAuth2Client(BaseModel):
    """OAuth 2.0 Client model for OpenID Connect applications."""

    __tablename__ = "oauth2_clients"

    client_id = Column(String(255), unique=True, nullable=False, index=True)
    client_secret = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    redirect_uris = Column(Text, nullable=False)  # JSON string of redirect URIs
    scopes = Column(Text, nullable=False)  # JSON string of allowed scopes
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationship to tokens (optional - can be added later if needed)
    # tokens = relationship("OAuth2Token", back_populates="client")

    def __repr__(self):
        return f"<OAuth2Client(id={self.id}, client_id='{self.client_id}', name='{self.name}')>"

    @property
    def is_client_active(self):
        """Check if client is active."""
        return self.is_active

    def get_redirect_uris(self):
        """Get list of redirect URIs from JSON string."""
        import json
        try:
            return json.loads(self.redirect_uris)
        except (json.JSONDecodeError, TypeError):
            return []

    def get_scopes(self):
        """Get list of scopes from JSON string."""
        import json
        try:
            return json.loads(self.scopes)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_redirect_uris(self, uris):
        """Set redirect URIs as JSON string."""
        import json
        self.redirect_uris = json.dumps(uris) if uris else "[]"

    def set_scopes(self, scope_list):
        """Set scopes as JSON string."""
        import json
        self.scopes = json.dumps(scope_list) if scope_list else "[]"
