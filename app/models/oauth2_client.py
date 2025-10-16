"""
OAuth 2.0 Client model for OpenID Connect applications.
"""

from sqlalchemy import Column, String, Text, Boolean, DateTime, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel
from app.core.crypto import ClientSecretHasher
from sqlalchemy import event


class OAuth2Client(BaseModel):
    """OAuth 2.0 Client model for OpenID Connect applications."""

    __tablename__ = "oauth2_clients"

    # Additional indexes for performance optimization
    __table_args__ = (
        # Index for filtering active clients
        Index('idx_oauth2_client_is_active', 'is_active'),
        # Composite index for active client queries
        Index('idx_oauth2_client_active_created', 'is_active', 'created_at'),
    )

    client_id = Column(String(255), unique=True, nullable=False, index=True)
    client_secret = Column(String(255), nullable=False)  # Hashed client secret
    name = Column(String(255), nullable=False)
    redirect_uris = Column(Text, nullable=False)  # JSON string of redirect URIs
    scopes = Column(Text, nullable=False)  # JSON string of allowed scopes
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    secret_last_rotated = Column(DateTime(timezone=True), nullable=True)  # Track when secret was last rotated

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

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Store plain secret temporarily if provided (for registration response)
        self._plain_secret = kwargs.get('client_secret')
        # Set initial rotation time
        if 'secret_last_rotated' not in kwargs and hasattr(self, 'created_at'):
            from datetime import datetime, timezone
            self.secret_last_rotated = datetime.now(timezone.utc)

    def set_client_secret(self, plain_secret: str):
        """Set and hash a new client secret."""
        from datetime import datetime, timezone
        self.client_secret = ClientSecretHasher.hash_secret(plain_secret)
        self.secret_last_rotated = datetime.now(timezone.utc)

    def verify_client_secret(self, plain_secret: str) -> bool:
        """Verify a plain client secret against the hashed secret."""
        try:
            return ClientSecretHasher.verify_secret(plain_secret, self.client_secret)
        except Exception:
            return False

    def rotate_client_secret(self) -> str:
        """Generate and set a new client secret. Returns the plain secret."""
        import secrets
        import string

        # Generate a new secure secret
        new_secret = secrets.token_urlsafe(64)

        # Hash and store it
        self.set_client_secret(new_secret)

        return new_secret

    @property
    def plain_secret(self) -> str:
        """Get the plain client secret (only available temporarily after creation)."""
        return getattr(self, '_plain_secret', None)

    def generate_registration_token(self):
        """Generate a secure registration access token."""
        import secrets
        import string
        from app.models.oauth2_client_token import OAuth2ClientToken

        # Generate a secure token
        token_value = secrets.token_urlsafe(64)

        # Create token record in database
        token_record = OAuth2ClientToken(
            client_id=self.id,
            token=token_value,
            token_type="registration"
        )

        return token_record


# Event listener to hash client secret before insert
@event.listens_for(OAuth2Client, 'before_insert')
def hash_client_secret_before_insert(mapper, connection, target):
    """Hash the client secret before inserting into database."""
    if hasattr(target, '_plain_secret') and target._plain_secret:
        target.set_client_secret(target._plain_secret)
