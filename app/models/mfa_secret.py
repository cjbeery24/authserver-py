"""
MFA Secret model for storing TOTP secrets and backup codes.
"""

import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class MFASecret(BaseModel):
    """MFA Secret model for TOTP authentication."""

    __tablename__ = "mfa_secrets"

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True, index=True)
    secret = Column(String(32), nullable=False)  # TOTP secret key
    backup_codes = Column(Text, default="[]", nullable=False)  # JSON array of backup codes
    is_enabled = Column(Boolean, default=False, nullable=False)
    backup_codes_expiry = Column(DateTime, nullable=True)  # When backup codes expire

    # Relationships
    user = relationship("User", backref="mfa_secret")

    def __repr__(self):
        return f"<MFASecret(user_id={self.user_id}, is_enabled={self.is_enabled})>"

    @property
    def is_backup_codes_expired(self):
        """Check if backup codes are expired."""
        if not self.backup_codes_expiry:
            return False
        return datetime.now(timezone.utc) > self.backup_codes_expiry

    def generate_secret(self):
        """Generate a new TOTP secret."""
        # Generate 32-character base32 secret
        alphabet = string.ascii_uppercase + string.digits
        self.secret = ''.join(secrets.choice(alphabet) for _ in range(32))
        return self.secret

    def generate_backup_codes(self, count=10, code_length=8, expiry_days=365):
        """Generate backup codes for MFA recovery."""
        codes = []
        for _ in range(count):
            # Generate alphanumeric code
            chars = string.ascii_uppercase + string.digits
            code = ''.join(secrets.choice(chars) for _ in range(code_length))
            codes.append(code)

        self.backup_codes = json.dumps(codes)
        self.backup_codes_expiry = datetime.now(timezone.utc) + timedelta(days=expiry_days)
        return codes

    def get_backup_codes(self):
        """Get list of backup codes."""
        if not self.backup_codes or self.backup_codes == "[]":
            return []
        try:
            codes = json.loads(self.backup_codes)
            return codes if codes else []
        except (json.JSONDecodeError, TypeError):
            return []

    def validate_backup_code(self, code):
        """Validate and consume a backup code."""
        if not self.backup_codes or self.backup_codes == "[]" or self.is_backup_codes_expired:
            return False

        try:
            codes = json.loads(self.backup_codes)
            if not codes:  # Empty array
                return False
            if code in codes:
                # Remove the used code
                codes.remove(code)
                self.backup_codes = json.dumps(codes) if codes else "[]"
                return True
        except (json.JSONDecodeError, TypeError):
            pass

        return False

    def regenerate_backup_codes(self, count=10, code_length=8, expiry_days=365):
        """Regenerate backup codes, invalidating all previous codes."""
        return self.generate_backup_codes(count, code_length, expiry_days)

    @classmethod
    def create_for_user(cls, db_session, user_id, generate_secret=True, generate_backup_codes=True):
        """Create MFA secret for a user."""
        # Check if MFA secret already exists for this user
        existing_secret = db_session.query(cls).filter(cls.user_id == user_id).first()
        if existing_secret:
            raise ValueError(f"MFA secret already exists for user {user_id}")

        mfa_secret = cls(user_id=user_id, is_enabled=False)

        if generate_secret:
            mfa_secret.generate_secret()

        if generate_backup_codes:
            mfa_secret.generate_backup_codes()

        return mfa_secret

    @classmethod
    def get_or_create_for_user(cls, db_session, user_id, generate_secret=True, generate_backup_codes=True):
        """Get existing MFA secret or create new one for a user."""
        existing_secret = db_session.query(cls).filter(cls.user_id == user_id).first()
        if existing_secret:
            return existing_secret

        return cls.create_for_user(
            db_session, user_id, generate_secret, generate_backup_codes
        )
