"""
Audit Log model for tracking security events and user actions.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class AuditLog(BaseModel):
    """Audit Log model for security event tracking."""

    __tablename__ = "audit_logs"

    user_id = Column(Integer, nullable=True, index=True)  # Nullable for system events
    action = Column(String(100), nullable=False, index=True)  # login, logout, password_change, etc.
    resource = Column(String(255), nullable=True, index=True)  # user, role, permission, etc.
    resource_id = Column(String(255), nullable=True)  # ID of the affected resource
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6 address
    user_agent = Column(Text, nullable=True)  # Browser/client user agent
    details = Column(Text, nullable=True)  # Additional JSON details
    success = Column(Boolean, default=True, nullable=False)

    # Additional indexes for performance optimization
    __table_args__ = (
        # Index for time-based queries
        Index('idx_audit_log_created_at', 'created_at'),
        # Composite index for user activity history
        Index('idx_audit_log_user_created', 'user_id', 'created_at'),
        # Composite index for action analytics
        Index('idx_audit_log_action_created', 'action', 'created_at'),
        # Composite index for resource change tracking
        Index('idx_audit_log_resource_created', 'resource', 'created_at'),
    )

    # Relationships
    user = relationship("User", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog(user_id={self.user_id}, action='{self.action}', resource='{self.resource}')>"

    @property
    def is_success(self):
        """Check if the action was successful."""
        return self.success

    @property
    def is_failure(self):
        """Check if the action failed."""
        return not self.success

    @classmethod
    def log_event(cls, db_session, user_id=None, action=None, resource=None, resource_id=None,
                  ip_address=None, user_agent=None, details=None, success=True):
        """Create and save an audit log entry."""
        import json

        audit_log = cls(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )

        if details:
            if isinstance(details, dict):
                audit_log.details = json.dumps(details)
            else:
                audit_log.details = str(details)

        db_session.add(audit_log)
        return audit_log

    @classmethod
    def log_login(cls, db_session, user_id, ip_address=None, user_agent=None, success=True):
        """Log a user login attempt."""
        return cls.log_event(
            db_session=db_session,
            user_id=user_id,
            action="login",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details={"event_type": "authentication", "method": "password"}
        )

    @classmethod
    def log_logout(cls, db_session, user_id, ip_address=None, user_agent=None):
        """Log a user logout."""
        return cls.log_event(
            db_session=db_session,
            user_id=user_id,
            action="logout",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"event_type": "authentication"}
        )

    @classmethod
    def log_password_change(cls, db_session, user_id, ip_address=None, user_agent=None, success=True):
        """Log a password change attempt."""
        return cls.log_event(
            db_session=db_session,
            user_id=user_id,
            action="password_change",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details={"event_type": "security", "action_type": "password_update"}
        )

    @classmethod
    def log_mfa_enable(cls, db_session, user_id, ip_address=None, user_agent=None, success=True):
        """Log MFA enable/disable."""
        return cls.log_event(
            db_session=db_session,
            user_id=user_id,
            action="mfa_enable",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details={"event_type": "security", "action_type": "mfa_setup"}
        )

    @classmethod
    def log_role_assignment(cls, db_session, admin_user_id, target_user_id, role_id,
                           ip_address=None, user_agent=None, success=True):
        """Log role assignment/removal."""
        return cls.log_event(
            db_session=db_session,
            user_id=admin_user_id,
            action="role_assignment",
            resource="user",
            resource_id=str(target_user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details={
                "event_type": "authorization",
                "target_user_id": target_user_id,
                "role_id": role_id,
                "action_type": "role_assignment"
            }
        )

    @classmethod
    def log_permission_change(cls, db_session, admin_user_id, resource, action,
                             ip_address=None, user_agent=None, success=True):
        """Log permission creation/modification."""
        return cls.log_event(
            db_session=db_session,
            user_id=admin_user_id,
            action="permission_change",
            resource=resource,
            resource_id=f"{resource}:{action}",
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details={
                "event_type": "authorization",
                "action_type": "permission_management",
                "permission": f"{resource}:{action}"
            }
        )

    def get_details(self):
        """Get audit log details as a dictionary."""
        import json
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except (json.JSONDecodeError, TypeError):
            return {"raw_details": self.details}

    def to_dict(self):
        """Convert audit log to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "success": self.is_success,
            "details": self.get_details(),
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
