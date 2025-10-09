"""
Role-Based Access Control (RBAC) implementation.

This module provides permission checking logic with resource-level and action-level granularity.
"""

from typing import List, Optional, Set
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
import logging

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.user_role import UserRole
from app.models.role_permission import RolePermission
from app.core.database import get_db
from app.middleware import get_current_user_or_401

logger = logging.getLogger(__name__)


class PermissionChecker:
    """
    Utility class for checking user permissions.
    
    Provides methods for resource-level and action-level permission granularity.
    """
    
    @staticmethod
    def get_user_roles(user_id: int, db: Session) -> List[Role]:
        """
        Get all roles assigned to a user.
        
        Args:
            user_id: The user's ID
            db: Database session
            
        Returns:
            List of Role objects
        """
        user_roles = db.query(UserRole).filter(UserRole.user_id == user_id).all()
        role_ids = [ur.role_id for ur in user_roles]
        
        if not role_ids:
            return []
        
        roles = db.query(Role).filter(Role.id.in_(role_ids)).all()
        return roles
    
    @staticmethod
    def get_role_permissions(role_id: int, db: Session) -> List[Permission]:
        """
        Get all permissions assigned to a role.
        
        Args:
            role_id: The role's ID
            db: Database session
            
        Returns:
            List of Permission objects
        """
        role_permissions = db.query(RolePermission).filter(
            RolePermission.role_id == role_id
        ).all()
        permission_ids = [rp.permission_id for rp in role_permissions]
        
        if not permission_ids:
            return []
        
        permissions = db.query(Permission).filter(
            Permission.id.in_(permission_ids)
        ).all()
        return permissions
    
    @staticmethod
    def get_user_permissions(user_id: int, db: Session) -> Set[str]:
        """
        Get all permissions for a user (from all their roles).
        
        Args:
            user_id: The user's ID
            db: Database session
            
        Returns:
            Set of permission strings in format "resource:action"
        """
        # Get user's roles
        roles = PermissionChecker.get_user_roles(user_id, db)
        
        if not roles:
            return set()
        
        # Get all permissions from all roles
        all_permissions = set()
        for role in roles:
            permissions = PermissionChecker.get_role_permissions(role.id, db)
            for perm in permissions:
                all_permissions.add(perm.permission_string)
        
        return all_permissions
    
    @staticmethod
    def has_permission(user_id: int, resource: str, action: str, db: Session) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user_id: The user's ID
            resource: The resource name (e.g., "users", "roles")
            action: The action name (e.g., "create", "read", "update", "delete")
            db: Database session
            
        Returns:
            True if user has the permission, False otherwise
        """
        permission_string = f"{resource}:{action}"
        user_permissions = PermissionChecker.get_user_permissions(user_id, db)
        
        result = permission_string in user_permissions
        
        if result:
            logger.debug(f"User {user_id} has permission {permission_string}")
        else:
            logger.debug(f"User {user_id} does NOT have permission {permission_string}")
        
        return result
    
    @staticmethod
    def has_any_permission(user_id: int, permissions: List[tuple], db: Session) -> bool:
        """
        Check if a user has any of the specified permissions.
        
        Args:
            user_id: The user's ID
            permissions: List of (resource, action) tuples
            db: Database session
            
        Returns:
            True if user has at least one permission, False otherwise
        """
        user_permissions = PermissionChecker.get_user_permissions(user_id, db)
        
        for resource, action in permissions:
            permission_string = f"{resource}:{action}"
            if permission_string in user_permissions:
                logger.debug(f"User {user_id} has permission {permission_string}")
                return True
        
        logger.debug(f"User {user_id} does not have any of the required permissions")
        return False
    
    @staticmethod
    def has_all_permissions(user_id: int, permissions: List[tuple], db: Session) -> bool:
        """
        Check if a user has all of the specified permissions.
        
        Args:
            user_id: The user's ID
            permissions: List of (resource, action) tuples
            db: Database session
            
        Returns:
            True if user has all permissions, False otherwise
        """
        user_permissions = PermissionChecker.get_user_permissions(user_id, db)
        
        for resource, action in permissions:
            permission_string = f"{resource}:{action}"
            if permission_string not in user_permissions:
                logger.debug(f"User {user_id} does NOT have permission {permission_string}")
                return False
        
        logger.debug(f"User {user_id} has all required permissions")
        return True
    
    @staticmethod
    def has_role(user_id: int, role_name: str, db: Session) -> bool:
        """
        Check if a user has a specific role.
        
        Args:
            user_id: The user's ID
            role_name: The role name to check
            db: Database session
            
        Returns:
            True if user has the role, False otherwise
        """
        roles = PermissionChecker.get_user_roles(user_id, db)
        role_names = [role.name for role in roles]
        
        result = role_name in role_names
        
        if result:
            logger.debug(f"User {user_id} has role '{role_name}'")
        else:
            logger.debug(f"User {user_id} does NOT have role '{role_name}'")
        
        return result
    
    @staticmethod
    def has_any_role(user_id: int, role_names: List[str], db: Session) -> bool:
        """
        Check if a user has any of the specified roles.
        
        Args:
            user_id: The user's ID
            role_names: List of role names to check
            db: Database session
            
        Returns:
            True if user has at least one role, False otherwise
        """
        roles = PermissionChecker.get_user_roles(user_id, db)
        user_role_names = [role.name for role in roles]
        
        for role_name in role_names:
            if role_name in user_role_names:
                logger.debug(f"User {user_id} has role '{role_name}'")
                return True
        
        logger.debug(f"User {user_id} does not have any of the required roles")
        return False
    
    @staticmethod
    def get_user_permissions_by_resource(user_id: int, resource: str, db: Session) -> Set[str]:
        """
        Get all actions a user can perform on a specific resource.
        
        Args:
            user_id: The user's ID
            resource: The resource name
            db: Database session
            
        Returns:
            Set of action names (e.g., {"create", "read", "update"})
        """
        all_permissions = PermissionChecker.get_user_permissions(user_id, db)
        
        # Filter permissions for the specified resource
        actions = set()
        for perm in all_permissions:
            if perm.startswith(f"{resource}:"):
                action = perm.split(":", 1)[1]
                actions.add(action)
        
        return actions


# ==================== FASTAPI DEPENDENCIES ====================

def require_permission(resource: str, action: str):
    """
    FastAPI dependency factory for requiring a specific permission.
    
    Usage:
        @router.post("/users", dependencies=[Depends(require_permission("users", "create"))])
        async def create_user(...):
            ...
    
    Args:
        resource: The resource name
        action: The action name
        
    Returns:
        Dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_user_or_401),
        db: Session = Depends(get_db)
    ):
        if not PermissionChecker.has_permission(current_user.id, resource, action, db):
            logger.warning(
                f"Permission denied: User {current_user.id} attempted {action} on {resource}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {resource}:{action} required"
            )
        return current_user
    
    return permission_dependency


def require_any_permission(*permissions: tuple):
    """
    FastAPI dependency factory for requiring any of the specified permissions.
    
    Usage:
        @router.get("/admin", dependencies=[Depends(require_any_permission(
            ("users", "read"), ("roles", "read")
        ))])
        async def admin_view(...):
            ...
    
    Args:
        permissions: Variable number of (resource, action) tuples
        
    Returns:
        Dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_user_or_401),
        db: Session = Depends(get_db)
    ):
        if not PermissionChecker.has_any_permission(current_user.id, list(permissions), db):
            logger.warning(
                f"Permission denied: User {current_user.id} lacks any of required permissions"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied: insufficient permissions"
            )
        return current_user
    
    return permission_dependency


def require_all_permissions(*permissions: tuple):
    """
    FastAPI dependency factory for requiring all of the specified permissions.
    
    Usage:
        @router.post("/admin/special", dependencies=[Depends(require_all_permissions(
            ("users", "create"), ("roles", "assign")
        ))])
        async def special_action(...):
            ...
    
    Args:
        permissions: Variable number of (resource, action) tuples
        
    Returns:
        Dependency function
    """
    async def permission_dependency(
        current_user: User = Depends(get_current_user_or_401),
        db: Session = Depends(get_db)
    ):
        if not PermissionChecker.has_all_permissions(current_user.id, list(permissions), db):
            logger.warning(
                f"Permission denied: User {current_user.id} lacks all required permissions"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied: all specified permissions required"
            )
        return current_user
    
    return permission_dependency


def require_role(role_name: str):
    """
    FastAPI dependency factory for requiring a specific role.
    
    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
        async def admin_only(...):
            ...
    
    Args:
        role_name: The role name required
        
    Returns:
        Dependency function
    """
    async def role_dependency(
        current_user: User = Depends(get_current_user_or_401),
        db: Session = Depends(get_db)
    ):
        if not PermissionChecker.has_role(current_user.id, role_name, db):
            logger.warning(
                f"Role check failed: User {current_user.id} attempted access requiring role '{role_name}'"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: '{role_name}' role required"
            )
        return current_user
    
    return role_dependency


def require_any_role(*role_names: str):
    """
    FastAPI dependency factory for requiring any of the specified roles.
    
    Usage:
        @router.get("/moderator", dependencies=[Depends(require_any_role("admin", "moderator"))])
        async def moderator_or_admin(...):
            ...
    
    Args:
        role_names: Variable number of role names
        
    Returns:
        Dependency function
    """
    async def role_dependency(
        current_user: User = Depends(get_current_user_or_401),
        db: Session = Depends(get_db)
    ):
        if not PermissionChecker.has_any_role(current_user.id, list(role_names), db):
            logger.warning(
                f"Role check failed: User {current_user.id} lacks any of required roles"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: insufficient role permissions"
            )
        return current_user
    
    return role_dependency


# ==================== UTILITY FUNCTIONS ====================

def check_user_permission(user: User, resource: str, action: str, db: Session) -> bool:
    """
    Convenience function to check if a user has a specific permission.
    
    Args:
        user: User object
        resource: Resource name
        action: Action name
        db: Database session
        
    Returns:
        True if user has permission, False otherwise
    """
    return PermissionChecker.has_permission(user.id, resource, action, db)


def get_user_resource_actions(user: User, resource: str, db: Session) -> Set[str]:
    """
    Get all actions a user can perform on a resource.
    
    Args:
        user: User object
        resource: Resource name
        db: Database session
        
    Returns:
        Set of action names
    """
    return PermissionChecker.get_user_permissions_by_resource(user.id, resource, db)


def enforce_permission(user: User, resource: str, action: str, db: Session) -> None:
    """
    Enforce that a user has a specific permission, raising an exception if not.
    
    Args:
        user: User object
        resource: Resource name
        action: Action name
        db: Database session
        
    Raises:
        HTTPException: If user lacks the required permission
    """
    if not PermissionChecker.has_permission(user.id, resource, action, db):
        logger.warning(
            f"Permission denied: User {user.id} ({user.username}) attempted {action} on {resource}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: {resource}:{action} required"
        )

