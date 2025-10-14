"""
Role-Based Access Control (RBAC) implementation with Redis caching.

This module provides permission checking logic with resource-level and action-level granularity.
Frequently accessed permissions are cached in Redis for improved performance.
"""

from typing import List, Optional, Set
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
import logging
import asyncio

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.user_role import UserRole
from app.models.role_permission import RolePermission
from app.core.database import get_db
from app.middleware import get_current_user_or_401
from app.core.cache import RBACCache

logger = logging.getLogger(__name__)


class PermissionChecker:
    """
    Utility class for checking user permissions.
    
    Provides methods for resource-level and action-level permission granularity.
    """
    
    @staticmethod
    async def get_user_roles(user_id: int, db: Session, use_cache: bool = True) -> List[Role]:
        """
        Get all roles assigned to a user (with optional caching).
        
        Args:
            user_id: The user's ID
            db: Database session
            use_cache: Whether to use Redis cache (default: True)
            
        Returns:
            List of Role objects
        """
        # Try cache first if enabled
        if use_cache:
            try:
                cached_roles = await RBACCache.get_user_roles(user_id)
                if cached_roles is not None:
                    # Convert cached dicts back to Role objects
                    return [Role(id=r['id'], name=r['name'], description=r.get('description')) 
                            for r in cached_roles]
            except Exception as e:
                logger.warning(f"Cache lookup failed for user roles, falling back to database: {e}")
        
        # Fetch from database using a single JOIN query
        roles = db.query(Role).join(
            UserRole, Role.id == UserRole.role_id
        ).filter(
            UserRole.user_id == user_id
        ).all()
        
        # Cache the result if caching is enabled
        if use_cache and roles:
            try:
                roles_data = [{'id': r.id, 'name': r.name, 'description': r.description} 
                             for r in roles]
                await RBACCache.set_user_roles(user_id, roles_data)
            except Exception as e:
                logger.warning(f"Failed to cache user roles: {e}")
        
        return roles
    
    @staticmethod
    async def get_role_permissions(role_id: int, db: Session, use_cache: bool = True) -> List[Permission]:
        """
        Get all permissions assigned to a role (with optional caching).
        
        Args:
            role_id: The role's ID
            db: Database session
            use_cache: Whether to use Redis cache (default: True)
            
        Returns:
            List of Permission objects
        """
        # Try cache first if enabled
        if use_cache:
            try:
                cached_perms = await RBACCache.get_role_permissions(role_id)
                if cached_perms is not None:
                    # Convert cached permission dicts back to Permission objects (no DB query!)
                    return [Permission(
                        id=p['id'], 
                        resource=p['resource'], 
                        action=p['action']
                    ) for p in cached_perms]
            except Exception as e:
                logger.warning(f"Cache lookup failed for role permissions, falling back to database: {e}")
        
        # Fetch from database using a single JOIN query
        permissions = db.query(Permission).join(
            RolePermission, Permission.id == RolePermission.permission_id
        ).filter(
            RolePermission.role_id == role_id
        ).all()
        
        # Cache the result if caching is enabled
        if use_cache and permissions:
            try:
                perms_data = [{
                    'id': perm.id,
                    'resource': perm.resource,
                    'action': perm.action
                } for perm in permissions]
                await RBACCache.set_role_permissions(role_id, perms_data)
            except Exception as e:
                logger.warning(f"Failed to cache role permissions: {e}")
        
        return permissions
    
    @staticmethod
    async def get_user_permissions(user_id: int, db: Session, use_cache: bool = True) -> Set[str]:
        """
        Get all permissions for a user (from all their roles) with caching.
        
        Args:
            user_id: The user's ID
            db: Database session
            use_cache: Whether to use Redis cache (default: True)
            
        Returns:
            Set of permission strings in format "resource:action"
        """
        # Try cache first if enabled
        if use_cache:
            try:
                cached_perms = await RBACCache.get_user_permissions(user_id)
                if cached_perms is not None:
                    return cached_perms
            except Exception as e:
                logger.warning(f"Cache lookup failed for user permissions, falling back to database: {e}")
        
        # Get user's roles
        roles = await PermissionChecker.get_user_roles(user_id, db, use_cache=use_cache)
        
        if not roles:
            return set()
        
        # Get all permissions from all roles
        all_permissions = set()
        for role in roles:
            permissions = await PermissionChecker.get_role_permissions(role.id, db, use_cache=use_cache)
            for perm in permissions:
                all_permissions.add(perm.permission_string)
        
        # Cache the result if caching is enabled
        if use_cache and all_permissions:
            try:
                await RBACCache.set_user_permissions(user_id, all_permissions)
            except Exception as e:
                logger.warning(f"Failed to cache user permissions: {e}")
        
        return all_permissions
    
    @staticmethod
    async def has_permission(user_id: int, resource: str, action: str, db: Session, use_cache: bool = True) -> bool:
        """
        Check if a user has a specific permission (with caching).
        
        Args:
            user_id: The user's ID
            resource: The resource name (e.g., "users", "roles")
            action: The action name (e.g., "create", "read", "update", "delete")
            db: Database session
            use_cache: Whether to use Redis cache (default: True)
            
        Returns:
            True if user has the permission, False otherwise
        """
        # Try cache first if enabled
        if use_cache:
            try:
                cached_result = await RBACCache.get_permission_check(user_id, resource, action)
                if cached_result is not None:
                    logger.debug(f"Cache HIT: Permission check {resource}:{action} for user {user_id} = {cached_result}")
                    return cached_result
            except Exception as e:
                logger.warning(f"Cache lookup failed for permission check, falling back to database: {e}")
        
        # Check permission via user permissions
        permission_string = f"{resource}:{action}"
        user_permissions = await PermissionChecker.get_user_permissions(user_id, db, use_cache=use_cache)
        
        result = permission_string in user_permissions
        
        if result:
            logger.debug(f"User {user_id} has permission {permission_string}")
        else:
            logger.debug(f"User {user_id} does NOT have permission {permission_string}")
        
        # Cache the result if caching is enabled
        if use_cache:
            try:
                await RBACCache.set_permission_check(user_id, resource, action, result)
            except Exception as e:
                logger.warning(f"Failed to cache permission check: {e}")
        
        return result
    
    @staticmethod
    async def has_any_permission(user_id: int, permissions: List[tuple], db: Session, use_cache: bool = True) -> bool:
        """
        Check if a user has any of the specified permissions.
        
        Args:
            user_id: The user's ID
            permissions: List of (resource, action) tuples
            db: Database session
            use_cache: Whether to use cached results
            
        Returns:
            True if user has at least one permission, False otherwise
        """
        user_permissions = await PermissionChecker.get_user_permissions(user_id, db, use_cache=use_cache)
        
        for resource, action in permissions:
            permission_string = f"{resource}:{action}"
            if permission_string in user_permissions:
                logger.debug(f"User {user_id} has permission {permission_string}")
                return True
        
        logger.debug(f"User {user_id} does not have any of the required permissions")
        return False
    
    @staticmethod
    async def has_all_permissions(user_id: int, permissions: List[tuple], db: Session, use_cache: bool = True) -> bool:
        """
        Check if a user has all of the specified permissions.
        
        Args:
            user_id: The user's ID
            permissions: List of (resource, action) tuples
            db: Database session
            use_cache: Whether to use cached results
            
        Returns:
            True if user has all permissions, False otherwise
        """
        user_permissions = await PermissionChecker.get_user_permissions(user_id, db, use_cache=use_cache)
        
        for resource, action in permissions:
            permission_string = f"{resource}:{action}"
            if permission_string not in user_permissions:
                logger.debug(f"User {user_id} does NOT have permission {permission_string}")
                return False
        
        logger.debug(f"User {user_id} has all required permissions")
        return True
    
    @staticmethod
    async def has_role(user_id: int, role_name: str, db: Session) -> bool:
        """
        Check if a user has a specific role.
        
        Args:
            user_id: The user's ID
            role_name: The role name to check
            db: Database session
            
        Returns:
            True if user has the role, False otherwise
        """
        roles = await PermissionChecker.get_user_roles(user_id, db)
        role_names = [role.name for role in roles]
        
        result = role_name in role_names
        
        if result:
            logger.debug(f"User {user_id} has role '{role_name}'")
        else:
            logger.debug(f"User {user_id} does NOT have role '{role_name}'")
        
        return result
    
    @staticmethod
    async def has_any_role(user_id: int, role_names: List[str], db: Session) -> bool:
        """
        Check if a user has any of the specified roles.
        
        Args:
            user_id: The user's ID
            role_names: List of role names to check
            db: Database session
            
        Returns:
            True if user has at least one role, False otherwise
        """
        roles = await PermissionChecker.get_user_roles(user_id, db)
        user_role_names = [role.name for role in roles]
        
        for role_name in role_names:
            if role_name in user_role_names:
                logger.debug(f"User {user_id} has role '{role_name}'")
                return True
        
        logger.debug(f"User {user_id} does not have any of the required roles")
        return False
    
    @staticmethod
    async def get_user_permissions_by_resource(user_id: int, resource: str, db: Session) -> Set[str]:
        """
        Get all actions a user can perform on a specific resource.
        
        Args:
            user_id: The user's ID
            resource: The resource name
            db: Database session
            
        Returns:
            Set of action names (e.g., {"create", "read", "update"})
        """
        all_permissions = await PermissionChecker.get_user_permissions(user_id, db)
        
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
        if not await PermissionChecker.has_permission(current_user.id, resource, action, db):
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
        if not await PermissionChecker.has_any_permission(current_user.id, list(permissions), db):
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
        if not await PermissionChecker.has_all_permissions(current_user.id, list(permissions), db):
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
        if not await PermissionChecker.has_role(current_user.id, role_name, db):
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
        if not await PermissionChecker.has_any_role(current_user.id, list(role_names), db):
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

async def check_user_permission(user: User, resource: str, action: str, db: Session) -> bool:
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
    return await PermissionChecker.has_permission(user.id, resource, action, db)


async def get_user_resource_actions(user: User, resource: str, db: Session) -> Set[str]:
    """
    Get all actions a user can perform on a resource.
    
    Args:
        user: User object
        resource: Resource name
        db: Database session
        
    Returns:
        Set of action names
    """
    return await PermissionChecker.get_user_permissions_by_resource(user.id, resource, db)


async def enforce_permission(user: User, resource: str, action: str, db: Session) -> None:
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
    if not await PermissionChecker.has_permission(user.id, resource, action, db):
        logger.warning(
            f"Permission denied: User {user.id} ({user.username}) attempted {action} on {resource}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: {resource}:{action} required"
        )

