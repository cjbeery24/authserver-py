"""
Administrative API endpoints for user, role, and permission management.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, List
import logging

from app.core.database import get_db
from app.core.config import settings
from app.core.rbac import PermissionChecker
from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.user_role import UserRole
from app.models.role_permission import RolePermission
from app.models.audit_log import AuditLog
from app.middleware import get_current_user_or_401
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger(__name__)


# ==================== SCHEMAS ====================

# Role schemas
class RoleCreateRequest(BaseModel):
    """Request model for creating a role."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

    class Config:
        json_schema_extra = {
            "example": {
                "name": "admin",
                "description": "Administrator role with full access"
            }
        }


class RoleUpdateRequest(BaseModel):
    """Request model for updating a role."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

    class Config:
        json_schema_extra = {
            "example": {
                "name": "super_admin",
                "description": "Updated description for super admin"
            }
        }


class RoleResponse(BaseModel):
    """Response model for role information."""
    id: int
    name: str
    description: Optional[str]
    created_at: str
    updated_at: str
    user_count: Optional[int] = 0
    permission_count: Optional[int] = 0

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "admin",
                "description": "Administrator role",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
                "user_count": 5,
                "permission_count": 20
            }
        }


# Permission schemas
class PermissionCreateRequest(BaseModel):
    """Request model for creating a permission."""
    resource: str = Field(..., min_length=1, max_length=100)
    action: str = Field(..., min_length=1, max_length=50)

    class Config:
        json_schema_extra = {
            "example": {
                "resource": "users",
                "action": "create"
            }
        }


class PermissionResponse(BaseModel):
    """Response model for permission information."""
    id: int
    resource: str
    action: str
    permission_string: str
    created_at: str
    updated_at: str

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "resource": "users",
                "action": "create",
                "permission_string": "users:create",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z"
            }
        }


# User-Role assignment schemas
class UserRoleAssignRequest(BaseModel):
    """Request model for assigning a role to a user."""
    user_id: int = Field(..., gt=0)
    role_id: int = Field(..., gt=0)

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 1,
                "role_id": 2
            }
        }


# Role-Permission assignment schemas
class RolePermissionAssignRequest(BaseModel):
    """Request model for assigning a permission to a role."""
    role_id: int = Field(..., gt=0)
    permission_id: int = Field(..., gt=0)

    class Config:
        json_schema_extra = {
            "example": {
                "role_id": 1,
                "permission_id": 3
            }
        }


# User management schemas
class AdminUserResponse(BaseModel):
    """Response model for user information in admin context."""
    id: int
    username: str
    email: str
    is_active: bool
    created_at: str
    updated_at: str
    roles: List[str] = []

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "johndoe",
                "email": "john.doe@example.com",
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
                "roles": ["user", "moderator"]
            }
        }


class UserDeactivateRequest(BaseModel):
    """Request model for deactivating a user account."""
    reason: Optional[str] = Field(None, max_length=500)

    class Config:
        json_schema_extra = {
            "example": {
                "reason": "Account suspended due to policy violation"
            }
        }


# Dashboard schemas
class DashboardStatsResponse(BaseModel):
    """Response model for dashboard statistics."""
    total_users: int
    active_users: int
    inactive_users: int
    total_roles: int
    total_permissions: int
    recent_logins: int
    failed_logins_24h: int
    recent_registrations: int

    class Config:
        json_schema_extra = {
            "example": {
                "total_users": 1250,
                "active_users": 1100,
                "inactive_users": 150,
                "total_roles": 5,
                "total_permissions": 45,
                "recent_logins": 320,
                "failed_logins_24h": 12,
                "recent_registrations": 45
            }
        }


# ==================== HELPER FUNCTIONS ====================

def _get_client_info(request: Request) -> tuple:
    """Extract client IP and user agent from request."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return ip_address, user_agent


async def _require_admin(current_user: User = Depends(get_current_user_or_401), db: Session = Depends(get_db)) -> User:
    """
    Dependency to require admin role.
    
    Checks if the user has the 'admin' role or 'admin:access' permission.
    """
    # Check if user has admin role or admin:access permission
    has_admin_role = await PermissionChecker.has_role(current_user.id, "admin", db)
    has_admin_permission = await PermissionChecker.has_permission(current_user.id, "admin", "access", db)
    
    if not (has_admin_role or has_admin_permission):
        logger.warning(
            f"Unauthorized admin access attempt by user {current_user.id} ({current_user.username})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: admin role or admin:access permission required"
        )
    
    return current_user


# ==================== ROLE MANAGEMENT ENDPOINTS ====================
#
# Note: These endpoints use the _require_admin dependency which checks for 'admin' role
# or 'admin:access' permission. For more granular control, you can use RBAC dependencies:
#
# from app.core.rbac import require_permission, require_role
# 
# Examples:
# - dependencies=[Depends(require_permission("roles", "create"))]
# - dependencies=[Depends(require_role("admin"))]
# - dependencies=[Depends(require_any_role("admin", "moderator"))]
#

@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED,
            dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def create_role(
    request: Request,
    role_data: RoleCreateRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Create a new role.
    
    Requires admin permissions.
    """
    # Check if role name already exists
    existing_role = db.query(Role).filter(Role.name == role_data.name).first()
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{role_data.name}' already exists"
        )
    
    try:
        # Create the role
        role = Role(
            name=role_data.name,
            description=role_data.description
        )
        db.add(role)
        db.commit()
        db.refresh(role)
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="role_create",
            resource="role",
            resource_id=str(role.id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"role_name": role.name}
        )
        db.commit()
        
        logger.info(f"Role '{role.name}' created by user {current_user.id}")
        
        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
            user_count=0,
            permission_count=0
        )
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role"
        )


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """
    List all roles with user and permission counts.
    
    Requires admin permissions.
    """
    # Optimized query using subqueries to avoid N+1 pattern
    from sqlalchemy import func, select
    
    # Subquery for user counts
    user_count_subq = select(
        UserRole.role_id,
        func.count(UserRole.user_id).label('user_count')
    ).group_by(UserRole.role_id).subquery()
    
    # Subquery for permission counts
    perm_count_subq = select(
        RolePermission.role_id,
        func.count(RolePermission.permission_id).label('permission_count')
    ).group_by(RolePermission.role_id).subquery()
    
    # Join role with both subqueries
    roles_with_counts = db.query(
        Role,
        func.coalesce(user_count_subq.c.user_count, 0).label('user_count'),
        func.coalesce(perm_count_subq.c.permission_count, 0).label('permission_count')
    ).outerjoin(
        user_count_subq, Role.id == user_count_subq.c.role_id
    ).outerjoin(
        perm_count_subq, Role.id == perm_count_subq.c.role_id
    ).offset(skip).limit(limit).all()
    
    role_responses = []
    for role, user_count, permission_count in roles_with_counts:
        role_responses.append(RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
            user_count=int(user_count),
            permission_count=int(permission_count)
        ))
    
    return role_responses


@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get details of a specific role.
    
    Requires admin permissions.
    """
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {role_id} not found"
        )
    
    # Count users and permissions
    user_count = db.query(UserRole).filter(UserRole.role_id == role.id).count()
    permission_count = db.query(RolePermission).filter(RolePermission.role_id == role.id).count()
    
    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        created_at=role.created_at.isoformat(),
        updated_at=role.updated_at.isoformat(),
        user_count=user_count,
        permission_count=permission_count
    )


@router.put("/roles/{role_id}", response_model=RoleResponse,
           dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def update_role(
    request: Request,
    role_id: int,
    role_data: RoleUpdateRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Update an existing role.
    
    Requires admin permissions.
    """
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {role_id} not found"
        )
    
    # Check if new name conflicts with existing role
    if role_data.name and role_data.name != role.name:
        existing_role = db.query(Role).filter(Role.name == role_data.name).first()
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role name '{role_data.name}' already exists"
            )
    
    try:
        # Update role fields
        if role_data.name:
            role.name = role_data.name
        if role_data.description is not None:
            role.description = role_data.description
        
        db.commit()
        db.refresh(role)
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="role_update",
            resource="role",
            resource_id=str(role.id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"role_name": role.name}
        )
        db.commit()
        
        logger.info(f"Role {role.id} updated by user {current_user.id}")
        
        # Get counts
        user_count = db.query(UserRole).filter(UserRole.role_id == role.id).count()
        permission_count = db.query(RolePermission).filter(RolePermission.role_id == role.id).count()
        
        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
            user_count=user_count,
            permission_count=permission_count
        )
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )


@router.delete("/roles/{role_id}", status_code=status.HTTP_200_OK,
              dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def delete_role(
    request: Request,
    role_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete a role.
    
    Requires admin permissions.
    This will also remove all user-role and role-permission associations.
    """
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {role_id} not found"
        )
    
    try:
        role_name = role.name
        
        # Delete associated user-role assignments
        db.query(UserRole).filter(UserRole.role_id == role_id).delete()
        
        # Delete associated role-permission assignments
        db.query(RolePermission).filter(RolePermission.role_id == role_id).delete()
        
        # Delete the role
        db.delete(role)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="role_delete",
            resource="role",
            resource_id=str(role_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"role_name": role_name}
        )
        db.commit()
        
        logger.warning(f"Role '{role_name}' (ID: {role_id}) deleted by user {current_user.id}")
        
        return {
            "message": f"Role '{role_name}' deleted successfully",
            "role_id": role_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )


# ==================== PERMISSION MANAGEMENT ENDPOINTS ====================

@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED,
            dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def create_permission(
    request: Request,
    permission_data: PermissionCreateRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Create a new permission.
    
    Requires admin permissions.
    """
    # Check if permission already exists
    existing_permission = db.query(Permission).filter(
        Permission.resource == permission_data.resource,
        Permission.action == permission_data.action
    ).first()
    
    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Permission '{permission_data.resource}:{permission_data.action}' already exists"
        )
    
    try:
        # Create the permission
        permission = Permission(
            resource=permission_data.resource,
            action=permission_data.action
        )
        db.add(permission)
        db.commit()
        db.refresh(permission)
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_permission_change(
            db_session=db,
            admin_user_id=current_user.id,
            resource=permission.resource,
            action=permission.action,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        db.commit()
        
        logger.info(f"Permission '{permission.permission_string}' created by user {current_user.id}")
        
        return PermissionResponse(
            id=permission.id,
            resource=permission.resource,
            action=permission.action,
            permission_string=permission.permission_string,
            created_at=permission.created_at.isoformat(),
            updated_at=permission.updated_at.isoformat()
        )
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create permission"
        )


@router.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    resource: Optional[str] = None
):
    """
    List all permissions, optionally filtered by resource.
    
    Requires admin permissions.
    """
    query = db.query(Permission)
    
    if resource:
        query = query.filter(Permission.resource == resource)
    
    permissions = query.offset(skip).limit(limit).all()
    
    return [
        PermissionResponse(
            id=perm.id,
            resource=perm.resource,
            action=perm.action,
            permission_string=perm.permission_string,
            created_at=perm.created_at.isoformat(),
            updated_at=perm.updated_at.isoformat()
        )
        for perm in permissions
    ]


@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
async def get_permission(
    permission_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get details of a specific permission.
    
    Requires admin permissions.
    """
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission with ID {permission_id} not found"
        )
    
    return PermissionResponse(
        id=permission.id,
        resource=permission.resource,
        action=permission.action,
        permission_string=permission.permission_string,
        created_at=permission.created_at.isoformat(),
        updated_at=permission.updated_at.isoformat()
    )


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_200_OK,
              dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def delete_permission(
    request: Request,
    permission_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete a permission.
    
    Requires admin permissions.
    This will also remove all role-permission associations.
    """
    permission = db.query(Permission).filter(Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission with ID {permission_id} not found"
        )
    
    try:
        permission_string = permission.permission_string
        
        # Delete associated role-permission assignments
        db.query(RolePermission).filter(RolePermission.permission_id == permission_id).delete()
        
        # Delete the permission
        db.delete(permission)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="permission_delete",
            resource=permission.resource,
            resource_id=str(permission_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"permission": permission_string}
        )
        db.commit()
        
        logger.warning(f"Permission '{permission_string}' (ID: {permission_id}) deleted by user {current_user.id}")
        
        return {
            "message": f"Permission '{permission_string}' deleted successfully",
            "permission_id": permission_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete permission"
        )


# ==================== USER-ROLE ASSIGNMENT ENDPOINTS ====================

@router.post("/user-roles", status_code=status.HTTP_201_CREATED,
            dependencies=[Depends(RateLimiter(times=20, minutes=1))])
async def assign_role_to_user(
    request: Request,
    assignment: UserRoleAssignRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Assign a role to a user.
    
    Requires admin permissions.
    """
    # Verify user exists
    user = db.query(User).filter(User.id == assignment.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {assignment.user_id} not found"
        )
    
    # Verify role exists
    role = db.query(Role).filter(Role.id == assignment.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {assignment.role_id} not found"
        )
    
    # Check if assignment already exists
    existing_assignment = db.query(UserRole).filter(
        UserRole.user_id == assignment.user_id,
        UserRole.role_id == assignment.role_id
    ).first()
    
    if existing_assignment:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User {user.username} already has role '{role.name}'"
        )
    
    try:
        # Create the assignment
        user_role = UserRole(
            user_id=assignment.user_id,
            role_id=assignment.role_id
        )
        db.add(user_role)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_role_assignment(
            db_session=db,
            admin_user_id=current_user.id,
            target_user_id=assignment.user_id,
            role_id=assignment.role_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True
        )
        db.commit()
        
        # Invalidate cache for this user
        from app.core.cache import RBACCache
        await RBACCache.invalidate_user(assignment.user_id)
        
        logger.info(f"Role '{role.name}' assigned to user {user.username} by admin {current_user.id}")
        
        return {
            "message": f"Role '{role.name}' assigned to user '{user.username}' successfully",
            "user_id": assignment.user_id,
            "role_id": assignment.role_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error assigning role to user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign role to user"
        )


@router.delete("/user-roles", status_code=status.HTTP_200_OK,
              dependencies=[Depends(RateLimiter(times=20, minutes=1))])
async def remove_role_from_user(
    request: Request,
    assignment: UserRoleAssignRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Remove a role from a user.
    
    Requires admin permissions.
    """
    # Verify user exists
    user = db.query(User).filter(User.id == assignment.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {assignment.user_id} not found"
        )
    
    # Verify role exists
    role = db.query(Role).filter(Role.id == assignment.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {assignment.role_id} not found"
        )
    
    # Find the assignment
    user_role = db.query(UserRole).filter(
        UserRole.user_id == assignment.user_id,
        UserRole.role_id == assignment.role_id
    ).first()
    
    if not user_role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user.username}' does not have role '{role.name}'"
        )
    
    try:
        # Remove the assignment
        db.delete(user_role)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="role_removal",
            resource="user",
            resource_id=str(assignment.user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={
                "event_type": "authorization",
                "target_user_id": assignment.user_id,
                "role_id": assignment.role_id,
                "role_name": role.name,
                "action_type": "role_removal"
            }
        )
        db.commit()
        
        # Invalidate cache for this user
        from app.core.cache import RBACCache
        await RBACCache.invalidate_user(assignment.user_id)
        
        logger.info(f"Role '{role.name}' removed from user {user.username} by admin {current_user.id}")
        
        return {
            "message": f"Role '{role.name}' removed from user '{user.username}' successfully",
            "user_id": assignment.user_id,
            "role_id": assignment.role_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error removing role from user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove role from user"
        )


@router.get("/users/{user_id}/roles", response_model=List[RoleResponse])
async def get_user_roles(
    user_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get all roles assigned to a specific user.
    
    Requires admin permissions.
    """
    # Verify user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Use PermissionChecker to get roles (benefits from caching)
    roles = await PermissionChecker.get_user_roles(user_id, db)
    
    return [
        RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at.isoformat(),
            updated_at=role.updated_at.isoformat(),
            user_count=db.query(UserRole).filter(UserRole.role_id == role.id).count(),
            permission_count=db.query(RolePermission).filter(RolePermission.role_id == role.id).count()
        )
        for role in roles
    ]


# ==================== ROLE-PERMISSION ASSIGNMENT ENDPOINTS ====================

@router.post("/role-permissions", status_code=status.HTTP_201_CREATED,
            dependencies=[Depends(RateLimiter(times=20, minutes=1))])
async def assign_permission_to_role(
    request: Request,
    assignment: RolePermissionAssignRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Assign a permission to a role.
    
    Requires admin permissions.
    """
    # Verify role exists
    role = db.query(Role).filter(Role.id == assignment.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {assignment.role_id} not found"
        )
    
    # Verify permission exists
    permission = db.query(Permission).filter(Permission.id == assignment.permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission with ID {assignment.permission_id} not found"
        )
    
    # Check if assignment already exists
    existing_assignment = db.query(RolePermission).filter(
        RolePermission.role_id == assignment.role_id,
        RolePermission.permission_id == assignment.permission_id
    ).first()
    
    if existing_assignment:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{role.name}' already has permission '{permission.permission_string}'"
        )
    
    try:
        # Create the assignment
        role_permission = RolePermission(
            role_id=assignment.role_id,
            permission_id=assignment.permission_id
        )
        db.add(role_permission)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="permission_assignment",
            resource="role",
            resource_id=str(assignment.role_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={
                "event_type": "authorization",
                "role_name": role.name,
                "permission": permission.permission_string,
                "action_type": "permission_assignment"
            }
        )
        db.commit()
        
        # Invalidate cache for this role
        from app.core.cache import RBACCache
        await RBACCache.invalidate_role(assignment.role_id)
        
        logger.info(f"Permission '{permission.permission_string}' assigned to role '{role.name}' by admin {current_user.id}")
        
        return {
            "message": f"Permission '{permission.permission_string}' assigned to role '{role.name}' successfully",
            "role_id": assignment.role_id,
            "permission_id": assignment.permission_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error assigning permission to role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign permission to role"
        )


@router.delete("/role-permissions", status_code=status.HTTP_200_OK,
              dependencies=[Depends(RateLimiter(times=20, minutes=1))])
async def remove_permission_from_role(
    request: Request,
    assignment: RolePermissionAssignRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Remove a permission from a role.
    
    Requires admin permissions.
    """
    # Verify role exists
    role = db.query(Role).filter(Role.id == assignment.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {assignment.role_id} not found"
        )
    
    # Verify permission exists
    permission = db.query(Permission).filter(Permission.id == assignment.permission_id).first()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission with ID {assignment.permission_id} not found"
        )
    
    # Find the assignment
    role_permission = db.query(RolePermission).filter(
        RolePermission.role_id == assignment.role_id,
        RolePermission.permission_id == assignment.permission_id
    ).first()
    
    if not role_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role '{role.name}' does not have permission '{permission.permission_string}'"
        )
    
    try:
        # Remove the assignment
        db.delete(role_permission)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="permission_removal",
            resource="role",
            resource_id=str(assignment.role_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={
                "event_type": "authorization",
                "role_name": role.name,
                "permission": permission.permission_string,
                "action_type": "permission_removal"
            }
        )
        db.commit()
        
        # Invalidate cache for this role
        from app.core.cache import RBACCache
        await RBACCache.invalidate_role(assignment.role_id)
        
        logger.info(f"Permission '{permission.permission_string}' removed from role '{role.name}' by admin {current_user.id}")
        
        return {
            "message": f"Permission '{permission.permission_string}' removed from role '{role.name}' successfully",
            "role_id": assignment.role_id,
            "permission_id": assignment.permission_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error removing permission from role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove permission from role"
        )


@router.get("/roles/{role_id}/permissions", response_model=List[PermissionResponse])
async def get_role_permissions(
    role_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get all permissions assigned to a specific role.
    
    Requires admin permissions.
    """
    # Verify role exists
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role with ID {role_id} not found"
        )
    
    # Use PermissionChecker to get role permissions (benefits from caching)
    permissions = await PermissionChecker.get_role_permissions(role_id, db)
    
    return [
        PermissionResponse(
            id=perm.id,
            resource=perm.resource,
            action=perm.action,
            permission_string=perm.permission_string,
            created_at=perm.created_at.isoformat(),
            updated_at=perm.updated_at.isoformat()
        )
        for perm in permissions
    ]


# ==================== USER MANAGEMENT ENDPOINTS ====================

@router.get("/users", response_model=List[AdminUserResponse])
async def list_users(
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False
):
    """
    List all users with their roles.
    
    Requires admin permissions.
    """
    from sqlalchemy import func
    from sqlalchemy.orm import joinedload
    
    query = db.query(User)
    
    if active_only:
        query = query.filter(User.is_active == True)
    
    users = query.offset(skip).limit(limit).all()
    
    # Optimize: Fetch all user-role mappings for these users in one query
    user_ids = [u.id for u in users]
    if user_ids:
        user_roles_query = db.query(
            UserRole.user_id,
            Role.name
        ).join(
            Role, UserRole.role_id == Role.id
        ).filter(
            UserRole.user_id.in_(user_ids)
        ).all()
        
        # Build a mapping of user_id -> list of role names
        user_roles_map = {}
        for user_id, role_name in user_roles_query:
            if user_id not in user_roles_map:
                user_roles_map[user_id] = []
            user_roles_map[user_id].append(role_name)
    else:
        user_roles_map = {}
    
    # Build responses using the pre-fetched data
    user_responses = []
    for user in users:
        user_responses.append(AdminUserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            is_active=user.is_active,
            created_at=user.created_at.isoformat(),
            updated_at=user.updated_at.isoformat(),
            roles=user_roles_map.get(user.id, [])
        ))
    
    return user_responses


@router.get("/users/{user_id}", response_model=AdminUserResponse)
async def get_user_details(
    user_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific user.
    
    Requires admin permissions.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Use PermissionChecker to get roles (benefits from caching)
    roles = await PermissionChecker.get_user_roles(user.id, db)
    role_names = [role.name for role in roles]
    
    return AdminUserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        updated_at=user.updated_at.isoformat(),
        roles=role_names
    )


@router.post("/users/{user_id}/deactivate", status_code=status.HTTP_200_OK,
            dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def deactivate_user(
    request: Request,
    user_id: int,
    deactivate_data: UserDeactivateRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Deactivate a user account.
    
    Requires admin permissions.
    This sets is_active to False but preserves the account.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User '{user.username}' is already deactivated"
        )
    
    try:
        # Deactivate the user
        user.is_active = False
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="user_deactivate",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={
                "target_user": user.username,
                "reason": deactivate_data.reason
            }
        )
        db.commit()
        
        logger.warning(f"User '{user.username}' (ID: {user_id}) deactivated by admin {current_user.id}")
        
        return {
            "message": f"User '{user.username}' deactivated successfully",
            "user_id": user_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error deactivating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user"
        )


@router.post("/users/{user_id}/activate", status_code=status.HTTP_200_OK,
            dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def activate_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Activate a previously deactivated user account.
    
    Requires admin permissions.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User '{user.username}' is already active"
        )
    
    try:
        # Activate the user
        user.is_active = True
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="user_activate",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"target_user": user.username}
        )
        db.commit()
        
        logger.info(f"User '{user.username}' (ID: {user_id}) activated by admin {current_user.id}")
        
        return {
            "message": f"User '{user.username}' activated successfully",
            "user_id": user_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error activating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user"
        )


@router.delete("/users/{user_id}", status_code=status.HTTP_200_OK,
              dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def delete_user_permanently(
    request: Request,
    user_id: int,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Permanently delete a user account.
    
    Requires admin permissions.
    WARNING: This is irreversible and will delete all user data.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    try:
        username = user.username
        
        # Delete user-role associations
        db.query(UserRole).filter(UserRole.user_id == user_id).delete()
        
        # Note: Other cascading deletes will be handled by database foreign key constraints
        # (UserToken, MFASecret, etc. should have cascade delete configured)
        
        # Delete the user
        db.delete(user)
        db.commit()
        
        # Log the action
        ip_address, user_agent = _get_client_info(request)
        AuditLog.log_event(
            db_session=db,
            user_id=current_user.id,
            action="user_delete",
            resource="user",
            resource_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"deleted_user": username}
        )
        db.commit()
        
        logger.warning(f"User '{username}' (ID: {user_id}) PERMANENTLY DELETED by admin {current_user.id}")
        
        return {
            "message": f"User '{username}' permanently deleted",
            "user_id": user_id
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )


# ==================== DASHBOARD ENDPOINTS ====================

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive dashboard statistics.
    
    Requires admin permissions.
    """
    from datetime import datetime, timezone, timedelta
    
    # Count users
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    inactive_users = total_users - active_users
    
    # Count roles and permissions
    total_roles = db.query(Role).count()
    total_permissions = db.query(Permission).count()
    
    # Count recent logins (last 7 days)
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_logins = db.query(AuditLog).filter(
        AuditLog.action == "login",
        AuditLog.success == True,
        AuditLog.created_at >= seven_days_ago
    ).count()
    
    # Count failed logins (last 24 hours)
    twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    failed_logins_24h = db.query(AuditLog).filter(
        AuditLog.action == "login",
        AuditLog.success == False,
        AuditLog.created_at >= twenty_four_hours_ago
    ).count()

    # Count recent registrations (last 7 days)
    recent_registrations = db.query(User).filter(
        User.created_at >= seven_days_ago
    ).count()

    return DashboardStatsResponse(
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        total_roles=total_roles,
        total_permissions=total_permissions,
        recent_logins=recent_logins,
        failed_logins_24h=failed_logins_24h,
        recent_registrations=recent_registrations
    )

