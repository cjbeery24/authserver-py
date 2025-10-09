# RBAC (Role-Based Access Control) Usage Guide

This guide explains how to use the RBAC system implemented in `app/core/rbac.py`.

## Overview

The RBAC system provides:

- **Role-based access control**: Users can have multiple roles
- **Permission-based access control**: Roles have permissions with resource:action granularity
- **Permission inheritance**: Users inherit all permissions from their assigned roles
- **FastAPI dependencies**: Easy integration with route protection

## Core Concepts

### Permissions

Permissions are defined with two components:

- **Resource**: The entity being accessed (e.g., "users", "roles", "posts")
- **Action**: The operation being performed (e.g., "create", "read", "update", "delete")

Permission format: `resource:action`

Examples:

- `users:create` - Permission to create users
- `roles:read` - Permission to view roles
- `posts:delete` - Permission to delete posts

### Roles

Roles are collections of permissions. Users are assigned roles, and they inherit all permissions from those roles.

Example roles:

- **admin**: Full access to all resources
- **moderator**: Can manage content but not users
- **user**: Basic access to own profile

## Using RBAC in Endpoints

### Method 1: Using FastAPI Dependencies (Recommended)

The easiest way to protect endpoints is using the built-in dependencies:

```python
from fastapi import APIRouter, Depends
from app.core.rbac import require_permission, require_role, require_any_role

router = APIRouter()

# Require specific permission
@router.post("/users", dependencies=[Depends(require_permission("users", "create"))])
async def create_user(...):
    # Only users with 'users:create' permission can access this
    pass

# Require specific role
@router.get("/admin", dependencies=[Depends(require_role("admin"))])
async def admin_dashboard(...):
    # Only users with 'admin' role can access this
    pass

# Require any of multiple roles
@router.get("/moderate", dependencies=[Depends(require_any_role("admin", "moderator"))])
async def moderate_content(...):
    # Users with 'admin' OR 'moderator' role can access this
    pass

# Require multiple permissions (all required)
from app.core.rbac import require_all_permissions

@router.post("/special", dependencies=[
    Depends(require_all_permissions(("users", "create"), ("roles", "assign")))
])
async def special_action(...):
    # User must have BOTH permissions
    pass
```

### Method 2: Manual Permission Checking

For more complex logic, use the `PermissionChecker` class:

```python
from app.core.rbac import PermissionChecker
from app.middleware import get_current_user_or_401

@router.post("/conditional-action")
async def conditional_action(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    # Check if user has permission
    if PermissionChecker.has_permission(current_user.id, "posts", "delete", db):
        # User can delete posts
        pass

    # Check if user has a role
    if PermissionChecker.has_role(current_user.id, "admin", db):
        # User is admin
        pass

    # Check if user has any of multiple permissions
    if PermissionChecker.has_any_permission(
        current_user.id,
        [("posts", "delete"), ("posts", "moderate")],
        db
    ):
        # User can delete OR moderate posts
        pass
```

### Method 3: Enforcement (Raises Exception)

For inline permission enforcement:

```python
from app.core.rbac import enforce_permission

@router.post("/action")
async def some_action(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    # This will raise HTTPException 403 if user lacks permission
    enforce_permission(current_user, "posts", "delete", db)

    # Continue with action...
```

## PermissionChecker Methods

### Check Permissions

- `has_permission(user_id, resource, action, db)` - Check single permission
- `has_any_permission(user_id, permissions, db)` - Check if user has ANY of the permissions
- `has_all_permissions(user_id, permissions, db)` - Check if user has ALL permissions

### Check Roles

- `has_role(user_id, role_name, db)` - Check if user has specific role
- `has_any_role(user_id, role_names, db)` - Check if user has ANY of the roles

### Get User Information

- `get_user_roles(user_id, db)` - Get all user's roles
- `get_user_permissions(user_id, db)` - Get all user's permissions (from all roles)
- `get_user_permissions_by_resource(user_id, resource, db)` - Get actions user can perform on resource

### Get Role Information

- `get_role_permissions(role_id, db)` - Get all permissions for a role

## Admin Endpoints

The `/api/v1/admin` endpoints allow administrators to manage the RBAC system:

### Role Management

- `POST /api/v1/admin/roles` - Create role
- `GET /api/v1/admin/roles` - List roles
- `GET /api/v1/admin/roles/{role_id}` - Get role details
- `PUT /api/v1/admin/roles/{role_id}` - Update role
- `DELETE /api/v1/admin/roles/{role_id}` - Delete role

### Permission Management

- `POST /api/v1/admin/permissions` - Create permission
- `GET /api/v1/admin/permissions` - List permissions
- `DELETE /api/v1/admin/permissions/{permission_id}` - Delete permission

### User-Role Assignment

- `POST /api/v1/admin/user-roles` - Assign role to user
- `DELETE /api/v1/admin/user-roles` - Remove role from user
- `GET /api/v1/admin/users/{user_id}/roles` - Get user's roles

### Role-Permission Assignment

- `POST /api/v1/admin/role-permissions` - Assign permission to role
- `DELETE /api/v1/admin/role-permissions` - Remove permission from role
- `GET /api/v1/admin/roles/{role_id}/permissions` - Get role's permissions

## Example: Setting Up RBAC

### 1. Create Roles

```bash
# Create admin role
POST /api/v1/admin/roles
{
  "name": "admin",
  "description": "Administrator with full access"
}

# Create moderator role
POST /api/v1/admin/roles
{
  "name": "moderator",
  "description": "Content moderator"
}
```

### 2. Create Permissions

```bash
# Create user management permissions
POST /api/v1/admin/permissions
{"resource": "users", "action": "create"}

POST /api/v1/admin/permissions
{"resource": "users", "action": "read"}

POST /api/v1/admin/permissions
{"resource": "users", "action": "update"}

POST /api/v1/admin/permissions
{"resource": "users", "action": "delete"}

# Create post management permissions
POST /api/v1/admin/permissions
{"resource": "posts", "action": "create"}

POST /api/v1/admin/permissions
{"resource": "posts", "action": "moderate"}
```

### 3. Assign Permissions to Roles

```bash
# Give admin all user permissions
POST /api/v1/admin/role-permissions
{
  "role_id": 1,
  "permission_id": 1  # users:create
}
# ... repeat for other permissions

# Give moderator post moderation permission
POST /api/v1/admin/role-permissions
{
  "role_id": 2,
  "permission_id": 6  # posts:moderate
}
```

### 4. Assign Roles to Users

```bash
# Make user #1 an admin
POST /api/v1/admin/user-roles
{
  "user_id": 1,
  "role_id": 1  # admin role
}
```

## Common Patterns

### Admin-Only Endpoint

```python
from app.core.rbac import require_role

@router.get("/admin/dashboard", dependencies=[Depends(require_role("admin"))])
async def admin_dashboard(...):
    pass
```

### Resource Owner or Admin

```python
@router.put("/posts/{post_id}")
async def update_post(
    post_id: int,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == post_id).first()

    # Allow if user owns the post OR has admin role
    is_owner = post.user_id == current_user.id
    is_admin = PermissionChecker.has_role(current_user.id, "admin", db)

    if not (is_owner or is_admin):
        raise HTTPException(status_code=403, detail="Access denied")

    # Update post...
```

### Conditional Features

```python
@router.get("/dashboard")
async def dashboard(
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    # Get what actions user can perform on posts
    post_actions = PermissionChecker.get_user_permissions_by_resource(
        current_user.id, "posts", db
    )

    return {
        "can_create": "create" in post_actions,
        "can_moderate": "moderate" in post_actions,
        "can_delete": "delete" in post_actions
    }
```

## Security Best Practices

1. **Principle of Least Privilege**: Grant only necessary permissions
2. **Use Dependencies**: Prefer FastAPI dependencies over manual checks for cleaner code
3. **Audit Logging**: All admin operations are automatically logged
4. **Regular Review**: Periodically review role assignments and permissions
5. **Granular Permissions**: Use specific resource:action combinations rather than broad permissions

## Troubleshooting

### Permission Denied Errors

If you get 403 errors:

1. Check if user has required role: `GET /api/v1/admin/users/{user_id}/roles`
2. Check if role has required permission: `GET /api/v1/admin/roles/{role_id}/permissions`
3. Check logs for specific permission that was denied

### Missing Permissions

To see all available permissions:

```bash
GET /api/v1/admin/permissions
```

To see what a user can do:

```python
permissions = PermissionChecker.get_user_permissions(user_id, db)
print(permissions)  # Set of "resource:action" strings
```
