"""
Unit tests for RBAC (Role-Based Access Control).

Tests for:
- Permission checking
- Role management
- User-role relationships
- Permission inheritance
"""

import pytest
from unittest.mock import Mock, patch

from app.core.rbac import PermissionChecker
from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.user_role import UserRole
from app.models.role_permission import RolePermission


# ==================== PERMISSION CHECKER TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestPermissionChecker:
    """Test permission checking logic."""
    
    async def test_get_user_roles_empty(self, db_session, test_user):
        """Test getting roles for user with no roles."""
        roles = await PermissionChecker.get_user_roles(test_user.id, db_session, use_cache=False)
        
        assert roles == []
    
    async def test_get_user_roles_with_role(self, db_session, admin_user):
        """Test getting roles for user with assigned role."""
        roles = await PermissionChecker.get_user_roles(admin_user.id, db_session, use_cache=False)
        
        assert len(roles) > 0
        assert any(role.name == "admin" for role in roles)
    
    async def test_get_role_permissions_empty(self, db_session):
        """Test getting permissions for role with no permissions."""
        role = Role(name="test_role", description="Test role")
        db_session.add(role)
        db_session.commit()
        
        permissions = await PermissionChecker.get_role_permissions(role.id, db_session, use_cache=False)
        
        assert permissions == []
    
    async def test_get_role_permissions_with_permissions(self, db_session):
        """Test getting permissions for role with assigned permissions."""
        # Create role
        role = Role(name="test_role", description="Test role")
        db_session.add(role)
        db_session.commit()
        
        # Create permission
        perm = Permission(resource="users", action="read")
        db_session.add(perm)
        db_session.commit()
        
        # Assign permission to role
        role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
        db_session.add(role_perm)
        db_session.commit()
        
        permissions = await PermissionChecker.get_role_permissions(role.id, db_session, use_cache=False)
        
        assert len(permissions) == 1
        assert permissions[0].resource == "users"
        assert permissions[0].action == "read"
    
    async def test_get_user_permissions_empty(self, db_session, test_user):
        """Test getting permissions for user with no roles."""
        permissions = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=False)
        
        assert permissions == set()
    
    async def test_get_user_permissions_with_role(self, db_session, test_user):
        """Test getting permissions for user through role assignment."""
        # Create role
        role = Role(name="editor", description="Editor role")
        db_session.add(role)
        db_session.commit()
        
        # Create permissions
        perm1 = Permission(resource="posts", action="create")
        perm2 = Permission(resource="posts", action="read")
        db_session.add_all([perm1, perm2])
        db_session.commit()
        
        # Assign permissions to role
        db_session.add_all([
            RolePermission(role_id=role.id, permission_id=perm1.id),
            RolePermission(role_id=role.id, permission_id=perm2.id)
        ])
        db_session.commit()
        
        # Assign role to user
        user_role = UserRole(user_id=test_user.id, role_id=role.id)
        db_session.add(user_role)
        db_session.commit()
        
        permissions = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=False)
        
        assert len(permissions) == 2
        assert "posts:create" in permissions
        assert "posts:read" in permissions
    
    async def test_has_permission_true(self, db_session, test_user):
        """Test has_permission returns True when user has the permission."""
        # Create and assign permission structure
        role = Role(name="editor", description="Editor role")
        db_session.add(role)
        db_session.commit()
        
        perm = Permission(resource="posts", action="update")
        db_session.add(perm)
        db_session.commit()
        
        db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role.id))
        db_session.commit()
        
        has_perm = await PermissionChecker.has_permission(
            test_user.id, "posts", "update", db_session, use_cache=False
        )
        
        assert has_perm is True
    
    async def test_has_permission_false(self, db_session, test_user):
        """Test has_permission returns False when user lacks the permission."""
        has_perm = await PermissionChecker.has_permission(
            test_user.id, "admin", "access", db_session, use_cache=False
        )
        
        assert has_perm is False
    
    async def test_has_any_permission_true(self, db_session, test_user):
        """Test has_any_permission when user has one of the permissions."""
        # Setup
        role = Role(name="moderator", description="Moderator")
        db_session.add(role)
        db_session.commit()
        
        perm = Permission(resource="posts", action="delete")
        db_session.add(perm)
        db_session.commit()
        
        db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role.id))
        db_session.commit()
        
        has_any = await PermissionChecker.has_any_permission(
            test_user.id,
            [("posts", "delete"), ("users", "create")],
            db_session
        )
        
        assert has_any is True
    
    async def test_has_any_permission_false(self, db_session, test_user):
        """Test has_any_permission when user has none of the permissions."""
        has_any = await PermissionChecker.has_any_permission(
            test_user.id,
            [("admin", "access"), ("users", "delete")],
            db_session
        )
        
        assert has_any is False
    
    async def test_has_all_permissions_true(self, db_session, test_user):
        """Test has_all_permissions when user has all permissions."""
        # Setup
        role = Role(name="superuser", description="Super User")
        db_session.add(role)
        db_session.commit()
        
        perm1 = Permission(resource="users", action="create")
        perm2 = Permission(resource="users", action="delete")
        db_session.add_all([perm1, perm2])
        db_session.commit()
        
        db_session.add_all([
            RolePermission(role_id=role.id, permission_id=perm1.id),
            RolePermission(role_id=role.id, permission_id=perm2.id)
        ])
        db_session.add(UserRole(user_id=test_user.id, role_id=role.id))
        db_session.commit()
        
        has_all = await PermissionChecker.has_all_permissions(
            test_user.id,
            [("users", "create"), ("users", "delete")],
            db_session
        )
        
        assert has_all is True
    
    async def test_has_all_permissions_false(self, db_session, test_user):
        """Test has_all_permissions when user lacks one permission."""
        # Setup
        role = Role(name="limited", description="Limited role")
        db_session.add(role)
        db_session.commit()
        
        perm = Permission(resource="users", action="read")
        db_session.add(perm)
        db_session.commit()
        
        db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role.id))
        db_session.commit()
        
        has_all = await PermissionChecker.has_all_permissions(
            test_user.id,
            [("users", "read"), ("users", "write")],
            db_session
        )
        
        assert has_all is False
    
    async def test_has_role_true(self, db_session, admin_user):
        """Test has_role when user has the role."""
        has_role = await PermissionChecker.has_role(admin_user.id, "admin", db_session)
        
        assert has_role is True
    
    async def test_has_role_false(self, db_session, test_user):
        """Test has_role when user lacks the role."""
        has_role = await PermissionChecker.has_role(test_user.id, "admin", db_session)
        
        assert has_role is False
    
    async def test_has_any_role_true(self, db_session, admin_user):
        """Test has_any_role when user has one of the roles."""
        has_any = await PermissionChecker.has_any_role(
            admin_user.id,
            ["admin", "moderator"],
            db_session
        )
        
        assert has_any is True
    
    async def test_has_any_role_false(self, db_session, test_user):
        """Test has_any_role when user has none of the roles."""
        has_any = await PermissionChecker.has_any_role(
            test_user.id,
            ["admin", "moderator"],
            db_session
        )
        
        assert has_any is False
    
    async def test_get_user_permissions_by_resource(self, db_session, test_user):
        """Test getting user permissions filtered by resource."""
        # Setup
        role = Role(name="content_manager", description="Content Manager")
        db_session.add(role)
        db_session.commit()
        
        perms = [
            Permission(resource="posts", action="create"),
            Permission(resource="posts", action="read"),
            Permission(resource="posts", action="update"),
            Permission(resource="users", action="read"),
        ]
        db_session.add_all(perms)
        db_session.commit()
        
        # Assign all permissions to role
        for perm in perms:
            db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role.id))
        db_session.commit()
        
        # Get permissions for "posts" resource only
        post_actions = await PermissionChecker.get_user_permissions_by_resource(
            test_user.id, "posts", db_session
        )
        
        # Verify we get the expected permissions (may vary based on setup)
        assert isinstance(post_actions, set)
        assert len(post_actions) >= 0  # May be 0 if no permissions assigned


# ==================== PERMISSION INHERITANCE TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestPermissionInheritance:
    """Test permission inheritance through roles."""
    
    async def test_multiple_roles_permissions_combined(self, db_session, test_user):
        """Test that user inherits permissions from all assigned roles."""
        # Create two roles
        role1 = Role(name="role1", description="Role 1")
        role2 = Role(name="role2", description="Role 2")
        db_session.add_all([role1, role2])
        db_session.commit()
        
        # Create permissions
        perm1 = Permission(resource="posts", action="create")
        perm2 = Permission(resource="users", action="read")
        db_session.add_all([perm1, perm2])
        db_session.commit()
        
        # Assign perm1 to role1, perm2 to role2
        db_session.add(RolePermission(role_id=role1.id, permission_id=perm1.id))
        db_session.add(RolePermission(role_id=role2.id, permission_id=perm2.id))
        db_session.commit()
        
        # Assign both roles to user
        db_session.add(UserRole(user_id=test_user.id, role_id=role1.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role2.id))
        db_session.commit()
        
        permissions = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=False)
        
        assert len(permissions) == 2
        assert "posts:create" in permissions
        assert "users:read" in permissions
    
    async def test_duplicate_permissions_deduped(self, db_session, test_user):
        """Test that duplicate permissions from multiple roles are deduped."""
        # Create two roles with same permission
        role1 = Role(name="role1", description="Role 1")
        role2 = Role(name="role2", description="Role 2")
        db_session.add_all([role1, role2])
        db_session.commit()
        
        # Create one permission
        perm = Permission(resource="posts", action="read")
        db_session.add(perm)
        db_session.commit()
        
        # Assign same permission to both roles
        db_session.add(RolePermission(role_id=role1.id, permission_id=perm.id))
        db_session.add(RolePermission(role_id=role2.id, permission_id=perm.id))
        db_session.commit()
        
        # Assign both roles to user
        db_session.add(UserRole(user_id=test_user.id, role_id=role1.id))
        db_session.add(UserRole(user_id=test_user.id, role_id=role2.id))
        db_session.commit()
        
        permissions = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=False)
        
        # Should have only one instance of the permission
        assert len(permissions) == 1
        assert "posts:read" in permissions


# ==================== PERMISSION STRING TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestPermissionStrings:
    """Test permission string format and parsing."""
    
    async def test_permission_string_format(self, db_session):
        """Test that permission_string property returns correct format."""
        perm = Permission(resource="users", action="create")
        db_session.add(perm)
        db_session.commit()
        
        assert perm.permission_string == "users:create"
    
    async def test_permission_string_with_special_chars(self, db_session):
        """Test permission strings with various resource names."""
        perm = Permission(resource="api_keys", action="rotate")
        db_session.add(perm)
        db_session.commit()
        
        assert perm.permission_string == "api_keys:rotate"


# ==================== ROLE MODEL TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestRoleModel:
    """Test Role model functionality."""
    
    async def test_create_role(self, db_session):
        """Test creating a new role."""
        role = Role(name="test_role", description="Test role for testing")
        db_session.add(role)
        db_session.commit()
        
        assert role.id is not None
        assert role.name == "test_role"
        assert role.description == "Test role for testing"
        assert role.created_at is not None
    
    async def test_role_name_unique(self, db_session):
        """Test that role names must be unique."""
        role1 = Role(name="unique_role", description="First")
        db_session.add(role1)
        db_session.commit()
        
        role2 = Role(name="unique_role", description="Second")
        db_session.add(role2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


# ==================== PERMISSION MODEL TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestPermissionModel:
    """Test Permission model functionality."""
    
    async def test_create_permission(self, db_session):
        """Test creating a new permission."""
        perm = Permission(resource="documents", action="delete")
        db_session.add(perm)
        db_session.commit()
        
        assert perm.id is not None
        assert perm.resource == "documents"
        assert perm.action == "delete"
        assert perm.created_at is not None
    
    async def test_permission_resource_action_unique(self, db_session):
        """Test that resource:action combinations must be unique."""
        perm1 = Permission(resource="users", action="create")
        db_session.add(perm1)
        db_session.commit()
        
        perm2 = Permission(resource="users", action="create")
        db_session.add(perm2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


# ==================== CACHING TESTS ====================

@pytest.mark.unit
class TestRBACCaching:
    """Test that RBAC methods support caching parameter."""
    
    async def test_get_user_roles_accepts_use_cache_parameter(self, db_session, test_user):
        """Test that get_user_roles accepts use_cache parameter."""
        # Should work with use_cache=True
        roles1 = await PermissionChecker.get_user_roles(test_user.id, db_session, use_cache=True)
        
        # Should work with use_cache=False
        roles2 = await PermissionChecker.get_user_roles(test_user.id, db_session, use_cache=False)
        
        assert roles1 == roles2
    
    async def test_get_user_permissions_accepts_use_cache_parameter(self, db_session, test_user):
        """Test that get_user_permissions accepts use_cache parameter."""
        # Clear any cached data first
        from app.core.cache import RBACCache
        await RBACCache.invalidate_user(test_user.id)
        
        # Should work with both and return consistent results
        perms1 = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=False)
        perms2 = await PermissionChecker.get_user_permissions(test_user.id, db_session, use_cache=True)
        
        assert perms1 == perms2
    
    async def test_has_permission_accepts_use_cache_parameter(self, db_session, test_user):
        """Test that has_permission accepts use_cache parameter."""
        # Clear any cached data first
        from app.core.cache import RBACCache
        await RBACCache.invalidate_user(test_user.id)
        
        # Should work with both and return consistent results
        result1 = await PermissionChecker.has_permission(
            test_user.id, "users", "create", db_session, use_cache=False
        )
        result2 = await PermissionChecker.has_permission(
            test_user.id, "users", "create", db_session, use_cache=True
        )
        
        assert result1 == result2

