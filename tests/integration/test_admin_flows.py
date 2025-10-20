"""
Integration tests for admin endpoints.

Tests complete end-to-end admin workflows including:
- Role management (CRUD operations)
- Permission management (CRUD operations)
- User-role assignments
- Role-permission assignments
- User administration
- Dashboard statistics
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import Role
from app.models.permission import Permission
from app.models.user_role import UserRole
from app.models.role_permission import RolePermission


# ==================== ROLE MANAGEMENT ====================

@pytest.mark.integration
class TestRoleManagement:
    """Test role management endpoints."""

    def test_create_role(self, integration_admin_authenticated_client: TestClient):
        """Test creating a new role."""
        role_data = {
            "name": "test_role",
            "description": "Test role for integration testing"
        }

        response = integration_admin_authenticated_client.post("/api/v1/admin/roles", json=role_data)

        assert response.status_code == 201
        data = response.json()

        assert data["name"] == "test_role"
        assert data["description"] == "Test role for integration testing"
        assert "id" in data
        assert "created_at" in data

    def test_create_duplicate_role(self, integration_admin_authenticated_client: TestClient):
        """Test creating a duplicate role fails."""
        role_data = {
            "name": "duplicate_role",
            "description": "First instance"
        }

        # Create first role
        response1 = integration_admin_authenticated_client.post("/api/v1/admin/roles", json=role_data)
        assert response1.status_code == 201

        # Try to create duplicate
        response2 = integration_admin_authenticated_client.post("/api/v1/admin/roles", json=role_data)
        assert response2.status_code == 400

    def test_list_roles(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test listing all roles."""
        # Create a test role first
        test_role = Role(name="list_test_role", description="Role for listing test")
        db_session.add(test_role)
        db_session.commit()

        response = integration_admin_authenticated_client.get("/api/v1/admin/roles")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) >= 1

        # Check if our test role is in the list
        role_names = [role["name"] for role in data]
        assert "list_test_role" in role_names

        # Clean up
        db_session.delete(test_role)
        db_session.commit()

    def test_get_role_details(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test getting specific role details."""
        # Create a test role
        test_role = Role(name="detail_test_role", description="Role for detail test")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        response = integration_admin_authenticated_client.get(f"/api/v1/admin/roles/{test_role.id}")

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == test_role.id
        assert data["name"] == "detail_test_role"
        assert data["description"] == "Role for detail test"

        # Clean up
        db_session.delete(test_role)
        db_session.commit()

    def test_get_nonexistent_role(self, integration_admin_authenticated_client: TestClient):
        """Test getting nonexistent role."""
        response = integration_admin_authenticated_client.get("/api/v1/admin/roles/99999")

        assert response.status_code == 404

    def test_update_role(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test updating a role."""
        # Create a test role
        test_role = Role(name="update_test_role", description="Original description")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        update_data = {
            "name": "updated_test_role",
            "description": "Updated description"
        }

        response = integration_admin_authenticated_client.put(f"/api/v1/admin/roles/{test_role.id}", json=update_data)

        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "updated_test_role"
        assert data["description"] == "Updated description"

        # Verify in database
        updated_role = db_session.query(Role).filter(Role.id == test_role.id).first()
        assert updated_role.name == "updated_test_role"

        # Note: Database truncation in conftest.py handles cleanup

    def test_delete_role(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test deleting a role."""
        # Create a test role
        test_role = Role(name="delete_test_role", description="Role to be deleted")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        response = integration_admin_authenticated_client.delete(f"/api/v1/admin/roles/{test_role.id}")

        assert response.status_code == 200

        # Verify deleted from database
        role = db_session.query(Role).filter_by(id=test_role.id).first()
        assert role is None

    def test_role_management_requires_admin(self, integration_authenticated_client: TestClient):
        """Test that role management requires admin role."""
        role_data = {"name": "test_role", "description": "Test"}

        # Try to create role without admin
        response = integration_authenticated_client.post("/api/v1/admin/roles", json=role_data)
        assert response.status_code == 403

        # Try to list roles without admin
        response = integration_authenticated_client.get("/api/v1/admin/roles")
        assert response.status_code == 403


# ==================== PERMISSION MANAGEMENT ====================

@pytest.mark.integration
class TestPermissionManagement:
    """Test permission management endpoints."""

    def test_create_permission(self, integration_admin_authenticated_client: TestClient):
        """Test creating a new permission."""
        permission_data = {
            "resource": "test_resource",
            "action": "test_action"
        }

        response = integration_admin_authenticated_client.post("/api/v1/admin/permissions", json=permission_data)

        assert response.status_code == 201
        data = response.json()

        assert data["resource"] == "test_resource"
        assert data["action"] == "test_action"
        assert "id" in data
        assert "created_at" in data

    def test_create_duplicate_permission(self, integration_admin_authenticated_client: TestClient):
        """Test creating duplicate permission fails."""
        permission_data = {
            "resource": "duplicate_resource",
            "action": "duplicate_action"
        }

        # Create first permission
        response1 = integration_admin_authenticated_client.post("/api/v1/admin/permissions", json=permission_data)
        assert response1.status_code == 201

        # Try to create duplicate
        response2 = integration_admin_authenticated_client.post("/api/v1/admin/permissions", json=permission_data)
        assert response2.status_code == 400

    def test_list_permissions(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test listing all permissions."""
        # Create a test permission
        test_permission = Permission(resource="list_test", action="list_action")
        db_session.add(test_permission)
        db_session.commit()

        response = integration_admin_authenticated_client.get("/api/v1/admin/permissions")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) >= 1

        # Check if our test permission is in the list
        permissions = [(p["resource"], p["action"]) for p in data]
        assert ("list_test", "list_action") in permissions

        # Clean up
        db_session.delete(test_permission)
        db_session.commit()

    def test_get_permission_details(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test getting specific permission details."""
        # Create a test permission
        test_permission = Permission(resource="detail_test", action="detail_action")
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_permission)

        response = integration_admin_authenticated_client.get(f"/api/v1/admin/permissions/{test_permission.id}")

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == test_permission.id
        assert data["resource"] == "detail_test"
        assert data["action"] == "detail_action"

        # Clean up
        db_session.delete(test_permission)
        db_session.commit()

    def test_delete_permission(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test deleting a permission."""
        # Create a test permission
        test_permission = Permission(resource="delete_test", action="delete_action")
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_permission)

        response = integration_admin_authenticated_client.delete(f"/api/v1/admin/permissions/{test_permission.id}")

        assert response.status_code == 200

        # Verify deleted from database
        permission = db_session.query(Permission).filter_by(id=test_permission.id).first()
        assert permission is None

    def test_permission_management_requires_admin(self, integration_authenticated_client: TestClient):
        """Test that permission management requires admin role."""
        permission_data = {"resource": "test", "action": "test"}

        response = integration_authenticated_client.post("/api/v1/admin/permissions", json=permission_data)
        assert response.status_code == 403

        response = integration_authenticated_client.get("/api/v1/admin/permissions")
        assert response.status_code == 403


# ==================== USER-ROLE ASSIGNMENTS ====================

@pytest.mark.integration
class TestUserRoleAssignments:
    """Test user-role assignment functionality."""

    def test_assign_role_to_user(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test assigning a role to a user."""
        # Create a test role
        test_role = Role(name="assignment_test_role", description="Role for assignment test")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        assignment_data = {
            "user_id": test_user.id,
            "role_id": test_role.id
        }

        response = integration_admin_authenticated_client.post("/api/v1/admin/user-roles", json=assignment_data)

        assert response.status_code == 201

        # Verify assignment in database
        user_role = db_session.query(UserRole).filter_by(
            user_id=test_user.id,
            role_id=test_role.id
        ).first()
        assert user_role is not None

        # Note: Database truncation in conftest.py handles cleanup

    def test_assign_duplicate_role_to_user(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test assigning duplicate role to user fails."""
        # Create a test role
        test_role = Role(name="duplicate_assignment_role", description="Role for duplicate test")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        assignment_data = {
            "user_id": test_user.id,
            "role_id": test_role.id
        }

        # First assignment
        response1 = integration_admin_authenticated_client.post("/api/v1/admin/user-roles", json=assignment_data)
        assert response1.status_code == 201

        # Duplicate assignment
        response2 = integration_admin_authenticated_client.post("/api/v1/admin/user-roles", json=assignment_data)
        assert response2.status_code == 400

        # Note: Database truncation in conftest.py handles cleanup

    def test_remove_role_from_user(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test removing a role from a user."""
        # Create a test role and assign it
        test_role = Role(name="removal_test_role", description="Role for removal test")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        user_role = UserRole(user_id=test_user.id, role_id=test_role.id)
        db_session.add(user_role)
        db_session.commit()

        # Remove the role
        removal_data = {
            "user_id": test_user.id,
            "role_id": test_role.id
        }

        response = integration_admin_authenticated_client.request("DELETE", "/api/v1/admin/user-roles", json=removal_data)

        assert response.status_code == 200

        # Verify removal from database
        user_role_check = db_session.query(UserRole).filter_by(
            user_id=test_user.id,
            role_id=test_role.id
        ).first()
        assert user_role_check is None

        # Clean up
        db_session.delete(test_role)
        db_session.commit()

    def test_get_user_roles(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test getting roles for a specific user."""
        # Create a test role and assign it
        test_role = Role(name="get_user_roles_test", description="Role for getting user roles")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        user_role = UserRole(user_id=test_user.id, role_id=test_role.id)
        db_session.add(user_role)
        db_session.commit()

        response = integration_admin_authenticated_client.get(f"/api/v1/admin/users/{test_user.id}/roles")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) >= 1

        # Check if our test role is in the list
        role_names = [role["name"] for role in data]
        assert "get_user_roles_test" in role_names

        # Note: Database truncation in conftest.py handles cleanup

    def test_user_role_operations_require_admin(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test that user-role operations require admin role."""
        # Create a test role
        test_role = Role(name="auth_test_role", description="Role for auth test")
        db_session.add(test_role)
        db_session.commit()
        db_session.refresh(test_role)

        assignment_data = {
            "user_id": test_user.id,
            "role_id": test_role.id
        }

        # Try operations without admin role
        response = integration_authenticated_client.post("/api/v1/admin/user-roles", json=assignment_data)
        assert response.status_code == 403

        response = integration_authenticated_client.get(f"/api/v1/admin/users/{test_user.id}/roles")
        assert response.status_code == 403

        # Clean up
        db_session.delete(test_role)
        db_session.commit()


# ==================== ROLE-PERMISSION ASSIGNMENTS ====================

@pytest.mark.integration
class TestRolePermissionAssignments:
    """Test role-permission assignment functionality."""

    def test_assign_permission_to_role(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test assigning a permission to a role."""
        # Create test role and permission
        test_role = Role(name="perm_assignment_role", description="Role for permission assignment")
        test_permission = Permission(resource="test_resource", action="test_action")

        db_session.add(test_role)
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_role)
        db_session.refresh(test_permission)

        assignment_data = {
            "role_id": test_role.id,
            "permission_id": test_permission.id
        }

        response = integration_admin_authenticated_client.post("/api/v1/admin/role-permissions", json=assignment_data)

        assert response.status_code == 201

        # Verify assignment in database
        role_permission = db_session.query(RolePermission).filter_by(
            role_id=test_role.id,
            permission_id=test_permission.id
        ).first()
        assert role_permission is not None

        # Note: Database truncation in conftest.py handles cleanup

    def test_remove_permission_from_role(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test removing a permission from a role."""
        # Create test role and permission, and assign
        test_role = Role(name="perm_removal_role", description="Role for permission removal")
        test_permission = Permission(resource="removal_resource", action="removal_action")

        db_session.add(test_role)
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_role)
        db_session.refresh(test_permission)

        role_permission = RolePermission(role_id=test_role.id, permission_id=test_permission.id)
        db_session.add(role_permission)
        db_session.commit()

        # Remove the permission
        removal_data = {
            "role_id": test_role.id,
            "permission_id": test_permission.id
        }

        response = integration_admin_authenticated_client.request("DELETE", "/api/v1/admin/role-permissions", json=removal_data)

        assert response.status_code == 200

        # Verify removal from database
        role_permission_check = db_session.query(RolePermission).filter_by(
            role_id=test_role.id,
            permission_id=test_permission.id
        ).first()
        assert role_permission_check is None

        # Clean up
        db_session.delete(test_role)
        db_session.delete(test_permission)
        db_session.commit()

    def test_get_role_permissions(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test getting permissions for a specific role."""
        # Create test role and permission, and assign
        test_role = Role(name="get_permissions_role", description="Role for getting permissions")
        test_permission = Permission(resource="get_perm_resource", action="get_perm_action")

        db_session.add(test_role)
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_role)
        db_session.refresh(test_permission)

        role_permission = RolePermission(role_id=test_role.id, permission_id=test_permission.id)
        db_session.add(role_permission)
        db_session.commit()

        response = integration_admin_authenticated_client.get(f"/api/v1/admin/roles/{test_role.id}/permissions")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) >= 1

        # Check if our test permission is in the list
        permissions = [(p["resource"], p["action"]) for p in data]
        assert ("get_perm_resource", "get_perm_action") in permissions

        # Note: Database truncation in conftest.py handles cleanup

    def test_role_permission_operations_require_admin(self, integration_authenticated_client: TestClient, db_session: Session):
        """Test that role-permission operations require admin role."""
        # Create test role and permission
        test_role = Role(name="auth_perm_role", description="Role for auth test")
        test_permission = Permission(resource="auth_perm_resource", action="auth_perm_action")

        db_session.add(test_role)
        db_session.add(test_permission)
        db_session.commit()
        db_session.refresh(test_role)
        db_session.refresh(test_permission)

        assignment_data = {
            "role_id": test_role.id,
            "permission_id": test_permission.id
        }

        # Try operations without admin role
        response = integration_authenticated_client.post("/api/v1/admin/role-permissions", json=assignment_data)
        assert response.status_code == 403

        response = integration_authenticated_client.get(f"/api/v1/admin/roles/{test_role.id}/permissions")
        assert response.status_code == 403

        # Clean up
        db_session.delete(test_role)
        db_session.delete(test_permission)
        db_session.commit()


# ==================== USER ADMINISTRATION ====================

@pytest.mark.integration
class TestUserAdministration:
    """Test user administration endpoints."""

    def test_list_users(self, integration_admin_authenticated_client: TestClient):
        """Test listing all users."""
        response = integration_admin_authenticated_client.get("/api/v1/admin/users")

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)
        assert len(data) >= 1  # At least admin user should exist

        # Check structure of user data
        if len(data) > 0:
            user = data[0]
            assert "id" in user
            assert "username" in user
            assert "email" in user
            assert "is_active" in user

    def test_get_user_details(self, integration_admin_authenticated_client: TestClient, test_user: User):
        """Test getting specific user details."""
        response = integration_admin_authenticated_client.get(f"/api/v1/admin/users/{test_user.id}")

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == test_user.id
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email
        assert data["is_active"] == test_user.is_active

    def test_deactivate_user(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test deactivating a user."""
        response = integration_admin_authenticated_client.post(f"/api/v1/admin/users/{test_user.id}/deactivate", json={})

        assert response.status_code == 200

        # Verify user is deactivated
        updated_user = db_session.query(User).filter(User.id == test_user.id).first()
        assert updated_user.is_active is False

        # Reactivate for other tests
        test_user.is_active = True
        db_session.commit()

    def test_activate_user(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test activating a user."""
        # First deactivate
        test_user.is_active = False
        db_session.commit()

        response = integration_admin_authenticated_client.post(f"/api/v1/admin/users/{test_user.id}/activate")

        assert response.status_code == 200

        # Verify user is activated
        updated_user = db_session.query(User).filter(User.id == test_user.id).first()
        assert updated_user.is_active is True

    def test_delete_user_admin(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test deleting a user as admin."""
        # Create a test user to delete
        from app.core.crypto import PasswordHasher
        from datetime import datetime, timezone
        delete_user = User(
            username="delete_me",
            email="delete@example.com",
            password_hash=PasswordHasher.hash_password("Str0ngP@ssw0rd!", "delete_me"),
            is_active=True
        )

        db_session.add(delete_user)
        db_session.commit()
        db_session.refresh(delete_user)

        response = integration_admin_authenticated_client.delete(f"/api/v1/admin/users/{delete_user.id}")

        assert response.status_code == 200

        # Verify user is deleted
        user = db_session.query(User).filter_by(id=delete_user.id).first()
        assert user is None

    def test_user_admin_operations_require_admin(self, integration_authenticated_client: TestClient, test_user: User):
        """Test that user admin operations require admin role."""
        response = integration_authenticated_client.get("/api/v1/admin/users")
        assert response.status_code == 403

        response = integration_authenticated_client.get(f"/api/v1/admin/users/{test_user.id}")
        assert response.status_code == 403

        response = integration_authenticated_client.post(f"/api/v1/admin/users/{test_user.id}/deactivate")
        assert response.status_code == 403

        response = integration_authenticated_client.post(f"/api/v1/admin/users/{test_user.id}/activate")
        assert response.status_code == 403

        response = integration_authenticated_client.delete(f"/api/v1/admin/users/{test_user.id}")
        assert response.status_code == 403


# ==================== DASHBOARD STATISTICS ====================

@pytest.mark.integration
class TestDashboardStatistics:
    """Test dashboard statistics endpoint."""

    def test_get_dashboard_stats(self, integration_admin_authenticated_client: TestClient):
        """Test getting dashboard statistics."""
        response = integration_admin_authenticated_client.get("/api/v1/admin/dashboard/stats")

        assert response.status_code == 200
        data = response.json()

        # Check that required statistics are present
        required_stats = [
            "total_users", "active_users", "total_roles", "total_permissions",
            "recent_registrations", "recent_logins"
        ]

        for stat in required_stats:
            assert stat in data, f"Missing statistic: {stat}"

        # Check data types
        assert isinstance(data["total_users"], int)
        assert isinstance(data["active_users"], int)
        assert isinstance(data["total_roles"], int)
        assert isinstance(data["total_permissions"], int)
        assert isinstance(data["recent_registrations"], int)
        assert isinstance(data["recent_logins"], int)

        # Logical checks
        assert data["total_users"] >= data["active_users"]
        assert data["total_users"] >= 0
        assert data["active_users"] >= 0

    def test_dashboard_stats_require_admin(self, integration_authenticated_client: TestClient):
        """Test that dashboard stats require admin role."""
        response = integration_authenticated_client.get("/api/v1/admin/dashboard/stats")

        assert response.status_code == 403


# ==================== ADMIN INTEGRATION SCENARIOS ====================

@pytest.mark.integration
class TestAdminIntegrationScenarios:
    """Test complete admin integration scenarios."""

    def test_complete_rbac_setup_workflow(self, integration_admin_authenticated_client: TestClient, db_session: Session):
        """Test complete RBAC setup workflow."""
        # Step 1: Create a permission
        permission_data = {
            "resource": "test_workflow",
            "action": "manage"
        }
        perm_response = integration_admin_authenticated_client.post("/api/v1/admin/permissions", json=permission_data)
        assert perm_response.status_code == 201
        permission = perm_response.json()

        # Step 2: Create a role
        role_data = {
            "name": "workflow_role",
            "description": "Role created in workflow test"
        }
        role_response = integration_admin_authenticated_client.post("/api/v1/admin/roles", json=role_data)
        assert role_response.status_code == 201
        role = role_response.json()

        # Step 3: Assign permission to role
        role_perm_data = {
            "role_id": role["id"],
            "permission_id": permission["id"]
        }
        rp_response = integration_admin_authenticated_client.post("/api/v1/admin/role-permissions", json=role_perm_data)
        assert rp_response.status_code == 201

        # Step 4: Create a test user
        from app.core.crypto import PasswordHasher
        workflow_user = User(
            username="workflow_user",
            email="workflow@example.com",
            password_hash=PasswordHasher.hash_password("Str0ngP@ssw0rd!", "workflow_user"),
            is_active=True
        )
        db_session.add(workflow_user)
        db_session.commit()
        db_session.refresh(workflow_user)

        # Step 5: Assign role to user
        user_role_data = {
            "user_id": workflow_user.id,
            "role_id": role["id"]
        }
        ur_response = integration_admin_authenticated_client.post("/api/v1/admin/user-roles", json=user_role_data)
        assert ur_response.status_code == 201

        # Step 6: Verify user has the role
        roles_response = integration_admin_authenticated_client.get(f"/api/v1/admin/users/{workflow_user.id}/roles")
        assert roles_response.status_code == 200
        user_roles = roles_response.json()
        role_names = [r["name"] for r in user_roles]
        assert "workflow_role" in role_names

        # Step 7: Verify role has the permission
        perms_response = integration_admin_authenticated_client.get(f"/api/v1/admin/roles/{role['id']}/permissions")
        assert perms_response.status_code == 200
        role_perms = perms_response.json()
        perm_resources = [(p["resource"], p["action"]) for p in role_perms]
        assert ("test_workflow", "manage") in perm_resources

        # Clean up
        # Remove user-role assignment
        ur_delete = integration_admin_authenticated_client.request("DELETE", "/api/v1/admin/user-roles", json=user_role_data)
        assert ur_delete.status_code == 200

        # Remove role-permission assignment
        rp_delete = integration_admin_authenticated_client.request("DELETE", "/api/v1/admin/role-permissions", json=role_perm_data)
        assert rp_delete.status_code == 200

        # Delete role
        role_delete = integration_admin_authenticated_client.delete(f"/api/v1/admin/roles/{role['id']}")
        assert role_delete.status_code == 200

        # Delete permission
        perm_delete = integration_admin_authenticated_client.delete(f"/api/v1/admin/permissions/{permission['id']}")
        assert perm_delete.status_code == 200

        # Delete user
        user_delete = integration_admin_authenticated_client.delete(f"/api/v1/admin/users/{workflow_user.id}")
        assert user_delete.status_code == 200
