"""
Integration tests for user management flows.

Tests complete end-to-end user management workflows including:
- User profile management
- Password changes
- Security settings
- Account deletion
- Token validation
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.models.audit_log import AuditLog


# ==================== USER PROFILE MANAGEMENT ====================

@pytest.mark.integration
class TestUserProfileManagement:
    """Test user profile management endpoints."""

    def test_get_user_profile(self, integration_authenticated_client: TestClient, test_user: User):
        """Test getting user profile."""
        response = integration_authenticated_client.get("/api/v1/users/me")

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == test_user.id
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email
        assert data["is_active"] == test_user.is_active
        assert "created_at" in data
        assert "updated_at" in data

    def test_update_user_profile_email(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test updating user profile email."""
        update_data = {
            "email": "newemail@example.com",
            "current_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        assert response.status_code == 200
        data = response.json()

        assert "changes" in data
        assert "email" in data["changes"]
        assert "Profile updated successfully" in data["message"]

        # Verify in database
        updated_user = db_session.query(User).filter_by(id=test_user.id).first()
        assert updated_user is not None
        assert updated_user.email == "newemail@example.com"

        # Reset email for other tests
        test_user.email = "test@example.com"
        db_session.commit()

    def test_update_user_profile_invalid_password(self, integration_authenticated_client: TestClient):
        """Test updating user profile with invalid password."""
        update_data = {
            "email": "newemail@example.com",
            "current_password": "WrongPassword!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "Invalid current password" in data["detail"]

    def test_update_user_profile_duplicate_email(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test updating user profile with duplicate email."""
        from datetime import datetime, timezone

        # Create another user with UTC timestamps (database schema uses timezone-aware datetimes)
        other_user = User(
            username="otheruser",
            email="other@example.com",
            password_hash="dummy_hash",
            is_active=True
        )

        db_session.add(other_user)
        db_session.commit()

        # Try to update to the other user's email
        update_data = {
            "email": "other@example.com",
            "current_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "Email address already in use" in data["detail"]

        # Clean up
        db_session.delete(other_user)
        db_session.commit()

    def test_update_user_profile_validation_error(self, integration_authenticated_client: TestClient):
        """Test updating user profile with validation error."""
        update_data = {
            "email": "invalid-email",
            "current_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        assert response.status_code == 422  # Validation error

    def test_user_profile_requires_authentication(self, integration_client: TestClient):
        """Test that user profile endpoints require authentication."""
        endpoints = [
            ("GET", "/api/v1/users/me"),
            ("PUT", "/api/v1/users/me")
        ]

        for method, endpoint in endpoints:
            if method == "GET":
                response = integration_client.get(endpoint)
            elif method == "PUT":
                response = integration_client.put(endpoint, json={})
            assert response.status_code == 401


# ==================== PASSWORD MANAGEMENT ====================

@pytest.mark.integration
class TestPasswordManagement:
    """Test password change functionality."""

    def test_change_password_success(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test successful password change."""
        change_data = {
            "current_password": "Str0ngP@ssw0rd!",
            "new_password": "N3wStr0ngP@ss!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me/password", json=change_data)

        assert response.status_code == 200
        data = response.json()
        assert "password updated" in data["message"].lower()

        # Verify can login with new password
        login_data = {
            "username": test_user.username,
            "password": "N3wStr0ngP@ss!"
        }
        login_response = integration_authenticated_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        # Reset password back for other tests
        from app.core.crypto import PasswordHasher
        test_user.password_hash = PasswordHasher.hash_password("Str0ngP@ssw0rd!", test_user.username)
        db_session.commit()

    def test_change_password_wrong_current_password(self, integration_authenticated_client: TestClient):
        """Test password change with wrong current password."""
        change_data = {
            "current_password": "WrongPassword!",
            "new_password": "N3wStr0ngP@ss!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me/password", json=change_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "Invalid current password" in data["detail"]

    def test_change_password_weak_new_password(self, integration_authenticated_client: TestClient):
        """Test password change with weak new password."""
        change_data = {
            "current_password": "Str0ngP@ssw0rd!",
            "new_password": "weak"
        }

        response = integration_authenticated_client.put("/api/v1/users/me/password", json=change_data)

        assert response.status_code == 422  # Validation error

    def test_change_password_same_as_current(self, integration_authenticated_client: TestClient):
        """Test password change with same password."""
        change_data = {
            "current_password": "Str0ngP@ssw0rd!",
            "new_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me/password", json=change_data)

        # Should either reject or allow (depending on implementation)
        assert response.status_code in [200, 400]

    def test_change_password_requires_authentication(self, integration_client: TestClient):
        """Test that password change requires authentication."""
        response = integration_client.put("/api/v1/users/me/password", json={})

        assert response.status_code == 401


# ==================== USER SECURITY SETTINGS ====================

@pytest.mark.integration
class TestUserSecuritySettings:
    """Test user security settings endpoint."""

    def test_get_security_settings_no_mfa(self, integration_authenticated_client: TestClient):
        """Test getting security settings when MFA is not enabled."""
        response = integration_authenticated_client.get("/api/v1/users/me/security")

        assert response.status_code == 200
        data = response.json()

        assert "mfa_enabled" in data
        assert "mfa_configured" in data
        assert "backup_codes_count" in data
        assert "backup_codes_expired" in data
        assert "password_last_changed" in data
        assert "active_sessions" in data

        assert data["mfa_enabled"] is False
        assert data["mfa_configured"] is False

    def test_get_security_settings_with_mfa(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test getting security settings when MFA is enabled."""
        # Enable MFA
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        response = integration_authenticated_client.get("/api/v1/users/me/security")

        assert response.status_code == 200
        data = response.json()

        assert data["mfa_enabled"] is True
        assert "mfa_configured" in data
        assert data["mfa_configured"] is True
        assert data["backup_codes_count"] == 10  # All codes are unused

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_security_settings_requires_authentication(self, integration_client: TestClient):
        """Test that security settings require authentication."""
        response = integration_client.get("/api/v1/users/me/security")

        assert response.status_code == 401


# ==================== ACCOUNT DELETION ====================

@pytest.mark.integration
class TestAccountDeletion:
    """Test account deletion functionality."""

    def test_delete_user_account(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test deleting user account."""
        delete_data = {
            "password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.request("DELETE", "/api/v1/users/me", json=delete_data)

        assert response.status_code == 200
        data = response.json()
        assert "Account has been deactivated successfully" in data["message"]

        # Verify user is marked as inactive in database
        updated_user = db_session.query(User).filter_by(id=test_user.id).first()
        assert updated_user is not None
        assert updated_user.is_active is False

        # Reactivate for other tests
        test_user.is_active = True
        db_session.commit()

    def test_delete_user_account_wrong_password(self, integration_authenticated_client: TestClient):
        """Test deleting account with wrong password."""
        delete_data = {
            "password": "WrongPassword!"
        }

        response = integration_authenticated_client.request("DELETE", "/api/v1/users/me", json=delete_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "Invalid password" in data["detail"]


    def test_delete_account_requires_authentication(self, integration_client: TestClient):
        """Test that account deletion requires authentication."""
        response = integration_client.delete("/api/v1/users/me")

        assert response.status_code == 401

    def test_delete_account_audit_logging(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test that account deletion is logged in audit log."""
        delete_data = {
            "password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.request("DELETE", "/api/v1/users/me", json=delete_data)
        assert response.status_code == 200

        # Check audit log
        audit_log = db_session.query(AuditLog).filter_by(
            user_id=test_user.id,
            action="account_delete"
        ).first()

        assert audit_log is not None
        assert audit_log.resource == "user"
        assert "self_delete" in audit_log.details

        # Reactivate for other tests
        test_user.is_active = True
        db_session.commit()


# ==================== TOKEN TESTING ====================

@pytest.mark.integration
class TestTokenValidation:
    """Test token validation endpoint."""

    def test_validate_valid_token(self, integration_authenticated_client: TestClient, test_user: User):
        """Test validating a valid token."""
        # Extract the JWT token from the Authorization header
        auth_header = integration_authenticated_client.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            pytest.skip("No valid token found in client headers")

        token = auth_header[7:]  # Remove "Bearer " prefix

        test_data = {"token": token}
        response = integration_authenticated_client.post("/api/v1/users/test-token", json=test_data)

        assert response.status_code == 200
        data = response.json()

        assert "valid" in data
        assert data["valid"] is True
        assert "user_id" in data
        assert data["user_id"] == test_user.id
        assert "decoded_payload" in data
        assert data["decoded_payload"]["sub"] == str(test_user.id)

    def test_validate_invalid_token(self, integration_authenticated_client: TestClient):
        """Test validating with invalid token."""
        test_data = {"token": "invalid.jwt.token"}
        response = integration_authenticated_client.post("/api/v1/users/test-token", json=test_data)

        assert response.status_code == 200  # API returns 200 with valid=false
        data = response.json()
        assert data["valid"] is False
        assert "error" in data

    def test_validate_expired_token(self, integration_authenticated_client: TestClient, test_user: User):
        """Test validating with expired token."""
        from app.core.token import TokenManager
        from datetime import timedelta

        # Create an expired access token
        user_data = {
            "sub": str(test_user.id),
            "username": test_user.username,
            "email": test_user.email,
        }
        expired_token = TokenManager.create_access_token(user_data, expires_delta=timedelta(seconds=-1))

        test_data = {"token": expired_token}
        response = integration_authenticated_client.post("/api/v1/users/test-token", json=test_data)

        assert response.status_code == 200  # API returns 200 with valid=false
        data = response.json()
        assert data["valid"] is False
        assert "error" in data

    def test_validate_malformed_token(self, integration_authenticated_client: TestClient):
        """Test validating with malformed token."""
        test_data = {"token": "malformed.jwt.token"}
        response = integration_authenticated_client.post("/api/v1/users/test-token", json=test_data)

        assert response.status_code == 200  # API returns 200 with valid=false
        data = response.json()
        assert data["valid"] is False
        assert "error" in data


# ==================== USER MANAGEMENT EDGE CASES ====================

@pytest.mark.integration
class TestUserManagementEdgeCases:
    """Test edge cases in user management."""

    def test_concurrent_profile_updates(self, integration_authenticated_client: TestClient, test_user: User):
        """Test handling concurrent profile updates."""
        # This tests race condition handling
        import threading
        import time

        results = []
        errors = []

        def update_profile(email_suffix):
            try:
                update_data = {
                    "email": f"test{email_suffix}@example.com",
                    "current_password": "Str0ngP@ssw0rd!"
                }
                response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # Create multiple threads to update profile concurrently
        threads = []
        for i in range(5):
            thread = threading.Thread(target=update_profile, args=(str(i),))
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # At least one should succeed, others might fail due to constraints
        assert 200 in results

    def test_large_profile_data(self, integration_authenticated_client: TestClient):
        """Test handling large profile data."""
        # Create a large email (but still valid)
        large_email = "a" * 200 + "@example.com"

        update_data = {
            "email": large_email,
            "current_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        # Should handle large data appropriately
        assert response.status_code in [200, 422]  # Success or validation error for length

    def test_special_characters_in_profile(self, integration_authenticated_client: TestClient):
        """Test special characters in profile updates."""
        special_email = "test+tag@example.com"

        update_data = {
            "email": special_email,
            "current_password": "Str0ngP@ssw0rd!"
        }

        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)

        # Should handle special characters appropriately
        assert response.status_code in [200, 422]

    def test_profile_update_during_password_change(self, integration_authenticated_client: TestClient):
        """Test profile update during password change operation."""
        # Change password first
        change_data = {
            "current_password": "Str0ngP@ssw0rd!",
            "new_password": "TempP@ssw0rd!"
        }

        password_response = integration_authenticated_client.put("/api/v1/users/me/password", json=change_data)
        assert password_response.status_code == 200

        # Try to update profile (should fail with old password)
        update_data = {
            "email": "new@example.com",
            "current_password": "Str0ngP@ssw0rd!"  # Old password
        }

        profile_response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)
        assert profile_response.status_code == 400  # Should fail

        # Reset password for other tests
        reset_data = {
            "current_password": "TempP@ssw0rd!",
            "new_password": "Str0ngP@ssw0rd!"
        }

        reset_response = integration_authenticated_client.put("/api/v1/users/me/password", json=reset_data)
        assert reset_response.status_code == 200
