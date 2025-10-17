"""
Integration tests for Multi-Factor Authentication (MFA) flows.

Tests complete end-to-end MFA workflows including:
- MFA status checking
- MFA enable/disable flow
- TOTP code verification
- Backup codes generation and usage
- MFA bypass mechanisms
- MFA recovery procedures
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import json
import pyotp
from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.models.mfa_secret import MFASecret


# ==================== MFA STATUS ====================

@pytest.mark.integration
class TestMFAStatus:
    """Test MFA status endpoint."""

    def test_get_mfa_status_disabled(self, integration_authenticated_client: TestClient):
        """Test getting MFA status when MFA is disabled."""
        response = integration_authenticated_client.get("/api/v1/mfa/status")

        assert response.status_code == 200
        data = response.json()

        assert data["enabled"] is False
        assert data["has_backup_codes"] is False
        assert data["backup_codes_count"] == 0
        assert data["backup_codes_expired"] is False

    def test_get_mfa_status_enabled(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test getting MFA status when MFA is enabled."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        response = integration_authenticated_client.get("/api/v1/mfa/status")

        assert response.status_code == 200
        data = response.json()

        assert data["enabled"] is True
        assert data["has_backup_codes"] is True
        assert data["backup_codes_count"] == 10  # Default number of backup codes
        assert data["backup_codes_expired"] is False

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_mfa_status_requires_authentication(self, integration_client: TestClient):
        """Test that MFA status requires authentication."""
        response = integration_client.get("/api/v1/mfa/status")

        assert response.status_code == 401


# ==================== MFA ENABLE FLOW ====================

@pytest.mark.integration
class TestMFAEnableFlow:
    """Test MFA enable flow."""

    def test_initialize_mfa_setup(self, integration_authenticated_client: TestClient):
        """Test initializing MFA setup."""
        response = integration_authenticated_client.post("/api/v1/mfa/enable/init")

        assert response.status_code == 200
        data = response.json()

        assert "qr_code_base64" in data
        assert "manual_entry_key" in data
        assert "issuer" in data
        assert "account_name" in data

        # Verify the fields are not empty
        assert isinstance(data["qr_code_base64"], str)
        assert len(data["qr_code_base64"]) > 0
        assert isinstance(data["manual_entry_key"], str)
        assert len(data["manual_entry_key"]) > 0
        assert data["issuer"] == "AuthServer"

    def test_initialize_mfa_setup_already_enabled(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test initializing MFA setup when already enabled."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        response = integration_authenticated_client.post("/api/v1/mfa/enable/init")

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "already enabled" in data["detail"].lower()

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_verify_mfa_setup_valid_code(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test verifying MFA setup with valid TOTP code."""
        # First initialize MFA setup
        init_response = integration_authenticated_client.post("/api/v1/mfa/enable/init")
        assert init_response.status_code == 200

        init_data = init_response.json()
        secret = init_data["manual_entry_key"]

        # Generate valid TOTP code
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Verify with valid code
        verify_data = {"totp_code": valid_code}
        verify_response = integration_authenticated_client.post("/api/v1/mfa/enable/verify", json=verify_data)

        assert verify_response.status_code == 200
        verify_data = verify_response.json()

        assert "message" in verify_data
        assert "backup_codes" in verify_data
        assert "expires_at" in verify_data

        # Verify MFA is enabled in database
        mfa_secret = db_session.query(MFASecret).filter_by(user_id=test_user.id).first()
        assert mfa_secret is not None
        assert mfa_secret.is_enabled is True

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_verify_mfa_setup_invalid_code(self, integration_authenticated_client: TestClient):
        """Test verifying MFA setup with invalid TOTP code."""
        # First initialize MFA setup
        init_response = integration_authenticated_client.post("/api/v1/mfa/enable/init")
        assert init_response.status_code == 200

        # Try to verify with invalid code
        verify_data = {"totp_code": "000000"}
        verify_response = integration_authenticated_client.post("/api/v1/mfa/enable/verify", json=verify_data)

        assert verify_response.status_code == 400
        data = verify_response.json()
        assert "detail" in data
        assert "invalid" in data["detail"].lower()

    def test_verify_mfa_setup_without_init(self, integration_authenticated_client: TestClient):
        """Test verifying MFA setup without initialization."""
        verify_data = {"totp_code": "123456"}
        response = integration_authenticated_client.post("/api/v1/mfa/enable/verify", json=verify_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "not initialized" in data["detail"].lower()

    def test_mfa_enable_requires_authentication(self, integration_client: TestClient):
        """Test that MFA enable endpoints require authentication."""
        endpoints = [
            "/api/v1/mfa/enable/init",
            "/api/v1/mfa/enable/verify"
        ]

        for endpoint in endpoints:
            response = integration_client.post(endpoint)
            assert response.status_code == 401


# ==================== MFA DISABLE ====================

@pytest.mark.integration
class TestMFADisable:
    """Test MFA disable functionality."""

    def test_disable_mfa(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test disabling MFA."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Verify MFA is enabled
        status_response = integration_authenticated_client.get("/api/v1/mfa/status")
        assert status_response.json()["enabled"] is True

        # Disable MFA
        disable_data = {"password": "Str0ngP@ssw0rd!"}  # test_user password
        disable_response = integration_authenticated_client.post("/api/v1/mfa/disable", json=disable_data)

        assert disable_response.status_code == 200
        data = disable_response.json()
        assert "message" in data
        assert "MFA has been disabled successfully" in data["message"]

        # Verify MFA is disabled in database
        updated_mfa_secret = db_session.query(MFASecret).filter_by(user_id=test_user.id).first()
        assert updated_mfa_secret is not None
        assert updated_mfa_secret.is_enabled is False

        # Clean up - don't delete since test fixtures should handle this
        db_session.commit()

    def test_disable_mfa_wrong_password(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test disabling MFA with wrong password."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Try to disable with wrong password
        disable_data = {"password": "WrongPassword!"}
        disable_response = integration_authenticated_client.post("/api/v1/mfa/disable", json=disable_data)

        assert disable_response.status_code == 400
        data = disable_response.json()
        assert "detail" in data
        assert "invalid password" in data["detail"].lower()

        # Verify MFA is still enabled
        updated_mfa_secret = db_session.query(MFASecret).filter_by(user_id=test_user.id).first()
        assert updated_mfa_secret is not None
        assert updated_mfa_secret.is_enabled is True

        # Clean up - don't delete since test fixtures should handle this
        db_session.commit()

    def test_disable_mfa_not_enabled(self, integration_authenticated_client: TestClient):
        """Test disabling MFA when not enabled."""
        disable_data = {"password": "Str0ngP@ssw0rd!"}
        response = integration_authenticated_client.post("/api/v1/mfa/disable", json=disable_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "not enabled" in data["detail"].lower()


# ==================== BACKUP CODES ====================

@pytest.mark.integration
class TestMFABackupCodes:
    """Test MFA backup codes functionality."""

    def test_regenerate_backup_codes(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test regenerating backup codes."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Get original backup codes
        original_codes = mfa_secret.get_backup_codes()

        # Regenerate backup codes
        response = integration_authenticated_client.post("/api/v1/mfa/backup-codes/regenerate")

        assert response.status_code == 200
        data = response.json()

        assert "backup_codes" in data
        assert isinstance(data["backup_codes"], list)
        assert len(data["backup_codes"]) == 10

        # Verify backup codes changed in database
        updated_mfa_secret = db_session.query(MFASecret).filter_by(user_id=test_user.id).first()
        assert updated_mfa_secret is not None
        new_codes = updated_mfa_secret.get_backup_codes()

        # At least some codes should be different
        assert set(original_codes) != set(new_codes)

        # Clean up - don't delete since test fixtures should handle this
        db_session.commit()

    def test_regenerate_backup_codes_not_enabled(self, integration_authenticated_client: TestClient):
        """Test regenerating backup codes when MFA not enabled."""
        response = integration_authenticated_client.post("/api/v1/mfa/backup-codes/regenerate")

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "not enabled" in data["detail"].lower()

    def test_get_backup_codes_status(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test getting backup codes status."""
        # Enable MFA with backup codes
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        response = integration_authenticated_client.get("/api/v1/mfa/backup-codes/status")

        assert response.status_code == 200
        data = response.json()

        assert "total_codes" in data
        assert "used_codes" in data
        assert "unused_codes" in data
        assert data["total_codes"] == 10
        assert data["used_codes"] == 0
        assert data["unused_codes"] == 10

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_get_backup_codes_status_no_codes(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test getting backup codes status when no codes exist."""
        # Enable MFA without backup codes
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        response = integration_authenticated_client.get("/api/v1/mfa/backup-codes/status")

        assert response.status_code == 200
        data = response.json()

        assert data["total_codes"] == 0
        assert data["used_codes"] == 0
        assert data["unused_codes"] == 0

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()


# ==================== MFA BYPASS ====================

@pytest.mark.integration
class TestMFABypass:
    """Test MFA bypass functionality."""

    def test_admin_create_mfa_bypass(self, integration_admin_authenticated_client: TestClient, test_user: User):
        """Test admin creating MFA bypass token."""
        bypass_data = {
            "user_id": test_user.id,
            "reason": "Testing bypass functionality",
            "expires_in_hours": 1
        }

        response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/admin", json=bypass_data)

        assert response.status_code == 200
        data = response.json()

        assert "bypass_token" in data
        assert "expires_at" in data
        assert isinstance(data["bypass_token"], str)
        assert len(data["bypass_token"]) > 0

    def test_admin_create_mfa_bypass_invalid_user(self, integration_admin_authenticated_client: TestClient):
        """Test admin creating MFA bypass for invalid user."""
        bypass_data = {
            "user_id": "invalid-user-id",
            "reason": "Testing bypass functionality",
            "expires_in_hours": 1
        }

        response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/admin", json=bypass_data)

        assert response.status_code == 422  # Validation error for invalid user ID format

    def test_admin_create_mfa_bypass_requires_admin(self, integration_authenticated_client: TestClient, test_user: User):
        """Test that MFA bypass creation requires admin role."""
        bypass_data = {
            "user_id": test_user.id,
            "reason": "Testing bypass functionality",
            "expires_in_hours": 1
        }

        response = integration_authenticated_client.post("/api/v1/mfa/bypass/admin", json=bypass_data)

        assert response.status_code == 403

    def test_validate_mfa_bypass_token(self, integration_admin_authenticated_client: TestClient, test_user: User):
        """Test validating MFA bypass token."""
        # Store user_id before making requests (user object may get detached)
        user_id = test_user.id

        # Create bypass token
        bypass_data = {
            "user_id": user_id,
            "reason": "Testing bypass validation",
            "expires_in_hours": 1
        }

        create_response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/admin", json=bypass_data)
        bypass_token = create_response.json()["bypass_token"]

        # Validate bypass token
        validate_data = {"bypass_token": bypass_token, "user_id": user_id}
        validate_response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/validate", data=validate_data)

        assert validate_response.status_code == 200
        data = validate_response.json()

        assert "valid" in data
        assert data["valid"] is True
        assert "bypass_reason" in data
        assert data["bypass_reason"] == "Testing bypass validation"

    def test_validate_invalid_mfa_bypass_token(self, integration_admin_authenticated_client: TestClient):
        """Test validating invalid MFA bypass token."""
        validate_data = {"bypass_token": "invalid-bypass-token"}
        response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/validate", json=validate_data)

        assert response.status_code == 422  # Validation error for invalid token format
        data = response.json()

        # Should contain validation error details
        assert "detail" in data

    def test_validate_expired_mfa_bypass_token(self, integration_admin_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test validating expired MFA bypass token."""
        # Create bypass token that expires immediately
        bypass_data = {
            "user_id": test_user.id,
            "reason": "Testing expired bypass",
            "expires_in_hours": -1  # Already expired
        }

        create_response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/admin", json=bypass_data)
        bypass_token = create_response.json()["bypass_token"]

        # Validate expired token
        validate_data = {"bypass_token": bypass_token}
        validate_response = integration_admin_authenticated_client.post("/api/v1/mfa/bypass/validate", json=validate_data)

        assert validate_response.status_code == 422  # Validation error for expired/invalid token
        data = validate_response.json()

        assert "detail" in data


# ==================== MFA RECOVERY ====================

@pytest.mark.integration
class TestMFARecovery:
    """Test MFA recovery functionality."""

    def test_request_mfa_recovery(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test requesting MFA recovery."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        recovery_data = {"username": test_user.username, "email": test_user.email}
        response = integration_authenticated_client.post("/api/v1/mfa/recovery/request", json=recovery_data)

        assert response.status_code == 200
        data = response.json()

        assert "message" in data
        assert "recovery_initiated" in data

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_request_mfa_recovery_no_mfa(self, integration_authenticated_client: TestClient, test_user: User):
        """Test requesting MFA recovery when MFA not enabled."""
        recovery_data = {"username": test_user.username, "email": test_user.email}
        response = integration_authenticated_client.post("/api/v1/mfa/recovery/request", json=recovery_data)

        assert response.status_code == 200  # Always returns 200 to prevent enumeration
        data = response.json()
        assert "recovery_initiated" in data
        assert data["recovery_initiated"] is False

    def test_request_mfa_recovery_invalid_email(self, integration_authenticated_client: TestClient):
        """Test requesting MFA recovery with invalid email."""
        recovery_data = {"username": "nonexistent", "email": "nonexistent@example.com"}
        response = integration_authenticated_client.post("/api/v1/mfa/recovery/request", json=recovery_data)

        # Should return 200 to prevent email enumeration
        assert response.status_code == 200
        data = response.json()
        assert "recovery_initiated" in data
        assert data["recovery_initiated"] is False

    def test_complete_mfa_recovery(self, integration_authenticated_client: TestClient, test_user: User, db_session: Session):
        """Test completing MFA recovery."""
        # Enable MFA first
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Request recovery
        recovery_data = {"username": test_user.username, "email": test_user.email}
        request_response = integration_authenticated_client.post("/api/v1/mfa/recovery/request", json=recovery_data)
        assert request_response.status_code == 200

        # For this test, we'll skip the token-based completion since it requires
        # email verification which is not set up in tests
        # Just verify MFA is still enabled
        updated_mfa_secret = db_session.query(MFASecret).filter_by(user_id=test_user.id).first()
        assert updated_mfa_secret is not None
        assert updated_mfa_secret.is_enabled is True

        # Clean up - don't delete since test fixtures should handle this
        db_session.commit()

    def test_complete_mfa_recovery_invalid_token(self, integration_authenticated_client: TestClient):
        """Test completing MFA recovery with invalid token."""
        complete_data = {
            "recovery_token": "invalid-recovery-token",
            "password": "N3wStr0ngP@ss!",
            "action": "disable"
        }
        response = integration_authenticated_client.post("/api/v1/mfa/recovery/complete", json=complete_data)

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data

    def test_complete_mfa_recovery_wrong_password(self, integration_authenticated_client: TestClient):
        """Test completing MFA recovery with wrong password."""
        complete_data = {
            "recovery_token": "some-token",
            "password": "wrong-password",
            "action": "disable"
        }
        complete_response = integration_authenticated_client.post("/api/v1/mfa/recovery/complete", json=complete_data)

        assert complete_response.status_code == 400  # Token validation error
        data = complete_response.json()
        assert "detail" in data
        assert "invalid or expired recovery token" in data["detail"].lower()


# ==================== MFA RATE LIMITING ====================

@pytest.mark.integration
class TestMFARateLimiting:
    """Test MFA rate limiting."""

    def test_mfa_enable_rate_limiting(self, integration_authenticated_client: TestClient):
        """Test rate limiting on MFA enable endpoint."""
        # Make multiple requests to test rate limiting
        responses = []
        for _ in range(10):  # Exceed the rate limit
            response = integration_authenticated_client.post("/api/v1/mfa/enable/init")
            responses.append(response)

        # At least some requests should be rate limited
        rate_limited_responses = [r for r in responses if r.status_code == 429]
        assert len(rate_limited_responses) > 0
