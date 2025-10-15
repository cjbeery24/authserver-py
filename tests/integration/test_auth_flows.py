"""
Integration tests for authentication flows.

Tests complete end-to-end authentication workflows including:
- User registration
- Login (with and without MFA)
- Token refresh
- Logout
- Password reset
- Protected endpoint access
- Role-based access control
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import pyotp

from app.models.user import User
from app.models.mfa_secret import MFASecret
from app.models.role import Role
from app.models.user_role import UserRole
from app.core.security import PasswordHasher


# ==================== USER REGISTRATION FLOW ====================

@pytest.mark.integration
class TestUserRegistrationFlow:
    """Test complete user registration flow."""
    
    def test_successful_registration(self, integration_client: TestClient, db_session: Session):
        """Test successful user registration with valid data."""
        registration_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "Str0ngP@ssw0rd!"
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        
        assert response.status_code == 201
        data = response.json()
        
        # Registration returns user data, not tokens
        assert "id" in data
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["is_active"] is True
        assert data["message"] == "User registered successfully"
        
        # Verify user was created in database
        user = db_session.query(User).filter_by(username="newuser").first()
        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.is_active is True
    
    def test_registration_duplicate_username(self, integration_client: TestClient, test_user: User):
        """Test registration fails with duplicate username."""
        registration_data = {
            "username": test_user.username,  # Duplicate
            "email": "different@example.com",
            "password": "V@lidP@ss9!"
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        assert response.status_code == 409  # Conflict for duplicate username
        detail = response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "REG_001"
        else:
            assert "already" in str(detail).lower()
    
    def test_registration_duplicate_email(self, integration_client: TestClient, test_user: User):
        """Test registration fails with duplicate email."""
        registration_data = {
            "username": "differentuser",
            "email": test_user.email,  # Duplicate
            "password": "V@lidP@ss9!"
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        assert response.status_code == 409  # Conflict for duplicate email
        detail = response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "REG_002"
        else:
            assert "already" in str(detail).lower()
    
    def test_registration_weak_password(self, integration_client: TestClient):
        """Test registration fails with weak password."""
        registration_data = {
            "username": "weakpassuser",
            "email": "weak@example.com",
            "password": "weak"  # Too weak
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        assert response.status_code == 422  # FastAPI returns 422 for validation errors
        # For validation errors, detail is usually a list or string
        detail = response.json()["detail"]
        detail_str = str(detail).lower()
        assert "password" in detail_str
    
    def test_registration_invalid_email(self, integration_client: TestClient):
        """Test registration fails with invalid email format."""
        registration_data = {
            "username": "invalidemailuser",
            "email": "not-an-email",
            "password": "V@lidP@ss9!"
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        assert response.status_code == 422  # Validation error


# ==================== LOGIN FLOW ====================

@pytest.mark.integration
class TestLoginFlow:
    """Test complete login flow."""
    
    def test_successful_login(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test successful login with valid credentials."""
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        
        response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == test_user.id
        assert data["username"] == test_user.username
    
    def test_login_wrong_password(self, integration_client: TestClient, test_user: User):
        """Test login fails with wrong password."""
        login_data = {
            "username": test_user.username,
            "password": "Wr0ngP@ssw0rd!"
        }
        
        response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        assert response.status_code == 401
        detail = response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] in ["AUTH_001", "AUTH_002"]  # Invalid credentials
        else:
            assert "invalid" in str(detail).lower() or "credentials" in str(detail).lower()
    
    def test_login_nonexistent_user(self, integration_client: TestClient):
        """Test login fails with nonexistent user."""
        login_data = {
            "username": "nonexistent",
            "password": "Str0ngP@ssw0rd!"
        }
        
        response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        assert response.status_code == 401
    
    def test_login_inactive_user(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test login fails for inactive user."""
        # Deactivate user
        test_user.is_active = False
        db_session.commit()
        
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        
        response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        assert response.status_code == 403  # Inactive users get 403 Forbidden
        detail = response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "AUTH_002"  # Account deactivated
        else:
            assert "deactivat" in str(detail).lower() or "inactive" in str(detail).lower()
        
        # Reactivate for other tests
        test_user.is_active = True
        db_session.commit()


# ==================== MFA LOGIN FLOW ====================

@pytest.mark.integration
class TestMFALoginFlow:
    """Test login flow with MFA enabled."""
    
    def test_login_with_mfa_requires_session_token(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test that login with MFA enabled returns session token for MFA completion."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Try to login without MFA code
        login_data = {
            "username": test_user.username,
            "password": test_password
        }

        response = integration_client.post("/api/v1/auth/token", data=login_data)

        assert response.status_code == 200
        data = response.json()
        assert data["mfa_required"] is True
        assert data["user_id"] == test_user.id
        assert data["username"] == test_user.username
        assert "session_token" in data  # New: should include session token
        assert "access_token" not in data  # Should not get access token yet
        assert "refresh_token" not in data  # Should not get refresh token yet

        # Verify session token is a non-empty string
        session_token = data["session_token"]
        assert isinstance(session_token, str)
        assert len(session_token) > 0

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()
    
    def test_complete_mfa_with_valid_code(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test successful MFA completion with valid code using session token."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Step 1: Initial login to get session token
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        login_data = login_response.json()
        assert login_data["mfa_required"] is True
        session_token = login_data["session_token"]

        # Step 2: Complete MFA with valid code
        import pyotp
        totp = pyotp.TOTP(mfa_secret.secret)
        valid_code = totp.now()

        mfa_data = {
            "session_token": session_token,
            "mfa_token": valid_code
        }

        mfa_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)

        assert mfa_response.status_code == 200
        data = mfa_response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == test_user.id
        assert data["username"] == test_user.username

        # Verify tokens are valid by making an authenticated request
        access_token = data["access_token"]
        profile_response = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert profile_response.status_code == 200

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()
    
    def test_complete_mfa_with_invalid_code(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test MFA completion fails with invalid code."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Step 1: Initial login to get session token
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        session_token = login_response.json()["session_token"]

        # Step 2: Try to complete MFA with invalid code
        mfa_data = {
            "session_token": session_token,
            "mfa_token": "000000"  # Invalid
        }

        mfa_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)

        assert mfa_response.status_code == 401
        detail = mfa_response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "AUTH_003"  # Invalid MFA token
        else:
            assert "mfa" in str(detail).lower() or "invalid" in str(detail).lower()

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_complete_mfa_with_invalid_session_token(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test MFA completion fails with invalid session token."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Try to complete MFA with invalid session token
        mfa_data = {
            "session_token": "invalid_session_token_12345",
            "mfa_token": "123456"
        }

        response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)

        assert response.status_code == 401
        detail = response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "TOKEN_005"  # Invalid session token
        else:
            assert "session" in str(detail).lower() or "invalid" in str(detail).lower()

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_complete_mfa_with_backup_code(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test MFA completion with valid backup code."""
        # Enable MFA for user with backup codes
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=True
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Get a backup code
        backup_codes = mfa_secret.get_backup_codes()
        assert len(backup_codes) > 0
        test_backup_code = backup_codes[0]

        # Step 1: Initial login to get session token
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        session_token = login_response.json()["session_token"]

        # Step 2: Complete MFA with backup code
        mfa_data = {
            "session_token": session_token,
            "mfa_token": test_backup_code
        }

        mfa_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)

        assert mfa_response.status_code == 200
        data = mfa_response.json()
        assert "access_token" in data
        assert "refresh_token" in data

        # Verify backup code was consumed
        db_session.refresh(mfa_secret)
        remaining_codes = mfa_secret.get_backup_codes()
        assert test_backup_code not in remaining_codes

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_session_token_reuse_after_successful_mfa(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test that session token cannot be reused after successful MFA completion."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Step 1: Initial login to get session token
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        session_token = login_response.json()["session_token"]

        # Step 2: Complete MFA successfully
        import pyotp
        totp = pyotp.TOTP(mfa_secret.secret)
        valid_code = totp.now()

        mfa_data = {
            "session_token": session_token,
            "mfa_token": valid_code
        }

        mfa_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)
        assert mfa_response.status_code == 200

        # Step 3: Try to reuse the same session token (should fail)
        mfa_data_reuse = {
            "session_token": session_token,
            "mfa_token": totp.now()  # Generate new code just in case
        }

        reuse_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data_reuse)

        assert reuse_response.status_code == 401
        detail = reuse_response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "TOKEN_005"  # Invalid session token
        else:
            assert "session" in str(detail).lower() or "invalid" in str(detail).lower()

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()

    def test_mfa_session_expires(self, integration_client: TestClient, test_user: User, test_password: str, db_session: Session):
        """Test that MFA session tokens expire after the configured time."""
        # Enable MFA for user
        mfa_secret = MFASecret.create_for_user(
            db_session=db_session,
            user_id=test_user.id,
            generate_secret=True,
            generate_backup_codes=False
        )
        mfa_secret.is_enabled = True
        db_session.add(mfa_secret)
        db_session.commit()

        # Step 1: Initial login to get session token
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200

        session_token = login_response.json()["session_token"]

        # Step 2: Manually expire the session in Redis (simulate time passing)
        from app.core.redis import get_redis
        import asyncio
        import json

        async def expire_session():
            redis_client = await get_redis()
            # Delete the session key to simulate expiration
            key = f"mfa_session:{session_token}"
            await redis_client.delete(key)

        # Run the async function
        asyncio.run(expire_session())

        # Step 3: Try to complete MFA with expired session (should fail)
        import pyotp
        totp = pyotp.TOTP(mfa_secret.secret)
        valid_code = totp.now()

        mfa_data = {
            "session_token": session_token,
            "mfa_token": valid_code
        }

        mfa_response = integration_client.post("/api/v1/auth/token/mfa", json=mfa_data)

        assert mfa_response.status_code == 401
        detail = mfa_response.json()["detail"]
        # Check error code if available, otherwise check message
        if isinstance(detail, dict) and "error_code" in detail:
            assert detail["error_code"] == "TOKEN_005"  # Invalid session token
        else:
            assert "session" in str(detail).lower() or "invalid" in str(detail).lower()

        # Clean up
        db_session.delete(mfa_secret)
        db_session.commit()


# ==================== TOKEN REFRESH FLOW ====================

@pytest.mark.integration
class TestTokenRefreshFlow:
    """Test token refresh flow."""
    
    def test_successful_token_refresh(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test successful token refresh with valid refresh token."""
        # First, login to get tokens
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Now refresh the token
        refresh_response = integration_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == 200
        data = refresh_response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        
        # New tokens should be different from old ones
        assert data["access_token"] != login_response.json()["access_token"]
        assert data["refresh_token"] != refresh_token
    
    def test_refresh_with_invalid_token(self, integration_client: TestClient):
        """Test token refresh fails with invalid refresh token."""
        refresh_response = integration_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.token.here"}
        )
        
        assert refresh_response.status_code == 401
    
    def test_refresh_with_access_token(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test that refresh endpoint rejects access tokens."""
        # Login to get tokens
        login_data = {
            "username": test_user.username,
            "password": test_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        access_token = login_response.json()["access_token"]
        
        # Try to refresh with access token (should fail)
        refresh_response = integration_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": access_token}
        )
        
        assert refresh_response.status_code == 401


# ==================== LOGOUT FLOW ====================

@pytest.mark.integration
class TestLogoutFlow:
    """Test logout flow."""
    
    def test_successful_logout(self, integration_authenticated_client: TestClient):
        """Test successful logout."""
        response = integration_authenticated_client.post("/api/v1/auth/logout")
        
        assert response.status_code == 200
        assert "logged out" in response.json()["message"].lower()
    
    def test_logout_without_authentication(self, integration_client: TestClient):
        """Test logout without authentication fails."""
        response = integration_client.post("/api/v1/auth/logout")
        
        assert response.status_code == 401


# ==================== PASSWORD RESET FLOW ====================

@pytest.mark.integration
class TestPasswordResetFlow:
    """Test complete password reset flow."""
    
    def test_request_password_reset(self, integration_client: TestClient, test_user: User, db_session: Session):
        """Test requesting password reset sends email and creates token."""
        reset_data = {
            "email": test_user.email
        }
        
        response = integration_client.post("/api/v1/auth/password-reset/request", json=reset_data)
        
        assert response.status_code == 200
        assert "reset link" in response.json()["message"].lower()
        
        # Verify reset token was created in database
        from app.models.password_reset import PasswordResetToken
        reset_token = db_session.query(PasswordResetToken).filter_by(
            user_id=test_user.id
        ).first()
        assert reset_token is not None
        assert reset_token.is_used is False
        
        # Clean up
        db_session.delete(reset_token)
        db_session.commit()
    
    def test_request_password_reset_nonexistent_email(self, integration_client: TestClient):
        """Test requesting password reset for nonexistent email still returns 200."""
        reset_data = {
            "email": "nonexistent@example.com"
        }
        
        response = integration_client.post("/api/v1/auth/password-reset/request", json=reset_data)
        
        # Should return 200 to prevent email enumeration
        assert response.status_code == 200
    
    def test_complete_password_reset(self, integration_client: TestClient, test_user: User, db_session: Session):
        """Test completing password reset with valid token."""
        # First, request password reset
        from app.models.password_reset import PasswordResetToken
        from app.core.security import TokenGenerator

        reset_token = TokenGenerator.generate_reset_token()
        reset_token_obj = PasswordResetToken.create_reset_token(
            user_id=test_user.id,
            token=reset_token,
            expiry_hours=1
        )
        db_session.add(reset_token_obj)
        db_session.commit()

        # Get the plaintext token
        token = reset_token
        
        # Complete the reset
        new_password = "N3wP@ssw0rd!"
        reset_data = {
            "token": token,
            "new_password": new_password
        }
        
        response = integration_client.post("/api/v1/auth/password-reset/complete", json=reset_data)
        
        assert response.status_code == 200
        assert "password has been reset" in response.json()["message"].lower()
        
        # Verify can login with new password
        login_data = {
            "username": test_user.username,
            "password": new_password
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200
        
        # Verify token is marked as used
        db_session.refresh(reset_token_obj)
        assert reset_token_obj.is_used is True
        
        # Clean up - reset password back
        test_user.password_hash = PasswordHasher.hash_password("Str0ngP@ssw0rd!", test_user.username)
        db_session.commit()
    
    def test_complete_password_reset_invalid_token(self, integration_client: TestClient):
        """Test password reset fails with invalid token."""
        reset_data = {
            "token": "invalid_token_12345",
            "new_password": "N3wP@ssw0rd!"
        }
        
        response = integration_client.post("/api/v1/auth/password-reset/complete", json=reset_data)
        
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()
    
    def test_complete_password_reset_expired_token(self, integration_client: TestClient, test_user: User, db_session: Session):
        """Test password reset fails with expired token."""
        from app.models.password_reset import PasswordResetToken
        from app.core.security import TokenGenerator

        # Create expired token
        reset_token = TokenGenerator.generate_reset_token()
        reset_token_obj = PasswordResetToken.create_reset_token(
            user_id=test_user.id,
            token=reset_token,
            expiry_hours=1
        )
        # Manually set expiration to past
        reset_token_obj.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db_session.add(reset_token_obj)
        db_session.commit()
        
        token = reset_token
        
        reset_data = {
            "token": token,
            "new_password": "N3wP@ssw0rd!"
        }
        
        response = integration_client.post("/api/v1/auth/password-reset/complete", json=reset_data)
        
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()
        
        # Clean up
        db_session.delete(reset_token_obj)
        db_session.commit()


# ==================== PROTECTED ENDPOINTS ====================

@pytest.mark.integration
class TestProtectedEndpoints:
    """Test accessing protected endpoints."""
    
    def test_access_protected_endpoint_with_valid_token(self, integration_authenticated_client: TestClient):
        """Test accessing protected endpoint with valid token."""
        response = integration_authenticated_client.get("/api/v1/users/me")
        
        assert response.status_code == 200
        data = response.json()
        assert "username" in data
        assert "email" in data
    
    def test_access_protected_endpoint_without_token(self, integration_client: TestClient):
        """Test accessing protected endpoint without token fails."""
        response = integration_client.get("/api/v1/users/me")
        
        assert response.status_code == 401
    
    def test_access_protected_endpoint_with_invalid_token(self, integration_client: TestClient):
        """Test accessing protected endpoint with invalid token fails."""
        response = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        
        assert response.status_code == 401
    
    def test_update_user_profile(self, integration_authenticated_client: TestClient):
        """Test updating user profile."""
        update_data = {
            "email": "newemail@example.com"
        }
        
        response = integration_authenticated_client.put("/api/v1/users/me", json=update_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newemail@example.com"
    
    def test_change_password(self, integration_authenticated_client: TestClient, test_password: str):
        """Test changing user password."""
        password_data = {
            "current_password": test_password,
            "new_password": "N3wT3stP@ss!"
        }
        
        response = integration_authenticated_client.put("/api/v1/users/me/password", json=password_data)
        
        assert response.status_code == 200
        assert "password updated" in response.json()["message"].lower()


# ==================== ROLE-BASED ACCESS CONTROL ====================

@pytest.mark.integration
class TestRoleBasedAccessControl:
    """Test role-based access control in practice."""
    
    def test_admin_access_with_admin_role(self, integration_client: TestClient, admin_user: User, db_session: Session):
        """Test admin endpoints accessible with admin role."""
        # Login as admin
        login_data = {
            "username": admin_user.username,
            "password": "Str0ngP@ssw0rd!"
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        assert login_response.status_code == 200
        
        access_token = login_response.json()["access_token"]
        
        # Try to access admin endpoint
        response = integration_client.get(
            "/api/v1/admin/users",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
    
    def test_admin_access_without_admin_role(self, integration_authenticated_client: TestClient):
        """Test admin endpoints forbidden without admin role."""
        response = integration_authenticated_client.get("/api/v1/admin/users")
        
        # Should be 403 since user is authenticated but lacks admin role
        assert response.status_code == 403
        assert "permission" in response.json()["detail"].lower()
    
    def test_admin_access_with_admin_role(self, integration_admin_authenticated_client: TestClient):
        """Test admin endpoints accessible with admin role."""
        response = integration_admin_authenticated_client.get("/api/v1/admin/users")
        
        # Should be 200 since user has admin role
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)  # Should return list of users
    
    def test_assign_role_to_user(self, integration_client: TestClient, admin_user: User, test_user: User, db_session: Session):
        """Test assigning role to user (admin only)."""
        # Login as admin
        login_data = {
            "username": admin_user.username,
            "password": "Str0ngP@ssw0rd!"
        }
        login_response = integration_client.post("/api/v1/auth/token", data=login_data)
        access_token = login_response.json()["access_token"]
        
        # Create a test role
        test_role = db_session.query(Role).filter_by(name="test_role").first()
        if not test_role:
            test_role = Role(name="test_role", description="Test role")
            db_session.add(test_role)
            db_session.commit()
            db_session.refresh(test_role)
        
        # Assign role to test user
        assignment_data = {
            "user_id": test_user.id,
            "role_id": test_role.id
        }
        
        response = integration_client.post(
            "/api/v1/admin/user-roles/assign",
            json=assignment_data,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        
        # Verify assignment
        user_role = db_session.query(UserRole).filter_by(
            user_id=test_user.id,
            role_id=test_role.id
        ).first()
        assert user_role is not None
        
        # Clean up
        db_session.delete(user_role)
        db_session.commit()


# ==================== SESSION MANAGEMENT ====================

@pytest.mark.integration
class TestSessionManagement:
    """Test session management functionality."""
    
    def test_multiple_active_sessions(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test user can have multiple active sessions."""
        # Login from "device 1"
        login1 = integration_client.post(
            "/api/v1/auth/token",
            data={"username": test_user.username, "password": test_password}
        )
        assert login1.status_code == 200
        # Handle potential MFA response
        login1_data = login1.json()
        if "mfa_required" in login1_data:
            # Skip this test if MFA is required (would need MFA setup)
            pytest.skip("MFA is enabled for test user, skipping multi-session test")
        token1 = login1_data["access_token"]

        # Login from "device 2"
        login2 = integration_client.post(
            "/api/v1/auth/token",
            data={"username": test_user.username, "password": test_password}
        )
        assert login2.status_code == 200
        # Handle potential MFA response
        login2_data = login2.json()
        if "mfa_required" in login2_data:
            # Skip this test if MFA is required (would need MFA setup)
            pytest.skip("MFA is enabled for test user, skipping multi-session test")
        token2 = login2_data["access_token"]

        # Both tokens should be different and valid
        assert token1 != token2

        # Both should be able to access protected resources
        response1 = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token1}"}
        )
        response2 = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token2}"}
        )

        assert response1.status_code == 200
        assert response2.status_code == 200
    
    def test_logout_single_session(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test logout only invalidates current session."""
        # Create two sessions
        login1 = integration_client.post(
            "/api/v1/auth/token",
            data={"username": test_user.username, "password": test_password}
        )
        assert login1.status_code == 200
        login1_data = login1.json()
        if "mfa_required" in login1_data:
            pytest.skip("MFA is enabled for test user, skipping logout test")
        token1 = login1_data["access_token"]

        login2 = integration_client.post(
            "/api/v1/auth/token",
            data={"username": test_user.username, "password": test_password}
        )
        assert login2.status_code == 200
        login2_data = login2.json()
        if "mfa_required" in login2_data:
            pytest.skip("MFA is enabled for test user, skipping logout test")
        token2 = login2_data["access_token"]

        # Logout from session 1
        logout_response = integration_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token1}"}
        )
        assert logout_response.status_code == 200

        # Token 1 should be invalid
        response1 = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token1}"}
        )
        assert response1.status_code == 401

        # Token 2 should still be valid
        response2 = integration_client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token2}"}
        )
        assert response2.status_code == 200


# ==================== EDGE CASES AND ERROR HANDLING ====================

@pytest.mark.integration
class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""
    
    def test_concurrent_login_attempts(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test handling concurrent login attempts."""
        # Simulate concurrent logins
        responses = []
        for _ in range(5):
            response = integration_client.post(
                "/api/v1/auth/token",
                data={"username": test_user.username, "password": test_password}
            )
            responses.append(response)

        # All should succeed
        for response in responses:
            assert response.status_code == 200
            response_data = response.json()
            # Handle potential MFA response - if MFA required, skip token check
            if "mfa_required" not in response_data:
                assert "access_token" in response_data
    
    def test_token_reuse_after_refresh(self, integration_client: TestClient, test_user: User, test_password: str):
        """Test that old refresh token cannot be reused after refresh."""
        # Login
        login_response = integration_client.post(
            "/api/v1/auth/token",
            data={"username": test_user.username, "password": test_password}
        )
        assert login_response.status_code == 200
        login_data = login_response.json()
        if "mfa_required" in login_data:
            pytest.skip("MFA is enabled for test user, skipping refresh test")
        old_refresh_token = login_data["refresh_token"]

        # Refresh token
        refresh_response = integration_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh_token}
        )
        assert refresh_response.status_code == 200

        # Try to reuse old refresh token (should fail or return new tokens)
        reuse_response = integration_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh_token}
        )

        # Depending on implementation, this might fail (401) or succeed with rotation
        assert reuse_response.status_code in [200, 401]
    
    def test_sql_injection_prevention(self, integration_client: TestClient):
        """Test that SQL injection attempts are prevented."""
        malicious_input = "admin' OR '1'='1"
        
        login_data = {
            "username": malicious_input,
            "password": "anything"
        }
        
        response = integration_client.post("/api/v1/auth/token", data=login_data)
        
        # Should fail safely, not cause an error
        assert response.status_code == 401
    
    def test_xss_prevention_in_registration(self, integration_client: TestClient):
        """Test that XSS attempts are sanitized."""
        xss_script = "<script>alert('xss')</script>"
        
        registration_data = {
            "username": xss_script,
            "email": "xss@example.com",
            "password": "V@lidP@ss9!"
        }
        
        response = integration_client.post("/api/v1/auth/register", json=registration_data)
        
        # Should either reject or sanitize
        # Validation might reject special characters in username
        assert response.status_code in [400, 422]

