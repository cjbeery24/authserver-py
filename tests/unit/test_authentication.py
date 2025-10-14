"""
Unit tests for authentication manager and related functionality.

Tests for:
- User authentication logic
- MFA verification
- Password verification
- Account status checking
"""

import pytest
import json
from unittest.mock import AsyncMock, patch

from app.core.security import AuthenticationManager, PasswordHasher
from app.core.cache import RBACCache
from app.models.user import User
from app.models.mfa_secret import MFASecret


# ==================== AUTHENTICATION MANAGER TESTS ====================

@pytest.mark.unit
@pytest.mark.database
class TestAuthenticationManager:
    """Test authentication manager functionality."""
    
    async def test_authenticate_user_success(self, db_session, test_user, test_password):
        """Test successful user authentication without MFA."""
        user, requires_mfa, error = await AuthenticationManager.authenticate_user(
            username=test_user.username,
            password=test_password,
            db_session=db_session,
            redis_client=None,
            client_ip="127.0.0.1"
        )
        
        assert user is not None
        assert user.id == test_user.id
        assert requires_mfa is False
        assert error is None
    
    async def test_authenticate_user_wrong_password(self, db_session, test_user):
        """Test authentication with wrong password."""
        user, requires_mfa, error = await AuthenticationManager.authenticate_user(
            username=test_user.username,
            password="Wr0ngP@ssw0rd!",
            db_session=db_session,
            redis_client=None,
            client_ip="127.0.0.1"
        )
        
        assert user is None
        assert requires_mfa is False
        assert error is not None
        assert "Invalid credentials" in error
    
    async def test_authenticate_user_nonexistent(self, db_session):
        """Test authentication with nonexistent user."""
        user, requires_mfa, error = await AuthenticationManager.authenticate_user(
            username="nonexistent",
            password="Str0ngP@ssw0rd!",
            db_session=db_session,
            redis_client=None,
            client_ip="127.0.0.1"
        )
        
        assert user is None
        assert requires_mfa is False
        assert error is not None
    
    async def test_authenticate_user_inactive_account(self, db_session, test_user, test_password):
        """Test authentication with inactive account."""
        # Deactivate user
        test_user.is_active = False
        db_session.commit()
        
        user, requires_mfa, error = await AuthenticationManager.authenticate_user(
            username=test_user.username,
            password=test_password,
            db_session=db_session,
            redis_client=None,
            client_ip="127.0.0.1"
        )
        
        assert user is None
        assert error is not None
        assert "deactivated" in error.lower()
    
    async def test_authenticate_user_mfa_required(self, db_session, test_user, test_password):
        """Test authentication when MFA is enabled but token not provided."""
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
        
        user, requires_mfa, error = await AuthenticationManager.authenticate_user(
            username=test_user.username,
            password=test_password,
            db_session=db_session,
            redis_client=None,
            client_ip="127.0.0.1"
        )
        
        assert user is not None
        assert requires_mfa is True
        assert error is None
    
    def test_verify_password_only_success(self, db_session, test_user, test_password):
        """Test password-only verification (no MFA check)."""
        user = AuthenticationManager.verify_password_only(
            username=test_user.username,
            password=test_password,
            db_session=db_session
        )
        
        assert user is not None
        assert user.id == test_user.id
    
    def test_verify_password_only_wrong_password(self, db_session, test_user):
        """Test password-only verification with wrong password."""
        user = AuthenticationManager.verify_password_only(
            username=test_user.username,
            password="Wr0ngP@ssw0rd!",
            db_session=db_session
        )
        
        assert user is None
    
    def test_verify_password_only_inactive_user(self, db_session, test_user, test_password):
        """Test password-only verification with inactive user."""
        test_user.is_active = False
        db_session.commit()
        
        user = AuthenticationManager.verify_password_only(
            username=test_user.username,
            password=test_password,
            db_session=db_session
        )
        
        assert user is None
    
    def test_verify_user_password_correct(self, test_user, test_password):
        """Test verifying user's password when correct."""
        result = AuthenticationManager.verify_user_password(test_user, test_password)
        assert result is True
    
    def test_verify_user_password_incorrect(self, test_user):
        """Test verifying user's password when incorrect."""
        result = AuthenticationManager.verify_user_password(test_user, "Wr0ngP@ss!")
        assert result is False
    
    def test_is_user_active_true(self, test_user):
        """Test checking if user is active."""
        assert AuthenticationManager.is_user_active(test_user) is True
    
    def test_is_user_active_false(self, test_user):
        """Test checking if user is inactive."""
        test_user.is_active = False
        assert AuthenticationManager.is_user_active(test_user) is False
    
    def test_is_user_active_none(self):
        """Test checking if user is active when user is None."""
        assert AuthenticationManager.is_user_active(None) is False


# ==================== CACHE MOCKING TESTS ====================

@pytest.mark.unit
class TestCacheMocking:
    """Test cache functionality with mocks (no Redis required)."""
    
    @patch('app.core.cache.get_redis')
    async def test_rbac_cache_set_with_mock(self, mock_get_redis):
        """Test caching with mocked Redis."""
        mock_redis = AsyncMock()
        mock_redis.setex.return_value = True
        mock_get_redis.return_value = mock_redis
        
        user_id = 123
        roles = [{"id": 1, "name": "user"}]
        
        success = await RBACCache.set_user_roles(user_id, roles)
        
        assert success is True
        mock_redis.setex.assert_called_once()
    
    @patch('app.core.cache.get_redis')
    async def test_rbac_cache_get_with_mock(self, mock_get_redis):
        """Test retrieving from cache with mocked Redis."""
        mock_redis = AsyncMock()
        mock_redis.get.return_value = json.dumps([{"id": 1, "name": "admin"}])
        mock_get_redis.return_value = mock_redis
        
        user_id = 123
        
        roles = await RBACCache.get_user_roles(user_id)
        
        assert roles is not None
        assert len(roles) == 1
        assert roles[0]["name"] == "admin"
    
    @patch('app.core.cache.get_redis')
    async def test_cache_error_handling(self, mock_get_redis):
        """Test cache error handling."""
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = Exception("Redis connection error")
        mock_get_redis.return_value = mock_redis
        
        # Should return None on error, not raise exception
        result = await RBACCache.get_user_roles(123)
        assert result is None


# ==================== CACHE TTL TESTS ====================

@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.redis  
class TestCacheTTL:
    """Test cache TTL (Time To Live) functionality."""
    
    async def test_user_roles_cache_with_custom_ttl(self):
        """Test caching user roles with custom TTL."""
        user_id = 123
        roles = [{"id": 1, "name": "user"}]
        custom_ttl = 60  # 1 minute
        
        success = await RBACCache.set_user_roles(user_id, roles, ttl=custom_ttl)
        assert success is True
        
        # Verify it's cached
        cached = await RBACCache.get_user_roles(user_id)
        assert cached is not None
    
    async def test_permission_check_cache_with_custom_ttl(self):
        """Test caching permission checks with custom TTL."""
        user_id = 123
        custom_ttl = 120  # 2 minutes
        
        success = await RBACCache.set_permission_check(
            user_id, "users", "create", True, ttl=custom_ttl
        )
        assert success is True
        
        # Verify it's cached
        result = await RBACCache.get_permission_check(user_id, "users", "create")
        assert result is True


# ==================== CACHE INVALIDATION EDGE CASES ====================

@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.redis
class TestCacheInvalidationEdgeCases:
    """Test edge cases in cache invalidation."""
    
    async def test_invalidate_nonexistent_user(self):
        """Test invalidating cache for user with no cached data."""
        deleted = await RBACCache.invalidate_user(999)
        
        # Should not error, just return 0
        assert deleted >= 0
    
    async def test_invalidate_all_users(self):
        """Test invalidating all user caches."""
        # Cache data for multiple users
        await RBACCache.set_user_roles(1, [{"id": 1, "name": "user"}])
        await RBACCache.set_user_roles(2, [{"id": 2, "name": "admin"}])
        await RBACCache.set_user_permissions(1, {"users:read"})
        await RBACCache.set_user_permissions(2, {"users:create"})
        
        # Invalidate all
        deleted = await RBACCache.invalidate_all_users()
        
        assert deleted >= 4  # At least 4 entries deleted
        
        # Verify all are cleared
        assert await RBACCache.get_user_roles(1) is None
        assert await RBACCache.get_user_roles(2) is None
        assert await RBACCache.get_user_permissions(1) is None
        assert await RBACCache.get_user_permissions(2) is None

