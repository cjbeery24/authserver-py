"""
Unit tests for cache utilities.

Tests for:
- RBAC cache operations
- User data cache
- Cache invalidation
"""

import pytest
import json

from app.core.cache import RBACCache, UserDataCache, CacheConfig


# ==================== RBAC CACHE TESTS ====================

@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.redis
class TestRBACCache:
    """Test RBAC caching functionality."""
    
    async def test_cache_key_generation(self):
        """Test cache key generation."""
        key = RBACCache._make_key("prefix", "123", "456")
        assert key == "prefix:123:456"
    
    async def test_set_and_get_user_roles(self):
        """Test caching and retrieving user roles."""
        user_id = 123
        roles_data = [
            {"id": 1, "name": "admin", "description": "Administrator"},
            {"id": 2, "name": "user", "description": "Regular user"}
        ]
        
        # Set cache
        success = await RBACCache.set_user_roles(user_id, roles_data)
        assert success is True
        
        # Get from cache
        cached_roles = await RBACCache.get_user_roles(user_id)
        assert cached_roles is not None
        assert len(cached_roles) == 2
        assert cached_roles[0]["name"] == "admin"
        assert cached_roles[1]["name"] == "user"
    
    async def test_get_user_roles_not_cached(self):
        """Test getting user roles when not cached."""
        cached_roles = await RBACCache.get_user_roles(999)
        assert cached_roles is None
    
    async def test_set_and_get_user_permissions(self):
        """Test caching and retrieving user permissions."""
        user_id = 123
        permissions = {"users:create", "posts:read", "posts:update"}
        
        # Set cache
        success = await RBACCache.set_user_permissions(user_id, permissions)
        assert success is True
        
        # Get from cache
        cached_perms = await RBACCache.get_user_permissions(user_id)
        assert cached_perms is not None
        assert cached_perms == permissions
    
    async def test_set_and_get_permission_check(self):
        """Test caching individual permission checks."""
        user_id = 123
        resource = "users"
        action = "create"
        
        # Cache positive result
        success = await RBACCache.set_permission_check(user_id, resource, action, True)
        assert success is True
        
        # Retrieve cached result
        result = await RBACCache.get_permission_check(user_id, resource, action)
        assert result is True
        
        # Cache negative result
        await RBACCache.set_permission_check(user_id, "admin", "access", False)
        result = await RBACCache.get_permission_check(user_id, "admin", "access")
        assert result is False
    
    async def test_set_and_get_role_permissions(self):
        """Test caching role permissions."""
        role_id = 5
        permissions = [
            {"id": 1, "resource": "users", "action": "create"},
            {"id": 2, "resource": "users", "action": "read"}
        ]
        
        # Set cache
        success = await RBACCache.set_role_permissions(role_id, permissions)
        assert success is True
        
        # Get from cache
        cached_perms = await RBACCache.get_role_permissions(role_id)
        assert cached_perms is not None
        assert len(cached_perms) == 2
        assert cached_perms[0]["resource"] == "users"
    
    async def test_invalidate_user(self):
        """Test invalidating all cache entries for a user."""
        user_id = 123
        
        # Cache some data
        await RBACCache.set_user_roles(user_id, [{"id": 1, "name": "admin"}])
        await RBACCache.set_user_permissions(user_id, {"users:create"})
        await RBACCache.set_permission_check(user_id, "users", "create", True)
        
        # Invalidate
        deleted = await RBACCache.invalidate_user(user_id)
        assert deleted >= 2  # At least roles and permissions deleted
        
        # Verify cache is cleared
        assert await RBACCache.get_user_roles(user_id) is None
        assert await RBACCache.get_user_permissions(user_id) is None
    
    async def test_invalidate_role(self):
        """Test invalidating cache for a role."""
        role_id = 5
        
        # Cache role permissions
        await RBACCache.set_role_permissions(role_id, [{"id": 1, "resource": "users", "action": "read"}])
        
        # Invalidate
        deleted = await RBACCache.invalidate_role(role_id)
        assert deleted >= 1
        
        # Verify cache is cleared
        assert await RBACCache.get_role_permissions(role_id) is None


# ==================== USER DATA CACHE TESTS ====================

@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.redis
class TestUserDataCache:
    """Test user data caching functionality."""
    
    async def test_set_and_get_user_profile(self):
        """Test caching and retrieving user profile."""
        user_id = 456
        profile = {
            "id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "is_active": True
        }
        
        # Set cache
        success = await UserDataCache.set_user_profile(user_id, profile)
        assert success is True
        
        # Get from cache
        cached_profile = await UserDataCache.get_user_profile(user_id)
        assert cached_profile is not None
        assert cached_profile["username"] == "testuser"
        assert cached_profile["email"] == "test@example.com"
    
    async def test_get_user_profile_not_cached(self):
        """Test getting user profile when not cached."""
        cached_profile = await UserDataCache.get_user_profile(999)
        assert cached_profile is None
    
    async def test_invalidate_user_profile(self):
        """Test invalidating user profile cache."""
        user_id = 456
        profile = {"id": user_id, "username": "testuser"}
        
        # Set cache
        await UserDataCache.set_user_profile(user_id, profile)
        
        # Invalidate
        invalidated = await UserDataCache.invalidate_user_profile(user_id)
        assert invalidated is True
        
        # Verify cache is cleared
        assert await UserDataCache.get_user_profile(user_id) is None


# ==================== CACHE CONFIG TESTS ====================

@pytest.mark.unit
class TestCacheConfig:
    """Test cache configuration constants."""
    
    def test_cache_ttl_values(self):
        """Test that cache TTL values are reasonable."""
        assert CacheConfig.USER_ROLES_TTL > 0
        assert CacheConfig.USER_PERMISSIONS_TTL > 0
        assert CacheConfig.PERMISSION_CHECK_TTL > 0
        assert CacheConfig.USER_PROFILE_TTL > 0
        assert CacheConfig.ROLE_PERMISSIONS_TTL > 0
        
        # TTLs should be between 1 minute and 1 hour
        assert 60 <= CacheConfig.USER_ROLES_TTL <= 3600
        assert 60 <= CacheConfig.USER_PERMISSIONS_TTL <= 3600
    
    def test_cache_key_prefixes(self):
        """Test that cache key prefixes are unique."""
        prefixes = {
            CacheConfig.USER_ROLES_PREFIX,
            CacheConfig.USER_PERMISSIONS_PREFIX,
            CacheConfig.PERMISSION_CHECK_PREFIX,
            CacheConfig.USER_PROFILE_PREFIX,
            CacheConfig.ROLE_PERMISSIONS_PREFIX
        }
        
        # All prefixes should be unique
        assert len(prefixes) == 5

