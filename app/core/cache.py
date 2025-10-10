"""
Redis caching utilities for RBAC and user data.

This module provides caching for frequently accessed data to improve performance:
- User roles and permissions
- Permission checks
- User profile data
"""

import json
import logging
from typing import Optional, List, Set, Callable, Any
from functools import wraps
import hashlib

from app.core.redis import get_redis

logger = logging.getLogger(__name__)


class CacheConfig:
    """Cache configuration constants."""
    
    # Cache TTLs (in seconds)
    USER_ROLES_TTL = 300  # 5 minutes
    USER_PERMISSIONS_TTL = 300  # 5 minutes
    PERMISSION_CHECK_TTL = 300  # 5 minutes
    USER_PROFILE_TTL = 600  # 10 minutes
    ROLE_PERMISSIONS_TTL = 600  # 10 minutes
    
    # Cache key prefixes
    USER_ROLES_PREFIX = "cache:user_roles"
    USER_PERMISSIONS_PREFIX = "cache:user_permissions"
    PERMISSION_CHECK_PREFIX = "cache:permission_check"
    USER_PROFILE_PREFIX = "cache:user_profile"
    ROLE_PERMISSIONS_PREFIX = "cache:role_permissions"


class RBACCache:
    """Redis caching for RBAC queries."""
    
    @staticmethod
    def _make_key(prefix: str, *args) -> str:
        """Create a cache key from prefix and arguments."""
        key_parts = [str(arg) for arg in args]
        return f"{prefix}:{':'.join(key_parts)}"
    
    @staticmethod
    async def get_user_roles(user_id: int) -> Optional[List[dict]]:
        """
        Get cached user roles.
        
        Args:
            user_id: User ID
            
        Returns:
            List of role dicts or None if not cached
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.USER_ROLES_PREFIX, user_id)
            cached = await redis_client.get(key)
            
            if cached:
                logger.debug(f"Cache HIT: user_roles for user_id={user_id}")
                return json.loads(cached)
            
            logger.debug(f"Cache MISS: user_roles for user_id={user_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached user roles: {e}")
            return None
    
    @staticmethod
    async def set_user_roles(user_id: int, roles: List[dict], ttl: int = None) -> bool:
        """
        Cache user roles.
        
        Args:
            user_id: User ID
            roles: List of role dicts (should be serializable)
            ttl: Time to live in seconds (default: CacheConfig.USER_ROLES_TTL)
            
        Returns:
            True if cached successfully
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.USER_ROLES_PREFIX, user_id)
            ttl = ttl or CacheConfig.USER_ROLES_TTL
            
            # Serialize roles to JSON
            value = json.dumps(roles)
            await redis_client.setex(key, ttl, value)
            
            logger.debug(f"Cached user_roles for user_id={user_id}, ttl={ttl}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching user roles: {e}")
            return False
    
    @staticmethod
    async def get_user_permissions(user_id: int) -> Optional[Set[str]]:
        """
        Get cached user permissions.
        
        Args:
            user_id: User ID
            
        Returns:
            Set of permission strings or None if not cached
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.USER_PERMISSIONS_PREFIX, user_id)
            cached = await redis_client.get(key)
            
            if cached:
                logger.debug(f"Cache HIT: user_permissions for user_id={user_id}")
                return set(json.loads(cached))
            
            logger.debug(f"Cache MISS: user_permissions for user_id={user_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached user permissions: {e}")
            return None
    
    @staticmethod
    async def set_user_permissions(user_id: int, permissions: Set[str], ttl: int = None) -> bool:
        """
        Cache user permissions.
        
        Args:
            user_id: User ID
            permissions: Set of permission strings (e.g., {"users:create", "posts:read"})
            ttl: Time to live in seconds (default: CacheConfig.USER_PERMISSIONS_TTL)
            
        Returns:
            True if cached successfully
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.USER_PERMISSIONS_PREFIX, user_id)
            ttl = ttl or CacheConfig.USER_PERMISSIONS_TTL
            
            # Serialize permissions to JSON (convert set to list)
            value = json.dumps(list(permissions))
            await redis_client.setex(key, ttl, value)
            
            logger.debug(f"Cached user_permissions for user_id={user_id}, ttl={ttl}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching user permissions: {e}")
            return False
    
    @staticmethod
    async def get_permission_check(user_id: int, resource: str, action: str) -> Optional[bool]:
        """
        Get cached permission check result.
        
        Args:
            user_id: User ID
            resource: Resource name
            action: Action name
            
        Returns:
            True/False if cached, None if not cached
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(
                CacheConfig.PERMISSION_CHECK_PREFIX, 
                user_id, 
                resource, 
                action
            )
            cached = await redis_client.get(key)
            
            if cached is not None:
                logger.debug(f"Cache HIT: permission_check user_id={user_id}, {resource}:{action}")
                return cached == "1"
            
            logger.debug(f"Cache MISS: permission_check user_id={user_id}, {resource}:{action}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached permission check: {e}")
            return None
    
    @staticmethod
    async def set_permission_check(
        user_id: int, 
        resource: str, 
        action: str, 
        has_permission: bool,
        ttl: int = None
    ) -> bool:
        """
        Cache permission check result.
        
        Args:
            user_id: User ID
            resource: Resource name
            action: Action name
            has_permission: Whether user has the permission
            ttl: Time to live in seconds (default: CacheConfig.PERMISSION_CHECK_TTL)
            
        Returns:
            True if cached successfully
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(
                CacheConfig.PERMISSION_CHECK_PREFIX, 
                user_id, 
                resource, 
                action
            )
            ttl = ttl or CacheConfig.PERMISSION_CHECK_TTL
            
            # Store as "1" or "0" string
            value = "1" if has_permission else "0"
            await redis_client.setex(key, ttl, value)
            
            logger.debug(f"Cached permission_check user_id={user_id}, {resource}:{action}={has_permission}, ttl={ttl}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching permission check: {e}")
            return False
    
    @staticmethod
    async def get_role_permissions(role_id: int) -> Optional[List[dict]]:
        """
        Get cached role permissions.
        
        Args:
            role_id: Role ID
            
        Returns:
            List of permission dicts (with id, resource, action) or None if not cached
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.ROLE_PERMISSIONS_PREFIX, role_id)
            cached = await redis_client.get(key)
            
            if cached:
                logger.debug(f"Cache HIT: role_permissions for role_id={role_id}")
                return json.loads(cached)
            
            logger.debug(f"Cache MISS: role_permissions for role_id={role_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached role permissions: {e}")
            return None
    
    @staticmethod
    async def set_role_permissions(role_id: int, permissions: List[dict], ttl: int = None) -> bool:
        """
        Cache role permissions.
        
        Args:
            role_id: Role ID
            permissions: List of permission dicts (must be JSON serializable)
            ttl: Time to live in seconds (default: CacheConfig.ROLE_PERMISSIONS_TTL)
            
        Returns:
            True if cached successfully
        """
        try:
            redis_client = await get_redis()
            key = RBACCache._make_key(CacheConfig.ROLE_PERMISSIONS_PREFIX, role_id)
            ttl = ttl or CacheConfig.ROLE_PERMISSIONS_TTL
            
            value = json.dumps(permissions)
            await redis_client.setex(key, ttl, value)
            
            logger.debug(f"Cached role_permissions for role_id={role_id}, ttl={ttl}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching role permissions: {e}")
            return False
    
    @staticmethod
    async def invalidate_user(user_id: int) -> int:
        """
        Invalidate all cache entries for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of cache entries deleted
        """
        try:
            redis_client = await get_redis()
            
            # Delete user roles cache
            roles_key = RBACCache._make_key(CacheConfig.USER_ROLES_PREFIX, user_id)
            
            # Delete user permissions cache
            perms_key = RBACCache._make_key(CacheConfig.USER_PERMISSIONS_PREFIX, user_id)
            
            # Delete all permission checks for this user
            perm_check_pattern = RBACCache._make_key(CacheConfig.PERMISSION_CHECK_PREFIX, user_id, "*")
            perm_check_keys = await redis_client.keys(perm_check_pattern)
            
            # Combine all keys to delete
            keys_to_delete = [roles_key, perms_key] + perm_check_keys
            
            deleted = 0
            for key in keys_to_delete:
                if await redis_client.delete(key):
                    deleted += 1
            
            logger.info(f"Invalidated {deleted} cache entries for user_id={user_id}")
            return deleted
            
        except Exception as e:
            logger.error(f"Error invalidating user cache: {e}")
            return 0
    
    @staticmethod
    async def invalidate_role(role_id: int) -> int:
        """
        Invalidate cache entries for a role.
        
        When a role's permissions change, we need to invalidate:
        1. The role's permission cache
        2. All users who have this role
        
        Args:
            role_id: Role ID
            
        Returns:
            Number of cache entries deleted
        """
        try:
            redis_client = await get_redis()
            
            # Delete role permissions cache
            role_key = RBACCache._make_key(CacheConfig.ROLE_PERMISSIONS_PREFIX, role_id)
            deleted = await redis_client.delete(role_key)
            
            logger.info(f"Invalidated {deleted} cache entries for role_id={role_id}")
            logger.warning(
                f"Role {role_id} permissions changed. "
                f"User caches will be invalidated on next access or after TTL expires."
            )
            
            return deleted
            
        except Exception as e:
            logger.error(f"Error invalidating role cache: {e}")
            return 0
    
    @staticmethod
    async def invalidate_all_users() -> int:
        """
        Invalidate all user-related caches.
        
        Use this sparingly, e.g., after bulk permission updates.
        
        Returns:
            Number of cache entries deleted
        """
        try:
            redis_client = await get_redis()
            
            patterns = [
                f"{CacheConfig.USER_ROLES_PREFIX}:*",
                f"{CacheConfig.USER_PERMISSIONS_PREFIX}:*",
                f"{CacheConfig.PERMISSION_CHECK_PREFIX}:*",
            ]
            
            deleted = 0
            for pattern in patterns:
                keys = await redis_client.keys(pattern)
                if keys:
                    deleted += await redis_client.delete(*keys)
            
            logger.warning(f"Invalidated ALL user caches: {deleted} entries deleted")
            return deleted
            
        except Exception as e:
            logger.error(f"Error invalidating all user caches: {e}")
            return 0


class UserDataCache:
    """Redis caching for user profile data."""
    
    @staticmethod
    def _make_key(user_id: int) -> str:
        """Create cache key for user profile."""
        return f"{CacheConfig.USER_PROFILE_PREFIX}:{user_id}"
    
    @staticmethod
    async def get_user_profile(user_id: int) -> Optional[dict]:
        """
        Get cached user profile.
        
        Args:
            user_id: User ID
            
        Returns:
            User profile dict or None if not cached
        """
        try:
            redis_client = await get_redis()
            key = UserDataCache._make_key(user_id)
            cached = await redis_client.get(key)
            
            if cached:
                logger.debug(f"Cache HIT: user_profile for user_id={user_id}")
                return json.loads(cached)
            
            logger.debug(f"Cache MISS: user_profile for user_id={user_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached user profile: {e}")
            return None
    
    @staticmethod
    async def set_user_profile(user_id: int, profile: dict, ttl: int = None) -> bool:
        """
        Cache user profile.
        
        Args:
            user_id: User ID
            profile: User profile dict (must be JSON serializable)
            ttl: Time to live in seconds (default: CacheConfig.USER_PROFILE_TTL)
            
        Returns:
            True if cached successfully
        """
        try:
            redis_client = await get_redis()
            key = UserDataCache._make_key(user_id)
            ttl = ttl or CacheConfig.USER_PROFILE_TTL
            
            value = json.dumps(profile)
            await redis_client.setex(key, ttl, value)
            
            logger.debug(f"Cached user_profile for user_id={user_id}, ttl={ttl}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching user profile: {e}")
            return False
    
    @staticmethod
    async def invalidate_user_profile(user_id: int) -> bool:
        """
        Invalidate cached user profile.
        
        Args:
            user_id: User ID
            
        Returns:
            True if invalidated successfully
        """
        try:
            redis_client = await get_redis()
            key = UserDataCache._make_key(user_id)
            deleted = await redis_client.delete(key)
            
            logger.debug(f"Invalidated user_profile for user_id={user_id}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Error invalidating user profile: {e}")
            return False


def cache_result(
    cache_key_fn: Callable,
    ttl: int = 300,
    get_cache_fn: Optional[Callable] = None,
    set_cache_fn: Optional[Callable] = None
):
    """
    Decorator for caching function results in Redis.
    
    Args:
        cache_key_fn: Function that takes the same args as decorated function and returns cache key
        ttl: Time to live in seconds
        get_cache_fn: Optional custom function to get from cache
        set_cache_fn: Optional custom function to set in cache
        
    Example:
        @cache_result(
            cache_key_fn=lambda user_id: f"user_data:{user_id}",
            ttl=600
        )
        async def get_user_data(user_id: int):
            # Expensive database query
            return user_data
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = cache_key_fn(*args, **kwargs)
            
            # Try to get from cache
            try:
                redis_client = await get_redis()
                cached = await redis_client.get(cache_key)
                
                if cached is not None:
                    logger.debug(f"Cache HIT: {cache_key}")
                    return json.loads(cached)
                
                logger.debug(f"Cache MISS: {cache_key}")
                
            except Exception as e:
                logger.error(f"Error getting from cache: {e}")
            
            # Call the actual function
            result = await func(*args, **kwargs)
            
            # Cache the result
            try:
                redis_client = await get_redis()
                value = json.dumps(result)
                await redis_client.setex(cache_key, ttl, value)
                logger.debug(f"Cached result for {cache_key}, ttl={ttl}s")
                
            except Exception as e:
                logger.error(f"Error setting cache: {e}")
            
            return result
        
        return wrapper
    return decorator

