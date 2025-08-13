"""
Redis connection and cache management.
"""

import redis.asyncio as redis
from redis.asyncio import ConnectionPool
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# Redis connection pool
redis_pool = None
redis_client = None

async def init_redis():
    """Initialize Redis connection pool and client."""
    global redis_pool, redis_client
    
    try:
        # Create connection pool
        redis_pool = ConnectionPool.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=20,
            retry_on_timeout=True,
            socket_keepalive=True,
            socket_keepalive_options={},
        )
        
        # Create Redis client
        redis_client = redis.Redis(connection_pool=redis_pool)
        
        # Test connection
        await redis_client.ping()
        logger.info("Redis connection established successfully")
        
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        redis_pool = None
        redis_client = None
        raise

async def get_redis():
    """Get Redis client for dependency injection."""
    if redis_client is None:
        await init_redis()
    return redis_client

async def close_redis():
    """Close Redis connections."""
    global redis_pool, redis_client
    
    if redis_client:
        await redis_client.close()
        redis_client = None
    
    if redis_pool:
        await redis_pool.disconnect()
        redis_pool = None
    
    logger.info("Redis connections closed")

# Cache utility functions
async def set_cache(key: str, value: str, expire: int = 3600):
    """Set a value in cache with expiration."""
    try:
        client = await get_redis()
        await client.setex(key, expire, value)
        return True
    except Exception as e:
        logger.error(f"Failed to set cache: {e}")
        return False

async def get_cache(key: str):
    """Get a value from cache."""
    try:
        client = await get_redis()
        value = await client.get(key)
        return value
    except Exception as e:
        logger.error(f"Failed to get cache: {e}")
        return None

async def delete_cache(key: str):
    """Delete a value from cache."""
    try:
        client = await get_redis()
        await client.delete(key)
        return True
    except Exception as e:
        logger.error(f"Failed to delete cache: {e}")
        return False

async def clear_cache_pattern(pattern: str):
    """Clear cache entries matching a pattern."""
    try:
        client = await get_redis()
        keys = await client.keys(pattern)
        if keys:
            await client.delete(*keys)
        return len(keys)
    except Exception as e:
        logger.error(f"Failed to clear cache pattern: {e}")
        return 0

# Session storage functions
async def store_session(session_id: str, session_data: str, expire: int = 86400):
    """Store session data in Redis."""
    return await set_cache(f"session:{session_id}", session_data, expire)

async def get_session(session_id: str):
    """Retrieve session data from Redis."""
    return await get_cache(f"session:{session_id}")

async def delete_session(session_id: str):
    """Delete session data from Redis."""
    return await delete_cache(f"session:{session_id}")

async def clear_user_sessions(user_id: str):
    """Clear all sessions for a specific user."""
    return await clear_cache_pattern(f"session:*:user:{user_id}")

# Rate limiting functions
async def increment_rate_limit(key: str, expire: int = 60):
    """Increment rate limit counter."""
    try:
        client = await get_redis()
        current = await client.incr(key)
        if current == 1:
            await client.expire(key, expire)
        return current
    except Exception as e:
        logger.error(f"Failed to increment rate limit: {e}")
        return 0

async def get_rate_limit(key: str):
    """Get current rate limit count."""
    try:
        client = await get_redis()
        return await client.get(key) or 0
    except Exception as e:
        logger.error(f"Failed to get rate limit: {e}")
        return 0
