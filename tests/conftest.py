"""
Pytest configuration and fixtures for testing.

This module provides common fixtures for:
- Database session management
- Redis connection (real and mocked)
- Test client for API testing
- Mock dependencies
"""

import pytest
import asyncio
from typing import Generator, AsyncGenerator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import AsyncMock

from app.main import app
from app.core.database import Base, get_db
from app.core.redis import get_redis
from app.core.config import settings


# ==================== DATABASE FIXTURES ====================

@pytest.fixture(scope="session")
def test_db_engine():
    """Create a test database engine with in-memory SQLite."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_db_engine):
    """Create a fresh database session for each test."""
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_db_engine,
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        # Clear all tables for next test
        Base.metadata.drop_all(bind=test_db_engine)
        Base.metadata.create_all(bind=test_db_engine)


@pytest.fixture(scope="function")
def override_get_db(db_session):
    """Override the get_db dependency to use test database."""
    def _override_get_db() -> Generator:
        yield db_session
    return _override_get_db


# ==================== REDIS FIXTURES ====================

@pytest.fixture(scope="function")
def mock_redis():
    """Create a mock Redis client for unit tests."""
    mock = AsyncMock()
    mock.get.return_value = None
    mock.setex.return_value = True
    mock.delete.return_value = True
    mock.ping.return_value = True
    return mock


@pytest.fixture(scope="function")
def override_get_redis(mock_redis):
    """Override the get_redis dependency to use mock Redis."""
    async def _override_get_redis() -> AsyncGenerator:
        yield mock_redis
    return _override_get_redis


@pytest.fixture(scope="function", autouse=True)
def clear_redis_cache():
    """Clear Redis cache before and after each test (for integration tests)."""
    import logging
    logger = logging.getLogger(__name__)

    def _clear_cache():
        """Helper to clear Redis cache."""
        try:
            # Reset the global Redis client to force reconnection
            import app.core.redis as redis_module
            redis_module.redis_client = None
            redis_module.redis_pool = None

            # Use synchronous Redis client to avoid event loop issues
            import redis
            from app.core.config import settings

            redis_url = getattr(settings, 'redis_url', 'redis://redis-test:6379/0')
            sync_redis = redis.Redis.from_url(redis_url, decode_responses=True)

            # Test connection first
            sync_redis.ping()
            sync_redis.flushdb()
            logger.debug("Redis cache cleared successfully")
        except Exception as e:
            logger.error(f"Failed to clear Redis cache: {e}")
            raise  # Fail the test if Redis clearing fails

    # Clear before test
    _clear_cache()
    yield
    # Clear after test
    _clear_cache()


# ==================== API CLIENT FIXTURES ====================

@pytest.fixture(scope="function")
def client(override_get_db, override_get_redis, db_session, mock_redis):
    """Create a test client for unit tests with mocked dependencies."""
    from fastapi import FastAPI
    from app.middleware import (
        AuthMiddleware,
        OptionalAuthMiddleware,
        SecurityHeadersMiddleware,
        RequestResponseLoggingMiddleware,
        RequestValidationMiddleware,
    )
    from app.core.config import settings

    # Create a test app with middleware configured for testing
    test_app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Add middleware with test-specific dependencies
    if settings.auth_middleware_enabled:
        test_app.add_middleware(
            AuthMiddleware,
            redis_getter=override_get_redis,  # Use mock Redis
            db_getter=override_get_db,       # Use test database session
        )

    test_app.add_middleware(RequestValidationMiddleware)
    test_app.add_middleware(SecurityHeadersMiddleware)

    # Include routers (same as main app)
    from app.api.v1.health import router as health_router
    from app.api.v1.auth import router as auth_router
    from app.api.v1.oauth import router as oauth_router
    from app.api.v1.security import router as security_router
    from app.api.v1.mfa import router as mfa_router
    from app.api.v1.users import router as users_router
    from app.api.v1.admin import router as admin_router

    test_app.include_router(health_router, prefix="/api/v1", tags=["health"])
    test_app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
    test_app.include_router(oauth_router, prefix="/oauth", tags=["oauth"])
    test_app.include_router(security_router, prefix="/api/v1/security", tags=["security"])
    test_app.include_router(mfa_router, prefix="/api/v1/mfa", tags=["mfa"])
    test_app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
    test_app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])

    # Override dependencies
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[get_redis] = override_get_redis

    with TestClient(test_app) as test_client:
        yield test_client


@pytest.fixture(scope="function")
def integration_client(override_get_db, db_session, clear_redis_cache):
    """Create a test client for integration tests with real Redis."""
    from fastapi import FastAPI
    from fastapi_limiter import FastAPILimiter
    from contextlib import asynccontextmanager
    from app.middleware import (
        AuthMiddleware,
        OptionalAuthMiddleware,
        SecurityHeadersMiddleware,
        RequestResponseLoggingMiddleware,
        RequestValidationMiddleware,
    )
    from app.core.redis import get_redis
    from app.core.config import settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Handle application startup and shutdown events for tests."""
        # Startup
        if settings.auth_rate_limit_enabled:
            redis_client = await get_redis()
            await FastAPILimiter.init(redis_client)

        yield

        # Shutdown - cleanup will be handled by clear_redis_cache fixture

    # Create a test app with middleware configured for testing
    test_app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # Add middleware with test-specific dependencies
    if settings.auth_middleware_enabled:
        test_app.add_middleware(
            AuthMiddleware,
            redis_getter=get_redis,         # Use real Redis
            db_getter=override_get_db,      # Use test database session
        )

    test_app.add_middleware(RequestValidationMiddleware)
    test_app.add_middleware(SecurityHeadersMiddleware)

    # Include routers (same as main app)
    from app.api.v1.health import router as health_router
    from app.api.v1.auth import router as auth_router
    from app.api.v1.oauth import router as oauth_router
    from app.api.v1.security import router as security_router
    from app.api.v1.mfa import router as mfa_router
    from app.api.v1.users import router as users_router
    from app.api.v1.admin import router as admin_router

    test_app.include_router(health_router, prefix="/api/v1", tags=["health"])
    test_app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
    test_app.include_router(oauth_router, prefix="/oauth", tags=["oauth"])
    test_app.include_router(security_router, prefix="/api/v1/security", tags=["security"])
    test_app.include_router(mfa_router, prefix="/api/v1/mfa", tags=["mfa"])
    test_app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
    test_app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])

    # Override dependencies
    test_app.dependency_overrides[get_db] = override_get_db

    with TestClient(test_app) as test_client:
        yield test_client


# ==================== AUTHENTICATED CLIENT FIXTURES ====================

@pytest.fixture(scope="function")
def authenticated_client(client, test_user, db_session):
    """Create a test client with an authenticated regular user (for unit tests)."""
    from app.core.token import TokenManager

    # Create access token for test user
    token_data = {
        "sub": str(test_user.id),
        "username": test_user.username,
        "email": test_user.email,
        "roles": ["user"]
    }
    access_token = TokenManager.create_access_token(token_data)

    # Add authorization header to client
    client.headers["Authorization"] = f"Bearer {access_token}"

    yield client

    # Clean up
    client.headers.pop("Authorization", None)


@pytest.fixture(scope="function")
def integration_authenticated_client(integration_client, test_user, db_session):
    """Create an integration test client with an authenticated regular user."""
    from app.core.token import TokenManager

    # Create access token for test user
    token_data = {
        "sub": str(test_user.id),
        "username": test_user.username,
        "email": test_user.email,
        "roles": ["user"]
    }
    access_token = TokenManager.create_access_token(token_data)

    # Add authorization header to client
    integration_client.headers["Authorization"] = f"Bearer {access_token}"

    yield integration_client

    # Clean up
    integration_client.headers.pop("Authorization", None)


@pytest.fixture(scope="function")
def admin_authenticated_client(client, admin_user, db_session):
    """Create a test client with an authenticated admin user."""
    from app.core.token import TokenManager

    # Create access token for admin user with admin role
    token_data = {
        "sub": str(admin_user.id),
        "username": admin_user.username,
        "email": admin_user.email,
        "roles": ["admin"]
    }
    access_token = TokenManager.create_access_token(token_data)

    # Add authorization header to client
    client.headers["Authorization"] = f"Bearer {access_token}"

    yield client

    # Clean up
    client.headers.pop("Authorization", None)


@pytest.fixture(scope="function")
def integration_admin_authenticated_client(integration_client, admin_user, db_session):
    """Create an integration test client with an authenticated admin user."""
    from app.core.token import TokenManager

    # Create access token for admin user with admin role
    token_data = {
        "sub": str(admin_user.id),
        "username": admin_user.username,
        "email": admin_user.email,
        "roles": ["admin"]
    }
    access_token = TokenManager.create_access_token(token_data)

    # Add authorization header to client
    integration_client.headers["Authorization"] = f"Bearer {access_token}"

    yield integration_client

    # Clean up
    integration_client.headers.pop("Authorization", None)


@pytest.fixture(scope="function")
def superuser_authenticated_client(client, db_session):
    """Create a test client with an authenticated superuser."""
    from app.models.user import User
    from app.models.role import Role
    from app.models.user_role import UserRole
    from app.core.crypto import PasswordHasher, TokenManager

    # Create superuser role if it doesn't exist
    superuser_role = db_session.query(Role).filter(Role.name == "superuser").first()
    if not superuser_role:
        superuser_role = Role(name="superuser", description="Super administrator role")
        db_session.add(superuser_role)
        db_session.commit()
        db_session.refresh(superuser_role)

    # Create superuser
    user = User(
        username="superuser",
        email="super@example.com",
        password_hash=PasswordHasher.hash_password("Str0ngP@ssw0rd!", "superuser"),
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Assign superuser role
    user_role = UserRole(user_id=user.id, role_id=superuser_role.id)
    db_session.add(user_role)
    db_session.commit()

    # Create access token for superuser
    token_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "roles": ["superuser"]
    }
    access_token = TokenManager.create_access_token(token_data)

    # Add authorization header to client
    client.headers["Authorization"] = f"Bearer {access_token}"

    yield client

    # Clean up
    client.headers.pop("Authorization", None)


@pytest.fixture(scope="function")
def create_authenticated_client():
    """Factory fixture to create authenticated clients with custom roles."""
    def _create_client(client, user, roles, db_session):
        from app.core.token import TokenManager

        # Create access token with specified roles
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": roles
        }
        access_token = TokenManager.create_access_token(token_data)

        # Add authorization header to client
        client.headers["Authorization"] = f"Bearer {access_token}"

        return client

    return _create_client


# ==================== USER FIXTURES ====================

@pytest.fixture(scope="function")
def test_user(db_session):
    """Create a test user."""
    from app.models.user import User
    from app.core.crypto import PasswordHasher

    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=PasswordHasher.hash_password("Str0ngP@ssw0rd!", "testuser"),
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    yield user


@pytest.fixture(scope="function")
def admin_user(db_session):
    """Create a test admin user with admin role."""
    from app.models.user import User
    from app.models.role import Role
    from app.models.user_role import UserRole
    from app.core.crypto import PasswordHasher

    # Create admin role if it doesn't exist
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin", description="Administrator role")
        db_session.add(admin_role)
        db_session.commit()
        db_session.refresh(admin_role)

    # Create admin user
    user = User(
        username="adminuser",
        email="admin@example.com",
        password_hash=PasswordHasher.hash_password("Str0ngP@ssw0rd!", "adminuser"),
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Assign admin role
    user_role = UserRole(user_id=user.id, role_id=admin_role.id)
    db_session.add(user_role)
    db_session.commit()

    yield user


# ==================== OAUTH FIXTURES ====================

@pytest.fixture(scope="function")
def test_oauth_client(db_session):
    """Create a test OAuth2 client."""
    from app.models.oauth2_client import OAuth2Client

    client = OAuth2Client(
        client_id="test_client_id",
        client_secret="test_client_secret",
        name="Test OAuth Client",
        redirect_uris='["http://localhost:3000/callback"]',
        scopes='["openid", "profile", "email"]',
        is_active=True
    )

    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)

    yield client


# ==================== HELPER FIXTURES ====================

@pytest.fixture(scope="function")
def test_password():
    """Provide a valid test password that passes validation."""
    return "Str0ngP@ssw0rd!"


@pytest.fixture(scope="function")
def invalid_token():
    """Provide an invalid JWT token for testing."""
    return "invalid.jwt.token"


@pytest.fixture
def mock_email_service():
    """Create a mock email service for testing."""
    from unittest.mock import AsyncMock

    mock = AsyncMock()
    mock.send_password_reset_email.return_value = True
    mock.send_password_changed_notification.return_value = True

    return mock


# ==================== EVENT LOOP FIXTURE ====================

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()