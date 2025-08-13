"""
Database connection and session management.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings

# Create declarative base for models
Base = declarative_base()

# Database URLs
DATABASE_URL = settings.database_url
ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Engine configurations
engine_kwargs = {
    "pool_size": settings.database_pool_size,
    "max_overflow": settings.database_max_overflow,
    "pool_timeout": settings.database_pool_timeout,
    "pool_recycle": settings.database_pool_recycle,
    "echo": settings.debug,  # Log SQL queries in debug mode
}

# Create sync engine
engine = create_engine(
    DATABASE_URL,
    **engine_kwargs
)

# Create async engine
async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    **engine_kwargs
)

# Session makers
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Test database setup
def get_test_database_url():
    """Get test database URL if configured."""
    if settings.test_database_url:
        return settings.test_database_url
    return DATABASE_URL.replace("/authserver", "/authserver_test")

def get_test_engine():
    """Get test database engine."""
    test_url = get_test_database_url()
    return create_engine(
        test_url,
        poolclass=StaticPool,  # Use static pool for testing
        echo=False
    )

# Dependency functions
def get_db():
    """Get database session for dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_async_db():
    """Get async database session for dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Database initialization
def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)

async def init_async_db():
    """Initialize database tables asynchronously."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def close_db():
    """Close database connections."""
    engine.dispose()
    async_engine.dispose()
