"""
Router registration utilities for FastAPI application.

This module provides a centralized way to register all API routers
across the application, used by both the main app and test fixtures.
"""

from fastapi import FastAPI

# Import all routers
from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router
from app.api.v1.oauth import router as oauth_router
from app.api.v1.security import router as security_router
from app.api.v1.mfa import router as mfa_router
from app.api.v1.users import router as users_router
from app.api.v1.admin import router as admin_router
from app.api.v1.well_known import router as well_known_router


def include_routers(app: FastAPI):
    """
    Include all API routers in the FastAPI application.

    This function centralizes router registration to ensure consistency
    between the main application and test fixtures.
    """
    app.include_router(health_router, prefix="/api/v1", tags=["health"])
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["authentication"])
    app.include_router(oauth_router, prefix="/oauth", tags=["oauth"])
    app.include_router(security_router, prefix="/api/v1/security", tags=["security"])
    app.include_router(mfa_router, prefix="/api/v1/mfa", tags=["mfa"])
    app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])
    app.include_router(well_known_router, prefix="/.well-known", tags=["well_known"])
