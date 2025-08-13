"""
Health check API endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import time

from app.core.database import get_db
from app.core.redis import get_redis
from app.core.config import settings

router = APIRouter()

@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "timestamp": time.time()
    }

@router.get("/health/detailed")
async def detailed_health_check(
    db: Session = Depends(get_db)
):
    """Detailed health check with database and Redis connectivity."""
    health_status = {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "timestamp": time.time(),
        "checks": {
            "database": "unknown",
            "redis": "unknown"
        }
    }
    
    # Check database connectivity
    try:
        db.execute("SELECT 1")
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Check Redis connectivity
    try:
        redis_client = await get_redis()
        await redis_client.ping()
        health_status["checks"]["redis"] = "healthy"
    except Exception as e:
        health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "degraded"
    
    # Determine overall status
    if health_status["status"] == "degraded":
        raise HTTPException(status_code=503, detail=health_status)
    
    return health_status

@router.get("/health/ready")
async def readiness_check():
    """Readiness check for Kubernetes/load balancer health checks."""
    return {
        "status": "ready",
        "service": settings.app_name,
        "timestamp": time.time()
    }

@router.get("/health/live")
async def liveness_check():
    """Liveness check for Kubernetes health checks."""
    return {
        "status": "alive",
        "service": settings.app_name,
        "timestamp": time.time()
    }
