"""
Security-focused API endpoints for token management and security validation.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
import logging

from app.core.database import get_db
from app.core.redis import get_redis_dependency
from app.core.security import TokenRotation, TokenBinding, TokenTransmissionSecurity
from app.middleware import get_current_user_or_401
from app.models.user import User
from app.schemas.base import BaseModel
from pydantic import Field

router = APIRouter()
logger = logging.getLogger(__name__)


class TokenSecurityValidationResponse(BaseModel):
    """Response model for token security validation."""
    
    is_secure: bool = Field(..., description="Overall security status")
    security_score: int = Field(..., description="Security score from 0-100")
    validation_results: Dict[str, bool] = Field(..., description="Individual validation results")
    recommendations: list[str] = Field(default_factory=list, description="Security recommendations")
    binding_status: Optional[Dict[str, Any]] = Field(None, description="Token binding status")


class TokenRotationRequest(BaseModel):
    """Request model for token rotation."""
    
    refresh_token: str = Field(..., description="Current refresh token to rotate")


class TokenRotationResponse(BaseModel):
    """Response model for token rotation."""
    
    access_token: str = Field(..., description="New access token")
    refresh_token: str = Field(..., description="New refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    rotated_at: str = Field(..., description="Rotation timestamp")


class SecurityAuditResponse(BaseModel):
    """Response model for security audit."""
    
    user_id: int = Field(..., description="User ID")
    active_tokens: int = Field(..., description="Number of active tokens")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")
    security_events: list[Dict[str, Any]] = Field(default_factory=list, description="Recent security events")
    risk_score: int = Field(..., description="Risk score from 0-100")


@router.post("/validate-transmission", response_model=TokenSecurityValidationResponse)
async def validate_token_transmission_security(
    request: Request,
    current_user: User = Depends(get_current_user_or_401)
):
    """
    Validate the security of current token transmission.
    
    Analyzes various security aspects of the current request and token
    to provide a comprehensive security assessment.
    """
    try:
        # Get transmission security validation
        validation_results = TokenTransmissionSecurity.validate_token_transmission_security(request)
        
        # Calculate security score
        security_score = _calculate_security_score(validation_results, request)
        
        # Generate recommendations
        recommendations = _generate_security_recommendations(validation_results, request)
        
        # Check token binding if enabled
        binding_status = None
        if hasattr(request.state, 'token_data') and request.state.token_data:
            binding_status = {
                "enabled": True,
                "client_fingerprint": TokenTransmissionSecurity.get_client_fingerprint(request),
                "status": "active"
            }
        
        return TokenSecurityValidationResponse(
            is_secure=security_score >= 80,
            security_score=security_score,
            validation_results=validation_results,
            recommendations=recommendations,
            binding_status=binding_status
        )
        
    except Exception as e:
        logger.error(f"Token security validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security validation failed"
        )


@router.post("/rotate-token", response_model=TokenRotationResponse)
async def rotate_user_token(
    request: Request,
    rotation_request: TokenRotationRequest,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Rotate a user's refresh token for enhanced security.
    
    This endpoint provides secure token rotation, invalidating the old
    refresh token and issuing new access and refresh tokens.
    """
    try:
        # Perform token rotation
        new_tokens = await TokenRotation.rotate_refresh_token(
            old_refresh_token=rotation_request.refresh_token,
            user_id=current_user.id,
            db_session=db,
            redis_client=redis_client,
            request=request
        )
        
        if not new_tokens:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token rotation failed"
            )
        
        logger.info(f"Token rotated successfully for user {current_user.id}")
        
        return TokenRotationResponse(
            access_token=new_tokens["access_token"],
            refresh_token=new_tokens["refresh_token"],
            token_type=new_tokens["token_type"],
            expires_in=new_tokens["expires_in"],
            rotated_at=new_tokens.get("issued_at", "")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token rotation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token rotation failed"
        )


@router.post("/revoke-all-tokens")
async def revoke_all_user_tokens(
    request: Request,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db),
    redis_client = Depends(get_redis_dependency)
):
    """
    Revoke all tokens for the current user.
    
    This is useful for security incidents or when a user wants to
    log out from all devices.
    """
    try:
        # Revoke all tokens for the user
        revoked_count = await TokenRotation.revoke_all_user_tokens(
            user_id=current_user.id,
            db_session=db,
            redis_client=redis_client,
            reason="user_requested_revocation"
        )
        
        logger.info(f"Revoked all tokens for user {current_user.id}: {revoked_count} tokens")
        
        return {
            "message": f"Successfully revoked {revoked_count} tokens",
            "revoked_count": revoked_count,
            "user_id": current_user.id
        }
        
    except Exception as e:
        logger.error(f"Token revocation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token revocation failed"
        )


@router.get("/audit", response_model=SecurityAuditResponse)
async def get_user_security_audit(
    request: Request,
    current_user: User = Depends(get_current_user_or_401),
    db: Session = Depends(get_db)
):
    """
    Get security audit information for the current user.
    
    Provides an overview of the user's security status, active tokens,
    and recent security events.
    """
    try:
        from app.models.user_token import UserToken
        from app.models.audit_log import AuditLog
        from datetime import datetime, timezone, timedelta
        
        # Count active tokens
        active_tokens = db.query(UserToken).filter(
            UserToken.user_id == current_user.id,
            UserToken.is_revoked == False,
            UserToken.expires_at > datetime.now(timezone.utc)
        ).count()
        
        # Get recent audit logs
        recent_logs = db.query(AuditLog).filter(
            AuditLog.user_id == current_user.id,
            AuditLog.created_at > datetime.now(timezone.utc) - timedelta(days=30)
        ).order_by(AuditLog.created_at.desc()).limit(10).all()
        
        # Convert audit logs to security events
        security_events = []
        for log in recent_logs:
            security_events.append({
                "action": log.action,
                "resource": log.resource,
                "timestamp": log.created_at.isoformat(),
                "ip_address": log.ip_address,
                "user_agent": log.user_agent
            })
        
        # Calculate risk score based on various factors
        risk_score = _calculate_user_risk_score(current_user, active_tokens, security_events)
        
        # Get last activity
        last_activity = None
        if recent_logs:
            last_activity = recent_logs[0].created_at.isoformat()
        
        return SecurityAuditResponse(
            user_id=current_user.id,
            active_tokens=active_tokens,
            last_activity=last_activity,
            security_events=security_events,
            risk_score=risk_score
        )
        
    except Exception as e:
        logger.error(f"Security audit error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security audit failed"
        )


def _calculate_security_score(validation_results: Dict[str, bool], request: Request) -> int:
    """Calculate overall security score based on validation results."""
    score = 0
    max_score = 100
    
    # HTTPS check (30 points)
    if validation_results.get("is_https", False):
        score += 30
    
    # Secure context (20 points)
    if validation_results.get("is_secure_context", False):
        score += 20
    
    # Valid content type (15 points)
    if validation_results.get("content_type_valid", False):
        score += 15
    
    # User agent present (10 points)
    if validation_results.get("has_user_agent", False):
        score += 10
    
    # Origin header present (10 points)
    if validation_results.get("has_origin", False):
        score += 10
    
    # Referer header present (10 points)
    if validation_results.get("has_referer", False):
        score += 10
    
    # Additional security headers check (5 points)
    security_headers = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]
    if any(header in request.headers for header in security_headers):
        score += 5
    
    return min(score, max_score)


def _generate_security_recommendations(validation_results: Dict[str, bool], request: Request) -> list[str]:
    """Generate security recommendations based on validation results."""
    recommendations = []
    
    if not validation_results.get("is_https", False):
        recommendations.append("Use HTTPS for all token transmission")
    
    if not validation_results.get("has_user_agent", False):
        recommendations.append("Include proper User-Agent header in requests")
    
    if not validation_results.get("has_origin", False):
        recommendations.append("Include Origin header for CORS validation")
    
    if not validation_results.get("content_type_valid", False):
        recommendations.append("Use valid Content-Type headers (application/json, application/x-www-form-urlencoded)")
    
    if not validation_results.get("is_secure_context", False):
        recommendations.append("Ensure requests are made from secure context (HTTPS environment)")
    
    # Add general recommendations
    recommendations.append("Regularly rotate refresh tokens")
    recommendations.append("Enable token binding for enhanced security")
    recommendations.append("Monitor for unusual access patterns")
    
    return recommendations


def _calculate_user_risk_score(user: User, active_tokens: int, security_events: list) -> int:
    """Calculate risk score for a user based on various factors."""
    risk_score = 0
    
    # Base risk (10 points)
    risk_score += 10
    
    # Active tokens risk (more tokens = higher risk)
    if active_tokens > 10:
        risk_score += 20
    elif active_tokens > 5:
        risk_score += 10
    
    # Recent security events risk
    failed_attempts = sum(1 for event in security_events if "failed" in event.get("action", "").lower())
    if failed_attempts > 5:
        risk_score += 30
    elif failed_attempts > 2:
        risk_score += 15
    
    # Account age (newer accounts have slightly higher risk)
    from datetime import datetime, timezone, timedelta
    if user.created_at > datetime.now(timezone.utc) - timedelta(days=7):
        risk_score += 10
    
    # Different IP addresses in recent events
    unique_ips = set(event.get("ip_address", "") for event in security_events if event.get("ip_address"))
    if len(unique_ips) > 5:
        risk_score += 15
    elif len(unique_ips) > 3:
        risk_score += 10
    
    return min(risk_score, 100)

