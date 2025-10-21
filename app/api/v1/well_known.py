"""
Well-known endpoints for OpenID Connect Discovery and JWKS.

These endpoints provide standard discovery information for OAuth 2.0 and OpenID Connect clients.
"""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status
import logging

from app.core.config import settings
from app.core.crypto import RSAKeyManager
from app.schemas.oauth import JWKSResponse

router = APIRouter()

# Logger
logger = logging.getLogger(__name__)


@router.get("/openid-configuration", response_model=Dict[str, Any])
async def openid_configuration():
    """
    OpenID Connect Discovery endpoint.

    Returns the OpenID Connect provider configuration.
    """
    return {
        "issuer": settings.oidc_issuer_url,
        "authorization_endpoint": settings.oidc_authorization_endpoint,
        "token_endpoint": settings.oidc_token_endpoint,
        "userinfo_endpoint": settings.oidc_userinfo_endpoint,
        "introspection_endpoint": settings.oidc_introspection_endpoint,
        "revocation_endpoint": settings.oidc_revocation_endpoint,
        "jwks_uri": settings.oidc_jwks_uri,
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "password"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],  # RS256 preferred, HS256 for backward compatibility
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "scopes_supported": settings.oauth2_supported_scopes,
        "code_challenge_methods_supported": ["S256", "plain"] if settings.pkce_required else [],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "username"
        ]
    }


@router.get("/jwks.json", response_model=JWKSResponse)
async def get_jwks():
    """
    JSON Web Key Set (JWKS) endpoint.

    Provides public keys for JWT signature verification.
    This allows consuming applications to verify JWT tokens
    without sharing secret keys.
    """
    try:
        jwks_data = RSAKeyManager.get_jwks()
        return JWKSResponse(**jwks_data)
    except ValueError as e:
        logger.error(f"JWKS generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWKS unavailable - server configuration error"
        )
    except Exception as e:
        logger.error(f"Unexpected error generating JWKS: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWKS unavailable"
        )
