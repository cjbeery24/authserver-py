"""
Pydantic schemas for OAuth 2.0 and OpenID Connect requests and responses.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, HttpUrl


class OAuth2ClientRegistrationRequest(BaseModel):
    """OAuth 2.0 Dynamic Client Registration request."""
    
    client_name: str = Field(..., description="Human-readable name of the client")
    redirect_uris: List[HttpUrl] = Field(..., description="Array of redirect URI strings")
    scopes: Optional[List[str]] = Field(None, description="Array of scope strings")
    grant_types: Optional[List[str]] = Field(None, description="Array of grant types")
    response_types: Optional[List[str]] = Field(None, description="Array of response types")
    token_endpoint_auth_method: Optional[str] = Field(
        "client_secret_basic", 
        description="Authentication method for token endpoint"
    )
    application_type: Optional[str] = Field("web", description="Application type")
    contacts: Optional[List[str]] = Field(None, description="Array of contact email addresses")
    logo_uri: Optional[HttpUrl] = Field(None, description="URL of client logo")
    client_uri: Optional[HttpUrl] = Field(None, description="URL of client home page")
    policy_uri: Optional[HttpUrl] = Field(None, description="URL of client privacy policy")
    tos_uri: Optional[HttpUrl] = Field(None, description="URL of client terms of service")


class OAuth2ClientRegistrationResponse(BaseModel):
    """OAuth 2.0 Dynamic Client Registration response."""
    
    client_id: str = Field(..., description="Client identifier")
    client_secret: str = Field(..., description="Client secret")
    client_name: str = Field(..., description="Human-readable name of the client")
    redirect_uris: List[str] = Field(..., description="Array of redirect URI strings")
    scopes: List[str] = Field(..., description="Array of scope strings")
    registration_access_token: str = Field(..., description="Access token for client management")
    registration_client_uri: str = Field(..., description="URI for client management")
    client_id_issued_at: Optional[int] = Field(None, description="Time when client ID was issued")
    client_secret_expires_at: Optional[int] = Field(0, description="Time when client secret expires")


class OAuth2ClientManagementResponse(BaseModel):
    """OAuth 2.0 client management response (for get/update operations)."""

    client_id: str = Field(..., description="Client identifier")
    client_name: str = Field(..., description="Human-readable name of the client")
    redirect_uris: List[str] = Field(..., description="Array of redirect URI strings")
    scopes: List[str] = Field(..., description="Array of scope strings")
    registration_client_uri: str = Field(..., description="URI for client management")
    client_id_issued_at: Optional[int] = Field(None, description="Time when client ID was issued")
    secret_last_rotated: Optional[datetime] = Field(None, description="Time when client secret was last rotated")
    is_active: bool = Field(True, description="Whether the client is active")


class OAuth2ClientListResponse(BaseModel):
    """OAuth 2.0 client list response."""

    clients: List[Dict[str, Any]] = Field(..., description="List of client information")


class AuthorizationRequest(BaseModel):
    """OAuth 2.0 authorization request parameters."""
    
    response_type: str = Field(..., description="Response type (typically 'code')")
    client_id: str = Field(..., description="Client identifier")
    redirect_uri: HttpUrl = Field(..., description="Redirect URI")
    scope: Optional[str] = Field(None, description="Requested scopes")
    state: Optional[str] = Field(None, description="State parameter for CSRF protection")
    code_challenge: Optional[str] = Field(None, description="PKCE code challenge")
    code_challenge_method: Optional[str] = Field(None, description="PKCE code challenge method")
    nonce: Optional[str] = Field(None, description="Nonce for ID token")


class AuthorizationResponse(BaseModel):
    """OAuth 2.0 authorization response."""
    
    code: Optional[str] = Field(None, description="Authorization code")
    state: Optional[str] = Field(None, description="State parameter")
    error: Optional[str] = Field(None, description="Error code")
    error_description: Optional[str] = Field(None, description="Error description")
    error_uri: Optional[str] = Field(None, description="Error URI")


class TokenRequest(BaseModel):
    """OAuth 2.0 token request parameters."""
    
    grant_type: str = Field(..., description="Grant type")
    client_id: Optional[str] = Field(None, description="Client identifier")
    client_secret: Optional[str] = Field(None, description="Client secret")
    code: Optional[str] = Field(None, description="Authorization code")
    redirect_uri: Optional[HttpUrl] = Field(None, description="Redirect URI")
    code_verifier: Optional[str] = Field(None, description="PKCE code verifier")
    username: Optional[str] = Field(None, description="Username (for password grant)")
    password: Optional[str] = Field(None, description="Password (for password grant)")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    scope: Optional[str] = Field(None, description="Requested scopes")


class TokenResponse(BaseModel):
    """OAuth 2.0 token response."""
    
    access_token: str = Field(..., description="Access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    scope: Optional[str] = Field(None, description="Granted scopes")
    id_token: Optional[str] = Field(None, description="OpenID Connect ID token")


class TokenIntrospectionResponse(BaseModel):
    """OAuth 2.0 token introspection response."""
    
    active: bool = Field(..., description="Whether the token is active")
    client_id: Optional[str] = Field(None, description="Client identifier")
    token_type: Optional[str] = Field(None, description="Token type")
    scope: Optional[str] = Field(None, description="Token scopes")
    sub: Optional[str] = Field(None, description="Subject identifier")
    exp: Optional[int] = Field(None, description="Token expiration time")
    iat: Optional[int] = Field(None, description="Token issued at time")
    nbf: Optional[int] = Field(None, description="Token not before time")
    aud: Optional[str] = Field(None, description="Token audience")
    iss: Optional[str] = Field(None, description="Token issuer")
    jti: Optional[str] = Field(None, description="JWT ID")


class TokenRevocationRequest(BaseModel):
    """OAuth 2.0 token revocation request."""
    
    token: str = Field(..., description="Token to revoke")
    token_type_hint: Optional[str] = Field(None, description="Token type hint")


class UserInfoResponse(BaseModel):
    """OpenID Connect UserInfo response."""
    
    sub: str = Field(..., description="Subject identifier")
    name: Optional[str] = Field(None, description="Full name")
    given_name: Optional[str] = Field(None, description="Given name")
    family_name: Optional[str] = Field(None, description="Family name")
    middle_name: Optional[str] = Field(None, description="Middle name")
    nickname: Optional[str] = Field(None, description="Nickname")
    preferred_username: Optional[str] = Field(None, description="Preferred username")
    profile: Optional[str] = Field(None, description="Profile page URL")
    picture: Optional[str] = Field(None, description="Profile picture URL")
    website: Optional[str] = Field(None, description="Website URL")
    email: Optional[str] = Field(None, description="Email address")
    email_verified: Optional[bool] = Field(None, description="Email verification status")
    gender: Optional[str] = Field(None, description="Gender")
    birthdate: Optional[str] = Field(None, description="Birth date")
    zoneinfo: Optional[str] = Field(None, description="Time zone")
    locale: Optional[str] = Field(None, description="Locale")
    phone_number: Optional[str] = Field(None, description="Phone number")
    phone_number_verified: Optional[bool] = Field(None, description="Phone verification status")
    address: Optional[Dict[str, Any]] = Field(None, description="Address information")
    updated_at: Optional[str] = Field(None, description="Last updated timestamp")


class JWKSResponse(BaseModel):
    """JSON Web Key Set response."""
    
    keys: List[Dict[str, Any]] = Field(..., description="Array of JSON Web Keys")


class ErrorResponse(BaseModel):
    """OAuth 2.0 error response."""
    
    error: str = Field(..., description="Error code")
    error_description: Optional[str] = Field(None, description="Error description")
    error_uri: Optional[str] = Field(None, description="Error URI")
    state: Optional[str] = Field(None, description="State parameter")


# Common OAuth 2.0 error codes
class OAuth2ErrorCodes:
    """OAuth 2.0 error codes."""
    
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
