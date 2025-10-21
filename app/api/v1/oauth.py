"""
OAuth 2.0 and OpenID Connect API endpoints.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError
from authlib.oauth2.rfc6749.errors import (
    InvalidClientError, InvalidRequestError, InvalidScopeError,
    InvalidGrantError, UnsupportedGrantTypeError, AccessDeniedError
)
from authlib.jose.errors import JoseError, InvalidClaimError
from authlib.common.security import generate_token
from jose import jwt, JWTError
import logging
from urllib.parse import urlencode, urlparse

from app.core.database import get_db
from app.core.oauth import (
    create_authorization_server,
    generate_client_credentials
)
from app.core.redis import get_redis_dependency
from app.core.config import settings
from app.core.rbac import PermissionChecker
from app.models.oauth2_client import OAuth2Client
from app.models.oauth2_client_token import OAuth2ClientToken
from app.models.user import User
from app.middleware import get_current_user_or_401
from app.schemas.oauth import (
    OAuth2ClientRegistrationRequest,
    OAuth2ClientRegistrationResponse,
    OAuth2ClientManagementResponse,
    OAuth2ClientListResponse,
    TokenIntrospectionResponse
)

router = APIRouter()

# Logger
logger = logging.getLogger(__name__)

# Security scheme for token introspection and revocation
token_scheme = HTTPBearer(auto_error=False)


async def _require_admin(current_user: User = Depends(get_current_user_or_401), db: Session = Depends(get_db)) -> User:
    """
    Dependency to require admin role.

    Checks if the user has the 'admin' role or 'admin:access' permission.
    """
    # Check if user has admin role or admin:access permission
    has_admin_role = await PermissionChecker.has_role(current_user.id, "admin", db)
    has_admin_permission = await PermissionChecker.has_permission(current_user.id, "admin", "access", db)

    if not (has_admin_role or has_admin_permission):
        logger.warning(
            f"Unauthorized OAuth client registration attempt by user {current_user.id} ({current_user.username})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: admin role or admin:access permission required"
        )

    return current_user


class OAuth2Error(Exception):
    """Base OAuth2 error class."""

    def __init__(self, error: str, error_description: str = None, error_uri: str = None, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        self.status_code = status_code
        super().__init__(error_description or error)


def create_oauth2_error_response(error: OAuth2Error) -> JSONResponse:
    """Create OAuth2 error response following RFC 6749."""
    response_data = {
        "error": error.error,
        "error_description": error.error_description
    }
    if error.error_uri:
        response_data["error_uri"] = error.error_uri

    return JSONResponse(
        status_code=error.status_code,
        content=response_data
    )


def validate_redirect_uri_security(redirect_uri) -> None:
    """
    Validate redirect URI for security vulnerabilities.

    Enforces HTTPS requirement and blocks malicious schemes.
    Accepts either string or Pydantic HttpUrl objects.
    """
    # Convert HttpUrl to string if necessary
    if hasattr(redirect_uri, '__str__'):
        redirect_uri_str = str(redirect_uri)
    else:
        redirect_uri_str = redirect_uri
        
    try:
        parsed = urlparse(redirect_uri_str)
    except Exception:
        raise OAuth2Error("invalid_request", "Invalid redirect_uri format")

    # Block malicious schemes
    malicious_schemes = {
        'javascript', 'data', 'vbscript', 'file', 'ftp',
        'blob', 'filesystem', 'chrome', 'chrome-extension',
        'moz-extension', 'safari-extension'
    }

    if parsed.scheme.lower() in malicious_schemes:
        raise OAuth2Error("invalid_request", f"Redirect URI scheme '{parsed.scheme}' is not allowed")

    # Enforce HTTPS unless in development mode
    if not settings.debug and parsed.scheme.lower() != 'https':
        raise OAuth2Error("invalid_request", "Redirect URI must use HTTPS in production")

    # Allow HTTP only in development mode and for localhost
    if settings.debug and parsed.scheme.lower() == 'http':
        # Allow localhost and common development hosts
        allowed_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}
        if parsed.hostname not in allowed_hosts and not parsed.hostname.endswith('.local'):
            raise OAuth2Error("invalid_request", "HTTP redirect URIs are only allowed for localhost in development")

    # Ensure the URI has a proper host
    if not parsed.hostname:
        raise OAuth2Error("invalid_request", "Redirect URI must include a valid hostname")

    # Additional security checks for hostname and URL structure
    hostname = parsed.hostname.lower()

    # Block URLs with authentication credentials (username/password)
    if parsed.username or parsed.password:
        raise OAuth2Error("invalid_request", "Redirect URI must not contain authentication credentials")

    # Block hostnames with suspicious characters or patterns
    if '@' in hostname or '\\' in hostname:
        raise OAuth2Error("invalid_request", "Redirect URI hostname contains invalid characters")

    # Block localhost/private IPs in production (additional check)
    if not settings.debug:
        private_ranges = ['127.', '10.', '172.', '192.168.', '169.254.', '::1', 'fc00:', 'fe80:']
        if any(hostname.startswith(prefix) for prefix in private_ranges):
            raise OAuth2Error("invalid_request", "Private/localhost addresses not allowed in production")

    # Basic hostname format validation
    import re
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', hostname):
        raise OAuth2Error("invalid_request", "Invalid hostname format")


def validate_oauth2_scopes(requested_scopes: str = None, client_scopes: list = None) -> str:
    """
    Validate OAuth2 scopes against global settings and client permissions.

    Args:
        requested_scopes: Space-separated string of requested scopes
        client_scopes: List of scopes the client is allowed to request

    Returns:
        Validated scope string

    Raises:
        OAuth2Error: If scopes are invalid
    """
    # Parse requested scopes
    if requested_scopes:
        requested_scope_list = set(requested_scopes.split())
    else:
        requested_scope_list = set()

    # If no scopes requested, use default scopes
    if not requested_scope_list:
        requested_scope_list = set(settings.oauth2_default_scopes)

    # Validate against globally supported scopes
    supported_scopes = set(settings.oauth2_supported_scopes)
    invalid_scopes = requested_scope_list - supported_scopes
    if invalid_scopes:
        raise OAuth2Error("invalid_scope", f"Unsupported scopes: {', '.join(sorted(invalid_scopes))}")

    # Validate against client-allowed scopes (if client scopes provided)
    if client_scopes:
        client_scope_set = set(client_scopes)
        unauthorized_scopes = requested_scope_list - client_scope_set
        if unauthorized_scopes:
            raise OAuth2Error("invalid_scope", f"Client not authorized for scopes: {', '.join(sorted(unauthorized_scopes))}")

    # Return validated scope string
    return ' '.join(sorted(requested_scope_list))


def handle_oauth2_exceptions(func):
    """Decorator for handling OAuth2-specific exceptions."""
    from functools import wraps
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except OAuth2Error as e:
            logger.warning(f"OAuth2 error in {func.__name__}: {e.error} - {e.error_description}")
            return create_oauth2_error_response(e)
        except InvalidClientError as e:
            logger.warning(f"Invalid client error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_client", "Client authentication failed", status_code=401)
            )
        except InvalidRequestError as e:
            logger.warning(f"Invalid request error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_request", str(e))
            )
        except InvalidScopeError as e:
            logger.warning(f"Invalid scope error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_scope", str(e))
            )
        except InvalidGrantError as e:
            logger.warning(f"Invalid grant error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_grant", str(e))
            )
        except UnsupportedGrantTypeError as e:
            logger.warning(f"Unsupported grant type error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("unsupported_grant_type", str(e))
            )
        except AccessDeniedError as e:
            logger.warning(f"Access denied error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("access_denied", str(e), status_code=403)
            )
        except JoseError as e:
            logger.warning(f"JWT/JOSE error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_request", "Invalid token format", status_code=400)
            )
        except InvalidClaimError as e:
            logger.warning(f"Invalid claim error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("invalid_request", "Invalid token claims", status_code=400)
            )
        except OperationalError as e:
            logger.error(f"Database connection error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("temporarily_unavailable", "Database temporarily unavailable", status_code=503)
            )
        except IntegrityError as e:
            logger.error(f"Database integrity error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("server_error", "Database constraint violation", status_code=500)
            )
        except SQLAlchemyError as e:
            logger.error(f"Database error in {func.__name__}: {str(e)}")
            return create_oauth2_error_response(
                OAuth2Error("server_error", "Database error occurred", status_code=500)
            )
        except HTTPException:
            # Re-raise HTTP exceptions as they are already properly formatted
            raise
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}", exc_info=True)
            return create_oauth2_error_response(
                OAuth2Error("server_error", "Internal server error", status_code=500)
            )

    return wrapper



@router.get("/authorize", response_class=RedirectResponse)
async def authorize(
    request: Request,
    response_type: str = None,
    client_id: str = None,
    redirect_uri: str = None,
    scope: str = None,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    nonce: str = None,
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Authorization endpoint.

    Initiates the authorization code flow with CSRF protection.
    """
    # Validate required parameters
    if not response_type:
        raise OAuth2Error("invalid_request", "Missing response_type parameter")

    if not client_id:
        raise OAuth2Error("invalid_request", "Missing client_id parameter")

    if not redirect_uri:
        raise OAuth2Error("invalid_request", "Missing redirect_uri parameter")

    # Only support authorization code flow for now
    if response_type != "code":
        raise OAuth2Error("unsupported_response_type", "Only 'code' response_type is supported")

    # Validate client
    try:
        client = db.query(OAuth2Client).filter(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active == True
        ).first()

        if not client:
            raise OAuth2Error("invalid_client", "Invalid client_id")

        # Validate redirect URI
        if redirect_uri not in client.get_redirect_uris():
            raise OAuth2Error("invalid_request", "Invalid redirect_uri")
    except OAuth2Error as e:
        return create_oauth2_error_response(e)

    # Additional security validation for redirect URI
    validate_redirect_uri_security(redirect_uri)

    # Validate and normalize scopes
    try:
        validated_scope = validate_oauth2_scopes(scope, client.get_scopes())
    except OAuth2Error as e:
        return create_oauth2_error_response(e)

    # Check if PKCE is required
    if settings.pkce_required and not code_challenge:
        raise OAuth2Error("invalid_request", "code_challenge is required")

    if code_challenge and code_challenge_method not in ["S256", "plain"]:
        raise OAuth2Error("invalid_request", "code_challenge_method must be S256 or plain")

    # Generate CSRF protection token for the authorization request
    csrf_token = generate_authorization_csrf_token(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=validated_scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce
    )

    # Store authorization request details with CSRF token
    # In a production system, this would be stored in Redis/cache with expiration
    # For now, we'll embed the information in the CSRF token itself (JWT)

    # Redirect to login page with authorization request details and CSRF token
    login_url = f"{settings.frontend_url}/login"
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": validated_scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
        "csrf_token": csrf_token  # CSRF protection token
    }

    # Filter out None values
    params = {k: v for k, v in params.items() if v is not None}

    query_string = "&".join([f"{k}={v}" for k, v in params.items()])

    return RedirectResponse(url=f"{login_url}?{query_string}")


def generate_authorization_csrf_token(
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    nonce: str = None
) -> str:
    """
    Generate a CSRF protection token for authorization requests.

    This token contains the authorization request parameters and is signed
    to prevent tampering. It will be validated when the user completes login.
    """
    from datetime import datetime, timezone, timedelta

    # Create token payload with authorization request details
    payload = {
        "type": "authorization_csrf",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),  # 30 minute expiry
        "iat": datetime.now(timezone.utc),
        "nbf": datetime.now(timezone.utc)
    }

    # Add optional parameters
    if state:
        payload["state"] = state
    if code_challenge:
        payload["code_challenge"] = code_challenge
    if code_challenge_method:
        payload["code_challenge_method"] = code_challenge_method
    if nonce:
        payload["nonce"] = nonce

    # Sign the token
    from app.core.crypto import RSAKeyManager
    signing_key = RSAKeyManager.get_signing_key()
    token = jwt.encode(payload, signing_key, algorithm=settings.jwt_algorithm)
    return token


def validate_authorization_csrf_token(csrf_token: str) -> dict:
    """
    Validate CSRF token and return authorization request details.

    Raises OAuth2Error if token is invalid or expired.
    """
    try:
        # Decode and verify token
        from app.core.crypto import RSAKeyManager
        verification_key = RSAKeyManager.get_verification_key()
        payload = jwt.decode(
            csrf_token,
            verification_key,
            algorithms=[settings.jwt_algorithm]
        )

        # Validate token type
        if payload.get("type") != "authorization_csrf":
            raise OAuth2Error("invalid_request", "Invalid CSRF token type")

        return payload

    except JWTError as e:
        if "expired" in str(e).lower():
            raise OAuth2Error("invalid_request", "CSRF token has expired")
        elif "signature" in str(e).lower():
            raise OAuth2Error("invalid_request", "Invalid CSRF token signature")
        else:
            raise OAuth2Error("invalid_request", f"Invalid CSRF token: {str(e)}")


@router.post("/authorize/complete", response_model=Dict[str, Any],
            dependencies=[Depends(RateLimiter(times=30, minutes=1))])
@handle_oauth2_exceptions
async def complete_authorization(
    request: Request,
    csrf_token: str = Form(...),
    user_id: int = Form(...),  # Would come from authenticated user session
    consent_given: bool = Form(True),  # User consent for the authorization
    db: Session = Depends(get_db)
):
    """
    Complete authorization after user login and consent.

    This endpoint is called by the frontend after user authentication
    to issue an authorization code.
    """
    # Validate CSRF token and get authorization request details
    try:
        auth_details = validate_authorization_csrf_token(csrf_token)
    except OAuth2Error as e:
        return create_oauth2_error_response(e)

    # Validate user exists and is active
    user = db.query(User).filter(
        User.id == user_id,
        User.is_active == True
    ).first()

    if not user:
        raise OAuth2Error("access_denied", "User not found or inactive")

    # Validate client (double-check)
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == auth_details["client_id"],
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise OAuth2Error("invalid_client", "Client not found or inactive")

    # Check user consent
    if not consent_given:
        raise OAuth2Error("access_denied", "User denied authorization request")

    # Create authorization server and generate authorization code
    server = create_authorization_server(db)

    # Create mock request object with authorization details
    mock_request = type('MockRequest', (), {
        'client': type('MockClient', (), {
            'client_id': auth_details["client_id"],
            'get_client_id': lambda: auth_details["client_id"]
        })(),
        'user': user,
        'redirect_uri': auth_details["redirect_uri"],
        'scope': auth_details["scope"],
        'code_challenge': auth_details.get("code_challenge"),
        'code_challenge_method': auth_details.get("code_challenge_method"),
        'nonce': auth_details.get("nonce")
    })()

    # Generate authorization code
    code = generate_token(48)  # Generate secure code

    # Save authorization code
    server.validator.save_authorization_code(
        auth_details["client_id"],
        code,
        mock_request
    )

    # Build redirect URI with authorization code
    redirect_params = {
        "code": code,
        "state": auth_details.get("state")
    }

    # Filter out None values
    redirect_params = {k: v for k, v in redirect_params.items() if v is not None}

    redirect_uri = auth_details["redirect_uri"] + "?" + urlencode(redirect_params)

    return {
        "redirect_uri": redirect_uri,
        "success": True
    }


@router.post("/token",
            dependencies=[Depends(RateLimiter(times=60, minutes=1))],
            response_model=Dict[str, Any])
@handle_oauth2_exceptions
async def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    code_verifier: str = Form(None),
    username: str = Form(None),
    password: str = Form(None),
    refresh_token: str = Form(None),
    scope: str = Form(None),
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Token endpoint.
    
    Issues access tokens for various grant types.
    """
    # Create authorization server
    server = create_authorization_server(db)

    # Handle different grant types
    if grant_type == "authorization_code":
        return await _handle_authorization_code_grant(
            server, client_id, client_secret, code, redirect_uri,
            code_verifier, db
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token_grant(
            server, client_id, client_secret, refresh_token, scope, db
        )
    elif grant_type == "client_credentials":
        return await _handle_client_credentials_grant(
            server, client_id, client_secret, scope, db
        )
    elif grant_type == "password":
        return await _handle_password_grant(
            server, client_id, client_secret, username, password, scope, db
        )
    else:
        raise OAuth2Error("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")


async def _handle_authorization_code_grant(
    server, client_id: str, client_secret: str, code: str,
    redirect_uri: str, code_verifier: str, db: Session
) -> Dict[str, Any]:
    """Handle authorization code grant."""
    # Validate client credentials
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Validate authorization code
    auth_code = server.validator.get_authorization_code(client_id, code)
    if not auth_code:
        raise OAuth2Error("invalid_grant", "Invalid or expired authorization code")

    # Validate redirect URI
    if auth_code.redirect_uri != redirect_uri:
        raise OAuth2Error("invalid_request", "Invalid redirect_uri")

    # Additional security validation for redirect URI (defense in depth)
    validate_redirect_uri_security(redirect_uri)

    # Validate PKCE if required
    if settings.pkce_required and auth_code.code_challenge:
        if not _validate_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
            raise OAuth2Error("invalid_request", "Invalid code_verifier")

    # Validate and normalize scopes
    validated_scope = validate_oauth2_scopes(auth_code.scope, client.get_scopes())

    # Generate tokens with nonce support for ID tokens
    tokens = await server.create_token_response(
        client_id=client_id,
        grant_type="authorization_code",
        user_id=auth_code.user_id,
        scope=validated_scope,
        nonce=getattr(auth_code, 'nonce', None),
        auth_time=datetime.now(timezone.utc)  # User just authenticated via auth code
    )

    # Delete used authorization code
    server.validator.delete_authorization_code(client_id, code)

    return tokens


async def _handle_refresh_token_grant(
    server, client_id: str, client_secret: str, refresh_token: str,
    scope: str, db: Session
) -> Dict[str, Any]:
    """Handle refresh token grant."""
    # Validate client credentials
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Validate refresh token
    token_info = server.validator.authenticate_refresh_token(refresh_token)
    if not token_info:
        raise OAuth2Error("invalid_grant", "Invalid or expired refresh token")

    # Determine the scope to use (requested scope or original token scope)
    requested_scope = scope or token_info.get('scope', '')

    # Validate and normalize scopes
    # For refresh tokens, we validate against the original token scope and client scopes
    original_scope = token_info.get('scope', '')
    if original_scope:
        # Client must be authorized for the original scope and any additional requested scopes
        validated_scope = validate_oauth2_scopes(requested_scope, client.get_scopes())
        # Ensure the new scope is not broader than the original scope
        original_scope_set = set(original_scope.split())
        requested_scope_set = set(validated_scope.split())
        if not requested_scope_set.issubset(original_scope_set):
            raise OAuth2Error("invalid_scope", "Cannot request broader scope than original token")
    else:
        # No original scope restriction, validate normally
        validated_scope = validate_oauth2_scopes(requested_scope, client.get_scopes())

    # Generate new tokens
    tokens = await server.create_token_response(
        client_id=client_id,
        grant_type="refresh_token",
        user_id=token_info.get('user').id if token_info.get('user') else None,
        scope=validated_scope,
        # No nonce for refresh tokens (nonce is only for initial auth)
        # No specific auth_time - tokens were already issued
    )

    return tokens


async def _handle_client_credentials_grant(
    server, client_id: str, client_secret: str, scope: str, db: Session
) -> Dict[str, Any]:
    """Handle client credentials grant."""
    # Validate client credentials
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Validate and normalize scopes
    validated_scope = validate_oauth2_scopes(scope, client.get_scopes())

    # Generate tokens (no user associated with client credentials)
    tokens = await server.create_token_response(
        client_id=client_id,
        grant_type="client_credentials",
        user_id=None,
        scope=validated_scope
        # No nonce or auth_time for client credentials (no user authentication)
    )

    return tokens


async def _handle_password_grant(
    server, client_id: str, client_secret: str, username: str,
    password: str, scope: str, db: Session
) -> Dict[str, Any]:
    """Handle resource owner password credentials grant."""
    # Validate client credentials
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Authenticate user
    user = server.validator.authenticate_user(username, password, client, None)
    if not user:
        raise OAuth2Error("invalid_grant", "Invalid username or password")

    # Validate and normalize scopes
    validated_scope = validate_oauth2_scopes(scope, client.get_scopes())

    # Generate tokens
    tokens = await server.create_token_response(
        client_id=client_id,
        grant_type="password",
        user_id=user.id,
        scope=validated_scope,
        # No nonce for password grant (direct authentication)
        auth_time=datetime.now(timezone.utc)  # User just authenticated via password
    )

    return tokens


def _validate_pkce(code_verifier: str, code_challenge: str, code_challenge_method: str) -> bool:
    """Validate PKCE code verifier against code challenge."""
    import hashlib
    import base64
    
    if code_challenge_method == "S256":
        # SHA256 hash of code_verifier, base64url encoded
        sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        expected_challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')
        return expected_challenge == code_challenge
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    
    return False


@router.get("/userinfo", 
            response_model=Dict[str, Any],
            dependencies=[Depends(RateLimiter(times=60, minutes=1))])
@handle_oauth2_exceptions
async def userinfo(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(token_scheme),
    db: Session = Depends(get_db)
):
    """
    OpenID Connect UserInfo endpoint (RFC 7662).

    Returns user claims based on the scopes granted with the access token.
    
    Standard scopes:
    - openid: Required, returns 'sub' claim
    - profile: Returns profile claims (name, preferred_username, updated_at, etc.)
    - email: Returns email and email_verified claims
    - address: Returns address claim
    - phone: Returns phone_number and phone_number_verified claims
    
    Requires a valid OAuth2 access token with 'openid' scope.
    """
    # Check if credentials were provided
    if not credentials:
        raise OAuth2Error(
            "invalid_request",
            "Missing authentication token",
            status_code=401
        )

    # Extract token
    access_token = credentials.credentials
    
    # Get Redis client for blacklist checking
    from app.core.redis import get_redis_dependency
    redis_client = await get_redis_dependency()
    
    # Validate token using TokenManager
    from app.core.token import TokenManager
    payload = await TokenManager.verify_token(access_token, "access", redis_client)
    
    if not payload:
        raise OAuth2Error(
            "invalid_token",
            "Invalid or expired access token",
            status_code=401
        )
    
    # Extract scopes from token
    token_scope = payload.get("scope", "")
    if isinstance(token_scope, str):
        scopes = set(token_scope.split())
    elif isinstance(token_scope, list):
        scopes = set(token_scope)
    else:
        scopes = set()
    
    # OpenID Connect requires 'openid' scope for UserInfo endpoint
    if "openid" not in scopes:
        raise OAuth2Error(
            "insufficient_scope",
            "The access token does not have the required 'openid' scope",
            status_code=403
        )
    
    # Get user information
    user_id = payload.get("sub")
    if not user_id:
        raise OAuth2Error(
            "invalid_token",
            "Token does not contain user identifier",
            status_code=400
        )
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise OAuth2Error(
            "invalid_token",
            "User not found or inactive",
            status_code=404
        )
    
    # Build userinfo response based on granted scopes
    userinfo_data = _build_userinfo_claims(user, scopes)
    
    logger.info(f"UserInfo request successful for user {user.id} with scopes: {', '.join(scopes)}")
    
    return userinfo_data


def _build_userinfo_claims(user: User, scopes: set) -> Dict[str, Any]:
    """
    Build UserInfo claims based on granted scopes.
    
    Args:
        user: User object
        scopes: Set of granted scopes
        
    Returns:
        Dictionary of claims to return
    """
    # Always include 'sub' claim (required by OpenID Connect)
    claims = {
        "sub": str(user.id)
    }
    
    # Profile scope claims
    if "profile" in scopes:
        # Preferred username
        if user.username:
            claims["preferred_username"] = user.username
            claims["name"] = user.username  # Use username as name if no separate name field
        
        # Updated_at timestamp (when profile was last updated)
        if user.updated_at:
            claims["updated_at"] = int(user.updated_at.timestamp())
        elif user.created_at:
            claims["updated_at"] = int(user.created_at.timestamp())
        
        # Add additional profile fields if available
        # These can be extended based on your User model
        # Examples: given_name, family_name, middle_name, nickname, 
        # profile (URL), picture (URL), website, gender, birthdate, 
        # zoneinfo, locale
    
    # Email scope claims
    if "email" in scopes:
        if user.email:
            claims["email"] = user.email
            # You can implement email verification in your system
            # For now, we'll assume verified if email exists
            claims["email_verified"] = True
    
    # Address scope claims
    if "address" in scopes:
        # If your User model has address fields, add them here
        # The address claim should be a JSON object with these optional fields:
        # formatted, street_address, locality, region, postal_code, country
        # Example:
        # if hasattr(user, 'address'):
        #     claims["address"] = {
        #         "formatted": user.address,
        #         "country": user.country
        #     }
        pass
    
    # Phone scope claims
    if "phone" in scopes:
        # If your User model has phone fields, add them here
        # Example:
        # if hasattr(user, 'phone_number') and user.phone_number:
        #     claims["phone_number"] = user.phone_number
        #     claims["phone_number_verified"] = user.phone_verified
        pass
    
    return claims


@router.post("/introspect",
            dependencies=[Depends(RateLimiter(times=30, minutes=1))],
            response_model=TokenIntrospectionResponse)
@handle_oauth2_exceptions
async def introspect_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: str = Form(None),
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Token Introspection endpoint.
    
    Returns information about the provided token.
    Requires client authentication via Authorization header (Bearer or Basic).
    """
    # Extract client credentials from Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header:
        raise OAuth2Error("invalid_client", "Missing Authorization header", status_code=401)
    
    try:
        import base64
        # Support both "Bearer <base64>" and "Basic <base64>" formats
        if auth_header.startswith("Bearer ") or auth_header.startswith("Basic "):
            encoded_creds = auth_header.split(" ", 1)[1]
        else:
            raise OAuth2Error("invalid_client", "Invalid Authorization header format", status_code=401)
            
        decoded = base64.b64decode(encoded_creds).decode('utf-8')
        client_id, client_secret = decoded.split(':', 1)
    except Exception as e:
        logger.warning(f"Failed to parse client credentials: {str(e)}")
        raise OAuth2Error("invalid_client", "Invalid client credentials", status_code=401)

    # Find and verify client
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Create authorization server for token introspection
    server = create_authorization_server(db)

    # Introspect token - pass the authenticated client
    token_info = server.validator.introspect_token(token, token_type_hint, client)

    if not token_info:
        return TokenIntrospectionResponse(active=False)

    return TokenIntrospectionResponse(**token_info)


@router.post("/revoke",
            dependencies=[Depends(RateLimiter(times=30, minutes=1))])
@handle_oauth2_exceptions
async def revoke_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: str = Form(None),
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Token Revocation endpoint.
    
    Revokes the provided token.
    Requires client authentication via Authorization header (Bearer or Basic).
    """
    # Extract client credentials from Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header:
        raise OAuth2Error("invalid_client", "Missing Authorization header", status_code=401)
    
    try:
        import base64
        # Support both "Bearer <base64>" and "Basic <base64>" formats
        if auth_header.startswith("Bearer ") or auth_header.startswith("Basic "):
            encoded_creds = auth_header.split(" ", 1)[1]
        else:
            raise OAuth2Error("invalid_client", "Invalid Authorization header format", status_code=401)
            
        decoded = base64.b64decode(encoded_creds).decode('utf-8')
        client_id, client_secret = decoded.split(':', 1)
    except Exception as e:
        logger.warning(f"Failed to parse client credentials: {str(e)}")
        raise OAuth2Error("invalid_client", "Invalid client credentials", status_code=401)

    # Find and verify client
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client or not client.verify_client_secret(client_secret):
        raise OAuth2Error("invalid_client", "Client authentication failed", status_code=401)

    # Create authorization server for token revocation
    server = create_authorization_server(db)

    # Revoke token - pass the authenticated client
    success = server.validator.revoke_token(token, token_type_hint, client)

    if success:
        logger.info(f"Successfully revoked token for client {client_id} (type_hint: {token_type_hint})")
    else:
        # RFC 7009: Always return 200 even if token wasn't found
        # But log for monitoring/debugging purposes
        logger.warning(f"Token revocation failed - token not found for client {client_id} (type_hint: {token_type_hint}, token_prefix: {token[:10]}...)")

    return {"message": "Token revoked successfully"}


@router.post("/admin/cleanup-tokens", dependencies=[Depends(RateLimiter(times=10, hours=1))])
async def cleanup_expired_tokens(
    days_old: int = 30,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Admin endpoint to clean up expired OAuth2 tokens.

    Only accessible to authenticated users (admin functionality).
    """
    # Check if user has admin privileges (for now, just check if user exists)
    # In production, you'd check for specific admin roles

    server = create_authorization_server(db)
    cleaned_count = server.validator.cleanup_expired_tokens(days_old)

    return {
        "message": f"Cleaned up {cleaned_count} expired tokens",
        "days_threshold": days_old,
        "performed_by": current_user.username
    }


@router.post("/clients",
            response_model=OAuth2ClientRegistrationResponse,
            status_code=201,
            dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def register_client(
    client_data: OAuth2ClientRegistrationRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    OAuth 2.0 Client Registration endpoint.
    
    Registers a new OAuth 2.0 client.
    """
    # Generate client credentials
    client_id, client_secret = generate_client_credentials()

    # Create new client
    new_client = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        name=client_data.client_name,
        redirect_uris=[],
        scopes=[]
    )
    # Validate redirect URIs for security
    for uri in client_data.redirect_uris:
        validate_redirect_uri_security(uri)

    new_client.set_redirect_uris(client_data.redirect_uris)
    new_client.set_scopes(client_data.scopes or settings.oauth2_default_scopes)

    # Add client to database first to get the ID
    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    # Generate and store registration access token
    token_record = new_client.generate_registration_token()
    db.add(token_record)
    db.commit()

    logger.info(f"Registered new OAuth2 client: {client_id} by user {current_user.id}")

    return OAuth2ClientRegistrationResponse(
        client_id=new_client.client_id,
        client_secret=client_secret,  # Return plain secret only during registration
        client_name=new_client.name,
        redirect_uris=new_client.get_redirect_uris(),
        scopes=new_client.get_scopes(),
        registration_access_token=token_record.plain_token,  # Return the plain token
        registration_client_uri=f"/oauth/clients/{new_client.client_id}"
    )


@router.get("/clients", response_model=OAuth2ClientListResponse)
async def list_clients(
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    List OAuth 2.0 clients for the current user.
    """
    # For now, return all clients (in production, filter by user)
    clients = db.query(OAuth2Client).filter(OAuth2Client.is_active == True).all()

    client_list = []
    for client in clients:
        client_list.append({
            "client_id": client.client_id,
            "client_name": client.name,
            "redirect_uris": client.get_redirect_uris(),
            "scopes": client.get_scopes(),
            "created_at": client.created_at.isoformat() if client.created_at else None,
            "secret_last_rotated": client.secret_last_rotated.isoformat() if client.secret_last_rotated else None,
            "is_active": client.is_active
        })

    return OAuth2ClientListResponse(clients=client_list)


# Registration access token bearer scheme
registration_token_scheme = HTTPBearer()


async def get_client_from_registration_token(
    credentials: HTTPAuthorizationCredentials = Depends(registration_token_scheme),
    db: Session = Depends(get_db)
) -> OAuth2Client:
    """
    Get OAuth2 client from registration access token.
    """
    token_value = credentials.credentials

    # Verify token
    token_record = OAuth2ClientToken.verify_token(db, token_value, "registration")

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired registration access token"
        )

    # Get the associated client
    client = db.query(OAuth2Client).filter(OAuth2Client.id == token_record.client_id).first()

    if not client or not client.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    return client


@router.get("/clients/{client_id}", response_model=OAuth2ClientManagementResponse)
async def get_client(
    client_id: str,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Get OAuth 2.0 client information.
    Requires admin privileges.
    """
    # Get the client by client_id
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    return OAuth2ClientManagementResponse(
        client_id=client.client_id,
        client_name=client.name,
        redirect_uris=client.get_redirect_uris(),
        scopes=client.get_scopes(),
        registration_client_uri=f"/oauth/clients/{client.client_id}",
        client_id_issued_at=int(client.created_at.timestamp()) if client.created_at else None,
        secret_last_rotated=client.secret_last_rotated,
        is_active=client.is_active
    )


@router.put("/clients/{client_id}", response_model=OAuth2ClientManagementResponse,
           dependencies=[Depends(RateLimiter(times=10, minutes=1))])
async def update_client(
    client_id: str,
    client_data: OAuth2ClientRegistrationRequest,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Update OAuth 2.0 client.
    Requires admin privileges.
    """
    # Get the client by client_id
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    # Update client fields
    if client_data.client_name:
        client.name = client_data.client_name

    if client_data.redirect_uris is not None:
        # Validate redirect URIs for security
        for uri in client_data.redirect_uris:
            validate_redirect_uri_security(uri)
        client.set_redirect_uris(client_data.redirect_uris)

    if client_data.scopes is not None:
        # Validate scopes before updating
        try:
            validate_oauth2_scopes(" ".join(client_data.scopes), None)  # Global validation only
            client.set_scopes(client_data.scopes)
        except OAuth2Error as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    client.updated_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(f"Updated OAuth2 client: {client_id}")

    return OAuth2ClientManagementResponse(
        client_id=client.client_id,
        client_name=client.name,
        redirect_uris=client.get_redirect_uris(),
        scopes=client.get_scopes(),
        registration_client_uri=f"/oauth/clients/{client.client_id}",
        client_id_issued_at=int(client.created_at.timestamp()) if client.created_at else None,
        secret_last_rotated=client.secret_last_rotated,
        is_active=client.is_active
    )


@router.delete("/clients/{client_id}",
              dependencies=[Depends(RateLimiter(times=5, hours=1))])
async def delete_client(
    client_id: str,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete OAuth 2.0 client.
    Requires admin privileges.
    """
    # Get the client by client_id
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    # Mark client as inactive instead of deleting (for audit purposes)
    client.is_active = False
    client.updated_at = datetime.now(timezone.utc)

    # Also revoke all registration tokens for this client
    db.query(OAuth2ClientToken).filter(
        OAuth2ClientToken.client_id == client.id,
        OAuth2ClientToken.token_type == "registration"
    ).update({"expires_at": datetime.now(timezone.utc)})

    db.commit()

    logger.info(f"Deactivated OAuth2 client: {client_id}")

    return {"message": "Client successfully deactivated"}


@router.post("/clients/{client_id}/rotate-secret", response_model=Dict[str, Any],
            dependencies=[Depends(RateLimiter(times=10, hours=1))])
@handle_oauth2_exceptions
async def rotate_client_secret(
    client_id: str,
    current_user: User = Depends(_require_admin),
    db: Session = Depends(get_db)
):
    """
    Rotate the client secret for an OAuth 2.0 client.
    Requires admin privileges.

    This generates a new client secret and returns it once.
    The old secret becomes invalid immediately.
    """
    # Get the client by client_id
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Client not found"
        )

    # Generate new secret
    new_secret = client.rotate_client_secret()

    # Update client in database
    db.commit()

    logger.info(f"Rotated client secret for OAuth2 client: {client_id}")

    return {
        "client_id": client.client_id,
        "client_secret": new_secret,  # Return new secret only once
        "secret_last_rotated": client.secret_last_rotated.isoformat(),
        "message": "Client secret rotated successfully. Store the new secret securely - it will not be shown again."
    }
