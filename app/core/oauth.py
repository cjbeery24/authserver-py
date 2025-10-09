"""
OAuth 2.0 and OpenID Connect implementation using Authlib.
"""

import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any
from urllib.parse import urlencode, parse_qs, urlparse

from authlib.oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants, ClientMixin
from authlib.oauth2.rfc6749.errors import InvalidClientError, InvalidRequestError, InvalidScopeError
from authlib.oauth2.rfc6749.models import AuthorizationCodeMixin
from authlib.common.security import generate_token
from authlib.jose import jwt, Key
import logging

from app.core.config import settings
from app.core.security import TokenManager, SecureTokenHasher
from app.models.oauth2_client import OAuth2Client
from app.models.oauth2_token import OAuth2Token
from app.models.oauth2_authorization_code import OAuth2AuthorizationCode
from app.models.user import User

logger = logging.getLogger(__name__)


class OAuth2ClientMixin(ClientMixin):
    """OAuth2Client adapter for Authlib."""

    def __init__(self, client: OAuth2Client):
        self.client = client

    def get_client_id(self) -> str:
        """Get client ID."""
        return self.client.client_id

    def get_client_secret(self) -> str:
        """Get client secret."""
        return self.client.client_secret

    def get_default_redirect_uri(self) -> str:
        """Get default redirect URI."""
        redirect_uris = self.client.get_redirect_uris()
        return redirect_uris[0] if redirect_uris else None

    def get_allowed_scope(self, scope: str) -> str:
        """Get allowed scopes."""
        client_scopes = set(self.client.get_scopes())
        requested_scopes = set(scope.split()) if scope else set()
        
        # Return intersection of requested and allowed scopes
        allowed = client_scopes.intersection(requested_scopes)
        return ' '.join(sorted(allowed))

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """Check if redirect URI is allowed."""
        allowed_uris = self.client.get_redirect_uris()
        return redirect_uri in allowed_uris

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        """Check if endpoint auth method is allowed."""
        # For simplicity, allow all methods for now
        return True

    def check_grant_type(self, grant_type: str) -> bool:
        """Check if grant type is allowed."""
        # Allow common grant types
        allowed_types = {
            'authorization_code',
            'refresh_token',
            'client_credentials',
            'password'  # Resource Owner Password Credentials
        }
        return grant_type in allowed_types

    def check_response_type(self, response_type: str) -> bool:
        """Check if response type is allowed."""
        # Allow authorization code flow
        return response_type == 'code'


class OAuth2AuthorizationCodeMixin(AuthorizationCodeMixin):
    """Authorization code mixin for database storage."""

    def __init__(self, code: str, client_id: str, user_id: int, redirect_uri: str, 
                 scope: str, expires_at: datetime, code_challenge: str = None, 
                 code_challenge_method: str = None):
        self.code = code
        self.client_id = client_id
        self.user_id = user_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.expires_at = expires_at
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method

    def get_redirect_uri(self) -> str:
        """Get redirect URI."""
        return self.redirect_uri

    def get_scope(self) -> str:
        """Get scope."""
        return self.scope

    def get_nonce(self) -> Optional[str]:
        """Get nonce (not used in basic implementation)."""
        return None

    def is_expired(self) -> bool:
        """Check if code is expired."""
        return datetime.now(timezone.utc) > self.expires_at


class CustomOAuth2RequestValidator:
    """Custom OAuth2 request validator."""

    def __init__(self, db_session):
        self.db_session = db_session

    def authenticate_client(self, request, credentials) -> Optional[OAuth2ClientMixin]:
        """Authenticate OAuth2 client."""
        client_id = credentials.get('client_id')
        client_secret = credentials.get('client_secret')

        if not client_id:
            return None

        # Find client in database
        client = self.db_session.query(OAuth2Client).filter(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active == True
        ).first()

        if not client:
            return None

        # Verify client secret using hashed comparison
        if not client.verify_client_secret(client_secret):
            return None

        return OAuth2ClientMixin(client)

    def authenticate_client_id(self, client_id: str) -> Optional[OAuth2ClientMixin]:
        """Authenticate client by ID only (for public clients)."""
        client = self.db_session.query(OAuth2Client).filter(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active == True
        ).first()

        if not client:
            return None

        return OAuth2ClientMixin(client)

    def get_client_credentials(self, client_id: str) -> Optional[Dict[str, str]]:
        """Get client credentials."""
        client = self.db_session.query(OAuth2Client).filter(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active == True
        ).first()

        if not client:
            return None

        return {
            'client_id': client.client_id,
            'client_secret': client.client_secret
        }

    def save_authorization_code(self, client_id: str, code: str, request) -> None:
        """Save authorization code to database."""
        # Create authorization code record
        auth_code = OAuth2AuthorizationCode.create_authorization_code(
            client_id=client_id,
            user_id=request.user.id if hasattr(request, 'user') and request.user else None,
            code=code,
            redirect_uri=request.redirect_uri,
            scope=request.scope.split() if request.scope else [],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.oauth2_authorization_code_expire_minutes),
            code_challenge=getattr(request, 'code_challenge', None),
            code_challenge_method=getattr(request, 'code_challenge_method', None),
            nonce=getattr(request, 'nonce', None)
        )

        # Store in database
        self.db_session.add(auth_code)
        self.db_session.commit()

    def get_authorization_code(self, client_id: str, code: str) -> Optional[OAuth2AuthorizationCodeMixin]:
        """Get authorization code from database."""
        # Query database for authorization code
        auth_code_record = self.db_session.query(OAuth2AuthorizationCode).filter(
            OAuth2AuthorizationCode.code == code,
            OAuth2AuthorizationCode.client_id == client_id
        ).first()

        if not auth_code_record:
            return None

        # Check if code is expired
        if auth_code_record.is_expired:
            # Clean up expired code
            self.db_session.delete(auth_code_record)
            self.db_session.commit()
            return None

        # Convert database record to Authlib-compatible mixin
        auth_mixin = OAuth2AuthorizationCodeMixin(
            code=auth_code_record.code,
            client_id=auth_code_record.client_id,
            user_id=auth_code_record.user_id,
            redirect_uri=auth_code_record.redirect_uri,
            scope=auth_code_record.scope or '',
            expires_at=auth_code_record.expires_at,
            code_challenge=auth_code_record.code_challenge,
            code_challenge_method=auth_code_record.code_challenge_method
        )
        # Add nonce as attribute
        auth_mixin.nonce = auth_code_record.nonce
        return auth_mixin

    def delete_authorization_code(self, client_id: str, code: str) -> None:
        """Delete authorization code from database (use once)."""
        # Delete authorization code from database
        auth_code_record = self.db_session.query(OAuth2AuthorizationCode).filter(
            OAuth2AuthorizationCode.code == code,
            OAuth2AuthorizationCode.client_id == client_id
        ).first()

        if auth_code_record:
            self.db_session.delete(auth_code_record)
            self.db_session.commit()

    def authenticate_user(self, username: str, password: str, client, request):
        """
        Authenticate user for password grant.
        
        Uses centralized AuthenticationManager for consistent authentication logic.
        """
        from app.core.security import AuthenticationManager
        
        # Use centralized authentication (no MFA for OAuth password grant)
        # Note: For OAuth, we don't use redis_client or track failed attempts here
        # OAuth has its own rate limiting
        user = AuthenticationManager.verify_password_only(
            username=username,
            password=password,
            db_session=self.db_session
        )
        
        return user

    def save_token(self, token: Dict[str, Any], request) -> None:
        """Save OAuth2 token to database."""
        client_id = request.client.client_id
        user_id = request.user.id if hasattr(request, 'user') and request.user else None
        scope = token.get('scope', '')

        # Save access token
        if 'access_token' in token:
            access_token = OAuth2Token.create_access_token(
                client_id=client_id,
                user_id=user_id,
                scopes=scope.split() if scope else [],
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.oauth2_access_token_expire_minutes)
            )
            access_token.set_access_token(token['access_token'])  # Use encryption method
            self.db_session.add(access_token)

        # Save refresh token
        if 'refresh_token' in token:
            refresh_token = OAuth2Token.create_refresh_token(
                client_id=client_id,
                user_id=user_id,
                scopes=scope.split() if scope else [],
                expires_at=datetime.now(timezone.utc) + timedelta(days=settings.oauth2_refresh_token_expire_days)
            )
            refresh_token.set_refresh_token(token['refresh_token'])  # Use encryption method
            self.db_session.add(refresh_token)

        self.db_session.commit()

    def get_token(self, client_id: str, grant_type: str, user=None, scope=None) -> Optional[Dict[str, Any]]:
        """Get existing token."""
        # Find existing token for client and user
        query = self.db_session.query(OAuth2Token).filter(
            OAuth2Client.client_id == client_id,
            OAuth2Token.expires_at > datetime.now(timezone.utc)
        )

        # For client credentials flow (user=None), only return tokens with user_id=None
        # For user-specific flows, only return tokens with user_id matching the user
        if user is None:
            # Client credentials flow - only tokens with no associated user
            query = query.filter(OAuth2Token.user_id.is_(None))
        else:
            # User-specific flow - only tokens for this specific user
            query = query.filter(OAuth2Token.user_id == user.id)

        if grant_type == 'refresh_token':
            query = query.filter(OAuth2Token.token_type == 'refresh')
        else:
            query = query.filter(OAuth2Token.token_type == 'access')

        token_record = query.first()
        
        if not token_record:
            return None

        result = {
            'access_token': token_record.access_token or token_record.refresh_token,
            'token_type': 'Bearer',
            'expires_in': int((token_record.expires_at - datetime.now(timezone.utc)).total_seconds())
        }

        if token_record.refresh_token:
            result['refresh_token'] = token_record.refresh_token

        if token_record.scope:
            result['scope'] = token_record.scope

        # Add metadata about token type for debugging
        result['_client_credentials'] = token_record.is_client_credentials_token

        return result

    def revoke_token(self, token: str, token_type_hint: str, client) -> bool:
        """Revoke token."""
        # Find token in database
        query = self.db_session.query(OAuth2Token).filter(
            OAuth2Client.client_id == client.client_id
        )

        if token_type_hint == 'access_token':
            query = query.filter(OAuth2Token.access_token == token)
        elif token_type_hint == 'refresh_token':
            query = query.filter(OAuth2Token.refresh_token == token)
        else:
            # Try both
            query = query.filter(
                (OAuth2Token.access_token == token) | 
                (OAuth2Token.refresh_token == token)
            )

        token_record = query.first()
        
        if token_record:
            # Mark as expired by setting expiry to past
            token_record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            self.db_session.commit()
            return True

        return False

    def introspect_token(self, token: str, token_type_hint: str, client) -> Optional[Dict[str, Any]]:
        """Introspect token."""
        # Find token in database
        query = self.db_session.query(OAuth2Token).filter(
            OAuth2Client.client_id == client.client_id
        )

        if token_type_hint == 'access_token':
            query = query.filter(OAuth2Token.access_token == token)
        elif token_type_hint == 'refresh_token':
            query = query.filter(OAuth2Token.refresh_token == token)
        else:
            # Try both
            query = query.filter(
                (OAuth2Token.access_token == token) | 
                (OAuth2Token.refresh_token == token)
            )

        token_record = query.first()
        
        if not token_record or token_record.is_expired:
            return {
                'active': False
            }

        result = {
            'active': True,
            'client_id': client.client_id,
            'token_type': token_record.token_type,
            'exp': int(token_record.expires_at.timestamp()),
            'iat': int(token_record.created_at.timestamp())
        }

        if token_record.scope:
            result['scope'] = token_record.scope

        if token_record.user_id:
            result['sub'] = str(token_record.user_id)

        return result

    def cleanup_expired_tokens(self, days_old: int = 30) -> int:
        """
        Clean up expired tokens from the database.

        Returns the number of tokens cleaned up.
        """
        from datetime import datetime, timezone, timedelta

        # Calculate cutoff date (tokens older than this many days)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)

        # Find and delete expired tokens that are also old enough to be cleaned up
        expired_tokens = self.db_session.query(OAuth2Token).filter(
            OAuth2Token.expires_at < datetime.now(timezone.utc),
            OAuth2Token.created_at < cutoff_date
        ).all()

        count = len(expired_tokens)
        for token in expired_tokens:
            self.db_session.delete(token)

        if count > 0:
            self.db_session.commit()
            logger.info(f"Cleaned up {count} expired OAuth2 tokens older than {days_old} days")

        return count


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """Authorization code grant with PKCE support."""

    def validate_authorization_request(self):
        """Validate authorization request."""
        super().validate_authorization_request()
        
        # Validate PKCE if required
        if settings.pkce_required:
            code_challenge = self.request.code_challenge
            code_challenge_method = self.request.code_challenge_method
            
            if not code_challenge:
                raise InvalidRequestError('code_challenge is required')
                
            if code_challenge_method not in ['S256', 'plain']:
                raise InvalidRequestError('code_challenge_method must be S256 or plain')

    def generate_authorization_code(self, client, grant_user, request):
        """Generate authorization code."""
        # Generate secure code
        code = generate_token(48)
        
        # Store authorization code
        self.server.save_authorization_code(client.get_client_id(), code, request)
        
        return code

    def create_authorization_response(self, redirect_uri, grant_user):
        """Create authorization response."""
        if grant_user:
            # Generate authorization code
            code = self.generate_authorization_code(
                self.request.client, grant_user, self.request
            )
            
            # Build redirect URI with code
            params = {
                'code': code,
                'state': self.request.state
            }
            
            # Filter out None values
            params = {k: v for k, v in params.items() if v is not None}
            
            return redirect_uri + '?' + urlencode(params)
        else:
            # Authentication required
            return None


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """Refresh token grant."""

    def authenticate_refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Authenticate refresh token."""
        # Find refresh token in database
        # Note: We need to handle both encrypted and plain text tokens during transition
        
        # First, try to find tokens that match directly (for backward compatibility)
        token_record = self.server.db_session.query(OAuth2Token).filter(
            OAuth2Token.token_type == 'refresh',
            OAuth2Token.expires_at > datetime.now(timezone.utc)
        ).all()
        
        # Check each token (decrypt if necessary)
        matching_token = None
        for record in token_record:
            stored_token = record.get_refresh_token()  # This handles decryption
            if stored_token == refresh_token:
                matching_token = record
                break
        
        if not matching_token:
            return None

        # Get user if token has user_id
        user = None
        if matching_token.user_id:
            user = self.server.db_session.query(User).filter(
                User.id == matching_token.user_id,
                User.is_active == True
            ).first()

        return {
            'client_id': matching_token.client.client_id,
            'scope': matching_token.scope,
            'user': user
        }

    def invalidate_authorization_code(self, authorization_code: str) -> None:
        """Invalidate authorization code."""
        self.server.delete_authorization_code(
            self.request.client.get_client_id(), 
            authorization_code
        )


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    """Client credentials grant."""

    def authenticate_user(self, client, credentials):
        """Authenticate user for client credentials grant."""
        # Client credentials grant doesn't require user authentication
        return None


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    """Resource owner password credentials grant."""

    def authenticate_user(self, username: str, password: str, client) -> Optional[User]:
        """Authenticate user with username and password."""
        return self.server.validate_user(username, password, client, self.request)


def create_authorization_server(db_session):
    """Create and configure authorization server."""
    
    # Create validator
    validator = CustomOAuth2RequestValidator(db_session)
    
    # Create authorization server using Authlib's core AuthorizationServer
    server = AuthorizationServer()
    
    # Add grants
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)
    server.register_grant(ClientCredentialsGrant)
    server.register_grant(PasswordGrant)
    
    # Store database session for use in grants
    server.db_session = db_session
    server.validator = validator
    
    # Add method to create token response with ID tokens
    server.create_token_response = lambda **kwargs: create_oauth2_token_response_with_id_token(db_session, **kwargs)
    
    return server


def create_oauth2_token_response_with_id_token(
    db_session,
    client_id: str, 
    grant_type: str, 
    user_id: Optional[int] = None, 
    scope: str = "",
    nonce: str = None,
    auth_time: datetime = None
) -> Dict[str, Any]:
    """
    Create OAuth2/OIDC token response with ID token support.
    
    Args:
        db_session: Database session
        client_id: OAuth2 client ID
        grant_type: Grant type being used
        user_id: User ID (None for client credentials)
        scope: Granted scopes as space-separated string
        nonce: Nonce from authorization request (for ID tokens)
        auth_time: Authentication time
        
    Returns:
        Token response dictionary
    """
    from app.core.security import TokenManager
    from app.models.user import User
    
    # Parse scopes
    scopes = scope.split() if scope else []
    
    # Prepare user data for tokens
    user_data = {}
    if user_id:
        # Get user from database
        user = db_session.query(User).filter(User.id == user_id).first()
        if user:
            user_data = {
                "sub": str(user.id),
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "email_verified": True  # Assume verified for now
            }
    
    # Use the enhanced token creation method
    token_response = TokenManager.create_oauth2_token_response(
        user_data=user_data,
        client_id=client_id,
        scopes=scopes,
        nonce=nonce,
        auth_time=auth_time
    )
    
    # Save tokens to database using existing method
    from datetime import timezone, timedelta
    
    # Save access token
    if 'access_token' in token_response:
        access_token = OAuth2Token.create_access_token(
            client_id=client_id,
            user_id=user_id,
            scopes=scopes,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.oauth2_access_token_expire_minutes)
        )
        access_token.access_token = token_response['access_token']
        db_session.add(access_token)

    # Save refresh token
    if 'refresh_token' in token_response:
        refresh_token = OAuth2Token.create_refresh_token(
            client_id=client_id,
            user_id=user_id,
            scopes=scopes,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.oauth2_refresh_token_expire_days)
        )
        refresh_token.refresh_token = token_response['refresh_token']
        db_session.add(refresh_token)

    db_session.commit()
    
    return token_response


def generate_client_credentials() -> tuple[str, str]:
    """Generate secure client credentials."""
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(64)
    return client_id, client_secret


def create_default_oauth_client(db_session) -> OAuth2Client:
    """Create default OAuth2 client for development."""
    client_id, client_secret = generate_client_credentials()
    
    client = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        name="Default OAuth2 Client",
        redirect_uris=[],
        scopes=["openid", "profile", "email"]
    )
    client.set_redirect_uris([settings.oauth2_redirect_uri])
    
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    
    logger.info(f"Created default OAuth2 client: {client_id}")
    
    return client
