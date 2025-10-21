"""
Configuration management for the authentication server.
Uses Pydantic Settings for environment variable handling and validation.
"""

from typing import List, Optional, Set
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application Settings
    app_name: str = Field(default="Authentication Server", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    app_env: str = Field(default="development", env="APP_ENV")
    debug: bool = Field(default=True, env="DEBUG")
    log_level: str = Field(default="DEBUG", env="LOG_LEVEL")
    
    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    workers: int = Field(default=1, env="WORKERS")
    reload: bool = Field(default=True, env="RELOAD")
    
    # Database Configuration
    database_url: str = Field(env="DATABASE_URL")
    database_host: str = Field(default="localhost", env="DATABASE_HOST")
    database_port: int = Field(default=5432, env="DATABASE_PORT")
    database_name: str = Field(default="authserver", env="DATABASE_NAME")
    database_user: str = Field(default="authuser", env="DATABASE_USER")
    database_password: str = Field(default="authpass", env="DATABASE_PASSWORD")
    database_pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    database_pool_timeout: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    database_pool_recycle: int = Field(default=3600, env="DATABASE_POOL_RECYCLE")
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_ssl: bool = Field(default=False, env="REDIS_SSL")
    
    # Security & Authentication
    jwt_secret_key: str = Field(env="JWT_SECRET_KEY")  # Kept for backward compatibility
    jwt_private_key: Optional[str] = Field(default=None, env="JWT_PRIVATE_KEY")  # RSA private key in PEM format
    jwt_public_key: Optional[str] = Field(default=None, env="JWT_PUBLIC_KEY")    # RSA public key in PEM format
    jwt_algorithm: str = Field(default="RS256", env="JWT_ALGORITHM")  # Changed default to RS256
    jwt_key_id: str = Field(default="auth-server-key-1", env="JWT_KEY_ID")  # Key ID for JWKS
    jwt_access_token_expire_minutes: int = Field(default=30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    jwt_refresh_token_expire_days: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Token Security
    security_salt: str = Field(default="default_salt_change_in_production", env="SECURITY_SALT")
    encrypt_tokens_in_db: bool = Field(default=True, env="ENCRYPT_TOKENS_IN_DB")
    token_encryption_key: Optional[str] = Field(default=None, env="TOKEN_ENCRYPTION_KEY")
    
    # Token Binding
    token_binding_enabled: bool = Field(default=True, env="TOKEN_BINDING_ENABLED")
    token_binding_strict_ip: bool = Field(default=False, env="TOKEN_BINDING_STRICT_IP")
    token_binding_tolerance_seconds: int = Field(default=300, env="TOKEN_BINDING_TOLERANCE_SECONDS")
    token_binding_skip_testing_tools: bool = Field(default=True, env="TOKEN_BINDING_SKIP_TESTING_TOOLS")
    
    # Password Security
    password_min_length: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    password_strong_length: int = Field(default=12, env="PASSWORD_STRONG_LENGTH")
    password_very_strong_length: int = Field(default=16, env="PASSWORD_VERY_STRONG_LENGTH")
    password_unique_chars_threshold: int = Field(default=10, env="PASSWORD_UNIQUE_CHARS_THRESHOLD")
    password_require_uppercase: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    password_require_lowercase: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    password_require_digits: bool = Field(default=True, env="PASSWORD_REQUIRE_DIGITS")
    password_require_special_chars: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL_CHARS")
    password_check_common_patterns: bool = Field(default=True, env="PASSWORD_CHECK_COMMON_PATTERNS")
    special_characters: str = Field(default="!@#$%^&*()_+-=[]{}|;:,.<>?", env="SPECIAL_CHARACTERS")

    # Authentication Middleware Settings
    auth_middleware_enabled: bool = Field(default=True, env="AUTH_MIDDLEWARE_ENABLED")
    
    # MFA Settings
    mfa_totp_issuer: str = Field(default="AuthServer", env="MFA_TOTP_ISSUER")
    mfa_totp_digits: int = Field(default=6, env="MFA_TOTP_DIGITS")
    mfa_totp_period: int = Field(default=30, env="MFA_TOTP_PERIOD")
    mfa_backup_codes_count: int = Field(default=10, env="MFA_BACKUP_CODES_COUNT")
    mfa_backup_codes_expiry_days: int = Field(default=365, env="MFA_BACKUP_CODES_EXPIRY_DAYS")
    mfa_backup_code_length: int = Field(default=8, env="MFA_BACKUP_CODE_LENGTH")
    
    # Token Generation Settings
    default_token_length: int = Field(default=32, env="DEFAULT_TOKEN_LENGTH")
    reset_token_length: int = Field(default=32, env="RESET_TOKEN_LENGTH")
    verification_code_length: int = Field(default=6, env="VERIFICATION_CODE_LENGTH")
    
    # Suspicious Activity Detection
    max_failed_attempts: int = Field(default=5, env="MAX_FAILED_ATTEMPTS")
    min_user_agent_length: int = Field(default=10, env="MIN_USER_AGENT_LENGTH")
    suspicious_ips: Set[str] = Field(default={"127.0.0.1", "0.0.0.0"}, env="SUSPICIOUS_IPS")
    suspicious_activity_time_window: int = Field(default=5, env="SUSPICIOUS_ACTIVITY_TIME_WINDOW")
    
    # Input Sanitization
    max_input_length: int = Field(default=255, env="MAX_INPUT_LENGTH")
    
    # OpenID Connect & OAuth 2.0
    oidc_issuer_url: str = Field(default="http://localhost:8000", env="OIDC_ISSUER_URL")
    oidc_jwks_uri: str = Field(default="http://localhost:8000/.well-known/jwks.json", env="OIDC_JWKS_URI")
    oidc_authorization_endpoint: str = Field(default="http://localhost:8000/oauth/authorize", env="OIDC_AUTHORIZATION_ENDPOINT")
    oidc_token_endpoint: str = Field(default="http://localhost:8000/oauth/token", env="OIDC_TOKEN_ENDPOINT")
    oidc_userinfo_endpoint: str = Field(default="http://localhost:8000/oauth/userinfo", env="OIDC_USERINFO_ENDPOINT")
    oidc_introspection_endpoint: str = Field(default="http://localhost:8000/oauth/introspect", env="OIDC_INTROSPECTION_ENDPOINT")
    oidc_revocation_endpoint: str = Field(default="http://localhost:8000/oauth/revoke", env="OIDC_REVOCATION_ENDPOINT")
    
    oauth2_client_id: str = Field(default="your-client-id", env="OAUTH2_CLIENT_ID")
    oauth2_client_secret: str = Field(default="your-client-secret", env="OAUTH2_CLIENT_SECRET")
    oauth2_redirect_uri: str = Field(default="http://localhost:3000/callback", env="OAUTH2_REDIRECT_URI")
    
    pkce_required: bool = Field(default=True, env="PKCE_REQUIRED")
    pkce_code_verifier_min_length: int = Field(default=43, env="PKCE_CODE_VERIFIER_MIN_LENGTH")
    pkce_code_verifier_max_length: int = Field(default=128, env="PKCE_CODE_VERIFIER_MAX_LENGTH")
    
    # OAuth 2.0 Token Settings
    oauth2_access_token_expire_minutes: int = Field(default=30, env="OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES")
    oauth2_refresh_token_expire_days: int = Field(default=7, env="OAUTH2_REFRESH_TOKEN_EXPIRE_DAYS")
    oauth2_authorization_code_expire_minutes: int = Field(default=10, env="OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES")
    
    # OAuth 2.0 Scopes
    oauth2_default_scopes: List[str] = Field(default=["openid", "profile", "email"], env="OAUTH2_DEFAULT_SCOPES")
    oauth2_supported_scopes: List[str] = Field(default=["openid", "profile", "email", "offline_access", "read", "write"], env="OAUTH2_SUPPORTED_SCOPES")
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_requests_per_hour: int = Field(default=1000, env="RATE_LIMIT_REQUESTS_PER_HOUR")
    rate_limit_requests_per_day: int = Field(default=10000, env="RATE_LIMIT_REQUESTS_PER_DAY")

    # Authentication Rate Limiting
    auth_rate_limit_enabled: bool = Field(default=True, env="AUTH_RATE_LIMIT_ENABLED")
    auth_registration_per_hour: int = Field(default=5, env="AUTH_REGISTRATION_PER_HOUR")
    auth_login_per_minute: int = Field(default=5, env="AUTH_LOGIN_PER_MINUTE")
    auth_token_refresh_per_hour: int = Field(default=20, env="AUTH_TOKEN_REFRESH_PER_HOUR")
    auth_failed_login_penalty_minutes: int = Field(default=15, env="AUTH_FAILED_LOGIN_PENALTY_MINUTES")
    
    # Email Configuration
    email_enabled: bool = Field(default=False, env="EMAIL_ENABLED")
    email_host: str = Field(default="smtp.gmail.com", env="EMAIL_HOST")
    email_port: int = Field(default=587, env="EMAIL_PORT")
    email_use_tls: bool = Field(default=True, env="EMAIL_USE_TLS")
    email_use_ssl: bool = Field(default=False, env="EMAIL_USE_SSL")
    email_username: str = Field(default="", env="EMAIL_USERNAME")
    email_password: str = Field(default="", env="EMAIL_PASSWORD")
    email_from: str = Field(default="noreply@authserver.com", env="EMAIL_FROM")

    # Password Reset Configuration
    password_reset_token_expire_hours: int = Field(default=1, env="PASSWORD_RESET_TOKEN_EXPIRE_HOURS")
    frontend_url: str = Field(default="http://localhost:3000", env="FRONTEND_URL")
    
    # Logging & Monitoring
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file: str = Field(default="logs/app.log", env="LOG_FILE")
    log_max_size: str = Field(default="100MB", env="LOG_MAX_SIZE")
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    health_check_enabled: bool = Field(default=True, env="HEALTH_CHECK_ENABLED")
    health_check_interval: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")
    
    # CORS Settings
    cors_enabled: bool = Field(default=True, env="CORS_ENABLED")
    cors_origins: str = Field(default="http://localhost:3000,http://localhost:8080", env="CORS_ORIGINS")
    cors_methods: str = Field(default="GET,POST,PUT,DELETE,OPTIONS", env="CORS_METHODS")
    cors_headers: str = Field(default="Content-Type,Authorization", env="CORS_HEADERS")
    cors_credentials: bool = Field(default=True, env="CORS_CREDENTIALS")
    
    # Audit & Compliance
    audit_logging_enabled: bool = Field(default=True, env="AUDIT_LOGGING_ENABLED")
    audit_log_retention_days: int = Field(default=7, env="AUDIT_LOG_RETENTION_DAYS")
    audit_log_level: str = Field(default="INFO", env="AUDIT_LOG_LEVEL")
    
    # Development & Testing
    testing: bool = Field(default=False, env="TESTING")
    test_database_url: str = Field(default="", env="TEST_DATABASE_URL")
    test_database_name: str = Field(default="", env="TEST_DATABASE_NAME")
    test_client_id: str = Field(default="test-client", env="TEST_CLIENT_ID")
    test_client_secret: str = Field(default="test-secret", env="TEST_CLIENT_SECRET")
    
    # External Services
    sms_enabled: bool = Field(default=False, env="SMS_ENABLED")
    sms_provider: str = Field(default="twilio", env="SMS_PROVIDER")
    sms_account_sid: str = Field(default="", env="SMS_ACCOUNT_SID")
    sms_auth_token: str = Field(default="", env="SMS_AUTH_TOKEN")
    sms_from_number: str = Field(default="", env="SMS_FROM_NUMBER")
    
    @field_validator("database_url", mode="before")
    @classmethod
    def build_database_url(cls, v, info):
        """Build database URL from components if not provided."""
        if v:
            return v
        values = info.data
        return f"postgresql://{values.get('database_user', 'authuser')}:{values.get('database_password', 'authpass')}@{values.get('database_host', 'localhost')}:{values.get('database_port', 5432)}/{values.get('database_name', 'authserver')}"
    
    @field_validator("redis_url", mode="before")
    @classmethod
    def build_redis_url(cls, v, info):
        """Build Redis URL from components if not provided."""
        if v:
            return v
        values = info.data
        password_part = f":{values.get('redis_password')}@" if values.get('redis_password') else ""
        return f"redis://{password_part}{values.get('redis_host', 'localhost')}:{values.get('redis_port', 6379)}/{values.get('redis_db', 0)}"
    
    @field_validator("suspicious_ips", mode="before")
    @classmethod
    def parse_suspicious_ips(cls, v):
        """Parse comma-separated suspicious IPs into a set."""
        if isinstance(v, set):
            return v
        if isinstance(v, str):
            return {ip.strip() for ip in v.split(",") if ip.strip()}
        return {"127.0.0.1", "0.0.0.0"}

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def parse_comma_separated(value: str) -> List[str]:
    """Parse a comma-separated string into a list of strings."""
    if not value:
        return []
    return [item.strip() for item in value.split(",")]


# Convenience methods for parsed CORS settings
def get_cors_origins() -> List[str]:
    """Get CORS origins as a list."""
    return parse_comma_separated(settings.cors_origins)


def get_cors_methods() -> List[str]:
    """Get CORS methods as a list."""
    return parse_comma_separated(settings.cors_methods)


def get_cors_headers() -> List[str]:
    """Get CORS headers as a list."""
    return parse_comma_separated(settings.cors_headers)