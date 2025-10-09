"""
Request/Response logging middleware for comprehensive API monitoring.
"""

import logging
import time
import json
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse, StreamingResponse
from io import BytesIO

from app.core.config import settings

logger = logging.getLogger(__name__)


class RequestResponseLoggingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request/response logging middleware.
    
    Features:
    - Request logging (method, path, headers, body)
    - Response logging (status, headers, timing)
    - Configurable log levels
    - Sensitive data filtering
    - Performance metrics
    """
    
    def __init__(
        self,
        app,
        log_request_body: bool = False,
        log_response_body: bool = False,
        sensitive_headers: list = None,
        max_body_log_size: int = 1024
    ):
        super().__init__(app)
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.max_body_log_size = max_body_log_size
        self.sensitive_headers = sensitive_headers or [
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "proxy-authorization"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> StarletteResponse:
        """Process request and log details."""
        start_time = time.time()
        
        # Generate request ID
        request_id = self._generate_request_id()
        
        # Log request
        await self._log_request(request, request_id)
        
        # Store request body for potential error logging
        request_body = None
        if self.log_request_body:
            request_body = await self._get_request_body(request)
        
        # Process request
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Log response
            await self._log_response(request, response, process_time, request_id)
            
            # Add request ID and timing headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            
            # Log error
            logger.error(
                f"Request failed | "
                f"request_id={request_id} | "
                f"method={request.method} | "
                f"path={request.url.path} | "
                f"error={str(e)} | "
                f"time={process_time:.3f}s",
                exc_info=True
            )
            
            # Re-raise the exception
            raise
    
    async def _log_request(self, request: Request, request_id: str) -> None:
        """Log incoming request details."""
        # Get client information
        client_host = request.client.host if request.client else "unknown"
        
        # Filter sensitive headers
        headers = self._filter_sensitive_headers(dict(request.headers))
        
        # Determine log level based on path
        if self._is_health_check(request.url.path):
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        
        # Log request
        logger.log(
            log_level,
            f"Incoming request | "
            f"request_id={request_id} | "
            f"method={request.method} | "
            f"path={request.url.path} | "
            f"query={request.url.query} | "
            f"client={client_host} | "
            f"user_agent={request.headers.get('user-agent', 'unknown')}"
        )
        
        # Log headers if in debug mode
        if settings.debug and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Request headers | request_id={request_id} | headers={json.dumps(headers)}")
    
    async def _log_response(
        self,
        request: Request,
        response: StarletteResponse,
        process_time: float,
        request_id: str
    ) -> None:
        """Log response details."""
        # Determine log level based on status code
        if response.status_code >= 500:
            log_level = logging.ERROR
        elif response.status_code >= 400:
            log_level = logging.WARNING
        elif self._is_health_check(request.url.path):
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        
        # Log response
        logger.log(
            log_level,
            f"Response sent | "
            f"request_id={request_id} | "
            f"method={request.method} | "
            f"path={request.url.path} | "
            f"status={response.status_code} | "
            f"time={process_time:.3f}s"
        )
        
        # Log response headers if in debug mode
        if settings.debug and logger.isEnabledFor(logging.DEBUG):
            headers = self._filter_sensitive_headers(dict(response.headers))
            logger.debug(f"Response headers | request_id={request_id} | headers={json.dumps(headers)}")
    
    async def _get_request_body(self, request: Request) -> bytes:
        """Read and cache request body."""
        body = await request.body()
        
        # Log body if not too large
        if len(body) <= self.max_body_log_size:
            try:
                # Try to parse as JSON
                body_json = json.loads(body.decode())
                # Filter sensitive fields
                body_json = self._filter_sensitive_fields(body_json)
                logger.debug(f"Request body | body={json.dumps(body_json)}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Log as text if not JSON
                logger.debug(f"Request body | body={body[:self.max_body_log_size]}")
        else:
            logger.debug(f"Request body too large | size={len(body)} bytes")
        
        return body
    
    def _filter_sensitive_headers(self, headers: dict) -> dict:
        """Remove sensitive headers from logging."""
        filtered = {}
        for key, value in headers.items():
            if key.lower() in self.sensitive_headers:
                filtered[key] = "***REDACTED***"
            else:
                filtered[key] = value
        return filtered
    
    def _filter_sensitive_fields(self, data: dict) -> dict:
        """Remove sensitive fields from data."""
        sensitive_fields = [
            "password",
            "token",
            "secret",
            "api_key",
            "access_token",
            "refresh_token",
            "client_secret",
            "authorization",
            "mfa_token"
        ]
        
        filtered = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                filtered[key] = "***REDACTED***"
            elif isinstance(value, dict):
                filtered[key] = self._filter_sensitive_fields(value)
            else:
                filtered[key] = value
        return filtered
    
    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _is_health_check(self, path: str) -> bool:
        """Check if this is a health check endpoint."""
        health_paths = ["/health", "/api/v1/health"]
        return any(path.startswith(health_path) for health_path in health_paths)


class StructuredLogger:
    """
    Structured logging utility for consistent log formatting.
    """
    
    @staticmethod
    def log_auth_event(
        event_type: str,
        user_id: int = None,
        username: str = None,
        ip_address: str = None,
        success: bool = True,
        details: dict = None
    ):
        """Log authentication events."""
        log_data = {
            "event_type": "auth",
            "action": event_type,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "success": success,
            "timestamp": time.time()
        }
        
        if details:
            log_data.update(details)
        
        level = logging.INFO if success else logging.WARNING
        logger.log(level, f"Auth event | {json.dumps(log_data)}")
    
    @staticmethod
    def log_api_call(
        method: str,
        path: str,
        status_code: int,
        duration: float,
        user_id: int = None,
        error: str = None
    ):
        """Log API call metrics."""
        log_data = {
            "event_type": "api_call",
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        if error:
            log_data["error"] = error
        
        logger.info(f"API call | {json.dumps(log_data)}")
    
    @staticmethod
    def log_security_event(
        event_type: str,
        severity: str,
        description: str,
        ip_address: str = None,
        user_id: int = None,
        details: dict = None
    ):
        """Log security-related events."""
        log_data = {
            "event_type": "security",
            "action": event_type,
            "severity": severity,
            "description": description,
            "ip_address": ip_address,
            "user_id": user_id,
            "timestamp": time.time()
        }
        
        if details:
            log_data.update(details)
        
        # Map severity to log level
        level_map = {
            "critical": logging.CRITICAL,
            "high": logging.ERROR,
            "medium": logging.WARNING,
            "low": logging.INFO
        }
        level = level_map.get(severity, logging.WARNING)
        
        logger.log(level, f"Security event | {json.dumps(log_data)}")
    
    @staticmethod
    def log_performance_metric(
        metric_name: str,
        value: float,
        unit: str = "ms",
        tags: dict = None
    ):
        """Log performance metrics."""
        log_data = {
            "event_type": "performance",
            "metric": metric_name,
            "value": value,
            "unit": unit,
            "timestamp": time.time()
        }
        
        if tags:
            log_data["tags"] = tags
        
        logger.info(f"Performance metric | {json.dumps(log_data)}")

