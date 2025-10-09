"""
Security utility functions for input validation and threat detection.

This module provides reusable security utilities that can be used across
the application for detecting and preventing common security threats.
"""

import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import unquote


class PathSecurityValidator:
    """
    Validates paths for security threats like directory traversal.
    
    Uses os.path normalization for robust path validation instead of
    fragile regex patterns.
    """
    
    @staticmethod
    def is_safe_path(path: str, allowed_base: Optional[str] = None) -> bool:
        """
        Check if a path is safe from directory traversal attacks.
        
        This method:
        1. URL decodes the path
        2. Normalizes it using os.path
        3. Checks for traversal attempts
        4. Optionally validates against an allowed base directory
        
        Args:
            path: Path to validate (URL path or file path)
            allowed_base: Optional base directory to constrain path within
            
        Returns:
            True if path is safe, False if potential traversal detected
            
        Example:
            >>> PathSecurityValidator.is_safe_path("/api/users/123")
            True
            >>> PathSecurityValidator.is_safe_path("/api/../etc/passwd")
            False
            >>> PathSecurityValidator.is_safe_path("uploads/file.txt", "/var/www/uploads")
            True
        """
        if not path:
            return True
        
        # URL decode the path (handles encoded traversal attempts)
        decoded_path = unquote(path)
        
        # Check for obvious patterns first (fast rejection)
        if PathSecurityValidator._contains_obvious_traversal(decoded_path):
            return False
        
        # Normalize the path using os.path (handles .., ./, etc.)
        try:
            normalized = os.path.normpath(decoded_path)
        except (ValueError, TypeError):
            return False
        
        # Check for parent directory references after normalization
        # A safe path shouldn't escape its starting point
        if normalized.startswith('..'):
            return False
        
        # If we have an allowed base, verify the path stays within it
        if allowed_base:
            try:
                # Convert to absolute paths for comparison
                base_path = Path(allowed_base).resolve()
                full_path = (base_path / normalized).resolve()
                
                # Check if the resolved path is within the base
                if not str(full_path).startswith(str(base_path)):
                    return False
            except (ValueError, RuntimeError, OSError):
                return False
        
        return True
    
    @staticmethod
    def _contains_obvious_traversal(path: str) -> bool:
        """
        Quick check for obvious traversal patterns.
        
        This is a fast pre-check before doing full path normalization.
        """
        # Common traversal patterns
        dangerous_patterns = [
            '../',
            '..\\',
            '%2e%2e/',
            '%2e%2e\\',
            '..%2f',
            '..%5c',
            '%2e%2e%2f',
            '%2e%2e%5c',
        ]
        
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in dangerous_patterns)
    
    @staticmethod
    def sanitize_url_path(path: str) -> str:
        """
        Sanitize a URL path component.
        
        Args:
            path: URL path to sanitize
            
        Returns:
            Sanitized path
            
        Example:
            >>> PathSecurityValidator.sanitize_url_path("/api/../admin")
            "/admin"
        """
        if not path:
            return "/"
        
        # URL decode
        decoded = unquote(path)
        
        # Normalize
        normalized = os.path.normpath(decoded)
        
        # Ensure it starts with /
        if not normalized.startswith('/'):
            normalized = '/' + normalized
        
        # Remove any remaining .. at the start
        while normalized.startswith('../') or normalized == '..':
            normalized = normalized[3:] if normalized.startswith('../') else '/'
        
        return normalized or '/'
    
    @staticmethod
    def validate_filename(filename: str, max_length: int = 255) -> tuple[bool, str]:
        """
        Validate a filename for security issues.
        
        Args:
            filename: Filename to validate
            max_length: Maximum allowed filename length
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Example:
            >>> PathSecurityValidator.validate_filename("document.pdf")
            (True, "")
            >>> PathSecurityValidator.validate_filename("../../etc/passwd")
            (False, "Filename contains path traversal")
        """
        if not filename:
            return False, "Filename cannot be empty"
        
        # Check for path separators
        if '/' in filename or '\\' in filename:
            return False, "Filename contains path separators"
        
        # Check for parent directory references
        if '..' in filename:
            return False, "Filename contains path traversal"
        
        # Check for null bytes
        if '\x00' in filename:
            return False, "Filename contains null bytes"
        
        # Check length
        if len(filename) > max_length:
            return False, f"Filename exceeds maximum length of {max_length}"
        
        # Check for hidden files (optional - you may want to allow these)
        if filename.startswith('.'):
            return False, "Hidden files not allowed"
        
        # Check for reserved names (Windows)
        reserved_names = {
            'CON', 'PRN', 'AUX', 'NUL',
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }
        name_without_ext = filename.rsplit('.', 1)[0].upper()
        if name_without_ext in reserved_names:
            return False, f"Filename uses reserved name: {name_without_ext}"
        
        return True, ""


class HeaderSecurityValidator:
    """
    Validates HTTP headers for security threats.
    """
    
    @staticmethod
    def validate_header_value(name: str, value: str, max_length: int = 8192) -> tuple[bool, str]:
        """
        Validate an HTTP header value.
        
        Args:
            name: Header name
            value: Header value
            max_length: Maximum allowed header length
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not value:
            return True, ""
        
        # Check length
        if len(value) > max_length:
            return False, f"Header '{name}' exceeds maximum length of {max_length}"
        
        # Check for CRLF injection (header splitting)
        if '\r' in value or '\n' in value:
            return False, f"Header '{name}' contains CRLF characters"
        
        # Check for null bytes
        if '\x00' in value:
            return False, f"Header '{name}' contains null bytes"
        
        return True, ""
    
    @staticmethod
    def is_suspicious_user_agent(user_agent: str) -> bool:
        """
        Check if a User-Agent string looks suspicious.
        
        This is a basic heuristic check, not foolproof.
        
        Args:
            user_agent: User-Agent header value
            
        Returns:
            True if suspicious, False otherwise
        """
        if not user_agent:
            return True  # Missing User-Agent can be suspicious
        
        # Very short User-Agent (likely scanner/bot)
        if len(user_agent) < 10:
            return True
        
        # Common attack tools (basic check)
        suspicious_patterns = [
            'sqlmap',
            'nikto',
            'nmap',
            'masscan',
            'metasploit',
            'havij',
            'acunetix',
            'netsparker',
            'burp',
            'zap',  # OWASP ZAP
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)


class InputSecurityValidator:
    """
    General input validation utilities.
    """
    
    @staticmethod
    def contains_null_bytes(value: str) -> bool:
        """Check if a string contains null bytes."""
        return '\x00' in value if value else False
    
    @staticmethod
    def contains_control_characters(value: str, allow_whitespace: bool = True) -> bool:
        """
        Check if a string contains control characters.
        
        Args:
            value: String to check
            allow_whitespace: If True, allow \n, \t, \r
            
        Returns:
            True if control characters found
        """
        if not value:
            return False
        
        allowed = {'\n', '\t', '\r'} if allow_whitespace else set()
        
        for char in value:
            if ord(char) < 32 and char not in allowed:
                return True
            if ord(char) == 127:  # DEL character
                return True
        
        return False
    
    @staticmethod
    def is_valid_content_length(content_length: str, max_size: int) -> tuple[bool, str]:
        """
        Validate Content-Length header.
        
        Args:
            content_length: Content-Length header value
            max_size: Maximum allowed size in bytes
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not content_length:
            return True, ""
        
        try:
            size = int(content_length)
        except ValueError:
            return False, "Invalid Content-Length format"
        
        if size < 0:
            return False, "Content-Length cannot be negative"
        
        if size > max_size:
            return False, f"Content-Length {size} exceeds maximum of {max_size}"
        
        return True, ""


class SecurityConfig:
    """
    Centralized security configuration constants.
    """
    
    # Request limits
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_HEADER_LENGTH = 8192  # 8KB
    MAX_FILENAME_LENGTH = 255
    
    # Timeouts (seconds)
    REQUEST_TIMEOUT = 30
    
    # Rate limiting
    DEFAULT_RATE_LIMIT = 100  # requests per minute
    
    # Allowed content types
    ALLOWED_CONTENT_TYPES = {
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain'
    }
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib',
        '.sh', '.bat', '.cmd', '.ps1',
        '.app', '.deb', '.rpm', '.dmg',
        '.jar', '.war', '.ear',
        '.scr', '.vbs', '.js'
    }

