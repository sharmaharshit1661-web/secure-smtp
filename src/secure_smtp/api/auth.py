"""
API Authentication & Authorization Module — Secure SMTP.

Provides constant-time API key verification via:
1. 'X-API-Key' HTTP Header
2. 'Authorization: Bearer <key>' Header
3. '?api_key=<key>' Query parameter (for direct file downloads/reports)
"""

import secrets
from typing import Optional

from fastapi import HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from secure_smtp.config import get_settings

# Configurable API Key and Auth Settings from central configuration
settings = get_settings()
DEFAULT_DEV_API_KEY = "securesmtp_live_secret_key"
API_KEY_ENV = settings.api_key
AUTH_REQUIRED = settings.auth_required

# Security Schemes for OpenAPI / Swagger UI
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="API Key Header")
http_bearer = HTTPBearer(auto_error=False, description="Bearer Token")


async def verify_api_key(
    header_key: Optional[str] = Security(api_key_header),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Security(http_bearer),
    query_key: Optional[str] = Query(None, alias="api_key", description="API key parameter for direct downloads"),
) -> str:
    """
    Validate API key from X-API-Key header, Authorization Bearer token, or api_key query param.
    Uses constant-time comparison (secrets.compare_digest) to prevent timing attacks.
    """
    if not AUTH_REQUIRED:
        return "anonymous"

    expected_key = API_KEY_ENV.strip()
    provided_key: Optional[str] = None

    if header_key:
        provided_key = header_key.strip()
    elif bearer_creds and bearer_creds.credentials:
        provided_key = bearer_creds.credentials.strip()
    elif query_key:
        provided_key = query_key.strip()

    if not provided_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API authentication. Provide 'X-API-Key' header, 'Authorization: Bearer <key>', or '?api_key=' parameter.",
            headers={"WWW-Authenticate": "ApiKey, Bearer"},
        )

    if not secrets.compare_digest(provided_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key. Access denied.",
            headers={"WWW-Authenticate": "ApiKey, Bearer"},
        )

    return provided_key
