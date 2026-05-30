"""Google OAuth authentication provider for MCP Proxy."""

import os
import logging
from typing import Optional

from fastmcp.server.auth.providers.google import GoogleProvider


def create_google_auth(logger: logging.Logger) -> Optional[GoogleProvider]:
    """
    Create Google OAuth provider for Claude.ai integration.

    Supports any OIDC-compliant provider via Google Cloud OAuth.
    Claude.ai requires OAuth with DCR support, which FastMCP's GoogleProvider handles.

    Environment Variables:
        GOOGLE_CLIENT_ID: OAuth 2.0 Client ID from Google Cloud Console
        GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
        MCP_BASE_URL: Public URL of this proxy (for OAuth callback)
        GOOGLE_JWT_KEY: JWT signing key (optional, recommended for production)

    Args:
        logger: Logger instance for output

    Returns:
        GoogleProvider instance or None if not configured
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    base_url = os.getenv("MCP_BASE_URL")
    jwt_key = os.getenv("GOOGLE_JWT_KEY")

    if not all([client_id, client_secret, base_url]):
        return None

    logger.info("Google OAuth Configuration:")
    logger.info(
        f"  Client ID: {'*' * 8 + (client_id[-8:] if client_id and len(client_id) > 8 else 'INVALID')}"
    )
    logger.info(f"  Client Secret: {'***REDACTED***' if client_secret else 'MISSING'}")
    logger.info(f"  Base URL: {base_url}")
    logger.info(f"  JWT Key: {'***CONFIGURED***' if jwt_key else 'not set (dev mode)'}")

    try:
        auth = GoogleProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            required_scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
            jwt_signing_key=jwt_key if jwt_key else None,
        )

        logger.info("✓ GoogleProvider successfully initialized")
        return auth

    except Exception as e:
        logger.error(f"✗ Failed to create GoogleProvider: {e}", exc_info=True)
        return None
