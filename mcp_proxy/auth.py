"""Authentication providers for MCP Proxy."""

import os
import logging
from typing import Optional

from fastmcp.server.auth import StaticTokenVerifier
from fastmcp.server.auth.providers.google import GoogleProvider

# Minimum acceptable length for MCP_AUTH_TOKEN. A shared static credential is
# only as strong as its entropy, so reject obviously weak values (e.g. "test")
# before they reach a gateway-exposed deployment.
MIN_TOKEN_LENGTH = 32

# Identity recorded for requests authenticated with the static token. There is
# only ever one caller in this mode -- the upstream gateway.
STATIC_TOKEN_CLIENT_ID = "agentgateway"


def create_static_token_auth(logger: logging.Logger) -> Optional[StaticTokenVerifier]:
    """
    Create a static shared-token verifier for gateway-fronted deployments.

    Intended for topologies where an upstream gateway (e.g. agentgateway)
    terminates the real OAuth flow and forwards requests to this proxy with a
    fixed ``Authorization: Bearer <token>`` header. This proxy then only needs
    to confirm the caller is that gateway.

    This mode provides no per-user identity, no token expiry, and no rotation.
    It is not a substitute for network scoping: bind the proxy so only the
    gateway can reach it (see MCP_HOST).

    Environment Variables:
        MCP_AUTH_TOKEN: Shared secret. Generate with `openssl rand -hex 32`.

    Args:
        logger: Logger instance for output

    Returns:
        StaticTokenVerifier instance, or None if not configured / invalid
    """
    token = os.getenv("MCP_AUTH_TOKEN")

    if not token:
        return None

    token = token.strip()

    if len(token) < MIN_TOKEN_LENGTH:
        logger.error(
            f"✗ MCP_AUTH_TOKEN is too short ({len(token)} chars, "
            f"minimum {MIN_TOKEN_LENGTH})."
        )
        logger.error("  Generate a strong token with: openssl rand -hex 32")
        return None

    try:
        # NOTE: the metadata dict is surfaced verbatim as the token's claims,
        # so it deliberately carries no secret material.
        auth = StaticTokenVerifier(
            tokens={token: {"client_id": STATIC_TOKEN_CLIENT_ID, "scopes": []}}
        )

        logger.info("Static Token Configuration:")
        logger.info(f"  Client ID: {STATIC_TOKEN_CLIENT_ID}")
        logger.info(f"  Token: ***REDACTED*** ({len(token)} chars)")
        logger.info("✓ StaticTokenVerifier successfully initialized")
        return auth

    except Exception as e:
        logger.error(f"✗ Failed to create StaticTokenVerifier: {e}", exc_info=True)
        return None


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
