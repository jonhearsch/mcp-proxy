"""
MCP Proxy Server - A resilient proxy server for Model Context Protocol (MCP) servers.

This module provides a robust proxy server that can manage multiple MCP servers
through a single FastMCP endpoint. It includes features like:

- Automatic restart on crashes
- Live configuration reloading
- Graceful shutdown handling
- File system monitoring for config changes
- Retry logic with exponential backoff
- Port availability checking
- Hybrid authentication (OAuth + API keys)

Environment Variables:
    MCP_CONFIG_PATH: Path to configuration file (default: mcp_config.json)
    MCP_MAX_RETRIES: Maximum config load retries (default: 3)
    MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
    MCP_LIVE_RELOAD: Enable live config reloading (default: false)
    MCP_PATH_PREFIX: Custom path prefix for MCP endpoint (default: none, endpoint at /mcp/)
    MCP_AUTH_PROVIDER: Auth provider type (set to 'oauth_proxy' for OAuth)
    MCP_API_KEYS: API keys for service accounts (format: "key1:client1,key2:client2")
    MCP_API_KEYS_PATH: Path to API keys JSON file (alternative to MCP_API_KEYS)
    MCP_DISABLE_AUTH: Disable authentication (NOT RECOMMENDED, default: false)
"""

# Core libraries

from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy, AccessToken, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse

import os
import sys
import json
import signal
import time
import logging
import threading
import socket
import re
from pathlib import Path
from typing import Optional, Any, Dict, List, Union

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(".env")
    if env_path.exists():
        load_dotenv(env_path)
        # Log will show after logging is configured
    else:
        # Log will show after logging is configured
        pass
except ImportError:
    pass  # dotenv not installed, env vars must be set manually

# JSON schema validation
import jsonschema

# File watching for live reload
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Version information
try:
    from version import get_version, get_version_info
except ImportError:
    # Fallback if version.py is not available
    def get_version():
        return "unknown"
    def get_version_info():
        return {"full": "unknown"}

# Configure structured logging with environment variable support
def setup_logging():
    """
    Configure structured logging with support for different log levels per logger.
    
    Environment Variables:
        MCP_LOG_LEVEL: Global log level (default: INFO)
                       Values: DEBUG, INFO, WARNING, ERROR, CRITICAL
        MCP_LOG_LEVELS: Comma-separated logger-specific levels (default: none)
                        Format: "logger1:DEBUG,logger2:WARNING,httpx:DEBUG"
    
    Examples:
        MCP_LOG_LEVEL=DEBUG - Enable debug logging globally
        MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG" - Debug only fastmcp and httpx
        MCP_LOG_LEVEL=INFO MCP_LOG_LEVELS="fastmcp:DEBUG" - Info globally, debug for fastmcp
    """
    # Standard log format with fixed-width logger name (15 chars) for alignment
    log_format = '%(asctime)s - %(name)-15s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(log_format)
    
    # Create handlers for stdout and stderr
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    
    # Get global log level from environment
    global_level_str = os.getenv("MCP_LOG_LEVEL", "INFO").upper()
    try:
        global_level = getattr(logging, global_level_str)
    except AttributeError:
        global_level = logging.INFO
        print(f"WARNING: Invalid MCP_LOG_LEVEL '{global_level_str}', using INFO", file=sys.stderr)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(global_level)
    root_logger.handlers.clear()
    root_logger.addHandler(stdout_handler)
    root_logger.addHandler(stderr_handler)
    
    # Configure logger-specific levels
    logger_levels_str = os.getenv("MCP_LOG_LEVELS", "")
    if logger_levels_str:
        for logger_config in logger_levels_str.split(","):
            logger_config = logger_config.strip()
            if ":" not in logger_config:
                continue
            
            logger_name, level_str = logger_config.split(":", 1)
            logger_name = logger_name.strip()
            level_str = level_str.strip().upper()
            
            try:
                level = getattr(logging, level_str)
                logger_obj = logging.getLogger(logger_name)
                logger_obj.setLevel(level)
            except AttributeError:
                print(f"WARNING: Invalid log level '{level_str}' for logger '{logger_name}'", file=sys.stderr)

# Run logging setup
setup_logging()
logger = logging.getLogger(__name__)

# Configure loggers for common libraries (will be overridden by MCP_LOG_LEVELS if specified)
logging.getLogger("fastmcp").setLevel(logging.INFO)
logging.getLogger("fastmcp.auth").setLevel(logging.DEBUG)  # Enable auth debug logging
logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)  # Enable auth debug logging
logging.getLogger("httpx").setLevel(logging.INFO)

# Log .env file loading
try:
    from dotenv import load_dotenv
    env_path = Path(".env")
    if env_path.exists():
        abs_env_path = os.path.abspath(env_path)
        logger.info(f"✓ Loaded environment from: {abs_env_path}")
    else:
        logger.info("No .env file found - using environment variables")
except ImportError:
    logger.info("python-dotenv not installed - using environment variables directly")


def load_users() -> Dict[str, Any]:
    """
    Load authorized users from users.json.

    TODO: This function is defined but not currently enforced!
    User whitelisting needs to be implemented in HybridAuthProvider.verify_token()
    to check if the authenticated user's email/client_id is in the allowed users list.

    For now, access control happens at the OAuth provider level (Auth0/Keycloak).
    """
    users_path = os.getenv("MCP_USERS_PATH", "/data/users.json")
    abs_path = os.path.abspath(users_path)
    try:
        with open(users_path, 'r') as f:
            users = json.load(f)
            user_count = len(users)
            user_emails = ", ".join(users.keys())
            logger.info(f"✓ Loaded users.json from {abs_path}")
            logger.info(f"  Users: {user_emails} ({user_count} total)")
            return users
    except FileNotFoundError:
        logger.error(f"✗ users.json NOT FOUND at {abs_path}")
        logger.error(f"  MCP_USERS_PATH={users_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"✗ Invalid JSON in users.json at {abs_path}: {e}")
        return {}


def load_auth_config() -> Optional[Dict[str, Any]]:
    """
    Load authentication configuration from auth_config.json.
    Supports environment variable expansion in config values.

    Returns:
        Dict containing provider config, or None if file not found or invalid
    """
    auth_config_path = os.getenv("MCP_AUTH_CONFIG_PATH", "/data/auth_config.json")
    abs_path = os.path.abspath(auth_config_path)

    try:
        with open(auth_config_path, 'r') as f:
            raw_config = json.load(f)

        # Expand environment variables in the auth config
        config = expand_env_vars(raw_config)

        logger.info(f"✓ Loaded auth_config.json from {abs_path}")
        logger.info(f"  Provider: {config.get('provider', 'unknown')}")

        return config

    except FileNotFoundError:
        logger.warning(f"auth_config.json not found at {abs_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"✗ Invalid JSON in auth_config.json at {abs_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"✗ Failed to load auth_config.json: {e}")
        return None


def create_auth_provider() -> Optional[OAuthProxy]:
    """
    Create OAuthProxy from auth_config.json or environment variables.

    Supports multiple OAuth 2.1 providers:
    - Auth0
    - Keycloak
    - Okta
    - Generic OIDC (any compliant provider)

    Configuration priority:
    1. auth_config.json (if exists)
    2. Environment variables (legacy Auth0 support)
    """
    auth_provider_type = os.getenv("MCP_AUTH_PROVIDER", "").lower()

    logger.info(f"Auth provider type: {auth_provider_type if auth_provider_type else '(not set)'}")

    if auth_provider_type != "oauth_proxy":
        if auth_provider_type:
            logger.info(f"OAuth not enabled (MCP_AUTH_PROVIDER={auth_provider_type}, expected 'oauth_proxy')")
        return None

    # Get base URL (required for all providers)
    mcp_base_url = os.getenv("MCP_BASE_URL")
    if not mcp_base_url:
        logger.error("✗ MCP_BASE_URL is required for OAuth authentication")
        return None

    try:
        # Try loading from auth_config.json first
        auth_config = load_auth_config()

        if auth_config:
            return _create_from_config(auth_config, mcp_base_url)
        else:
            # Fallback to legacy Auth0 environment variables
            logger.info("No auth_config.json found, checking for legacy Auth0 environment variables...")
            return _create_auth0_from_env(mcp_base_url)

    except Exception as e:
        logger.error(f"✗ Failed to create OAuthProxy: {e}", exc_info=True)
        return None


def _create_from_config(auth_config: Dict[str, Any], mcp_base_url: str) -> Optional[OAuthProxy]:
    """Create OAuthProxy from auth_config.json configuration."""
    provider = auth_config.get("provider", "").lower()

    logger.info(f"Configuring OAuth for provider: {provider}")

    if provider == "auth0":
        return _create_auth0_provider(auth_config.get("auth0", {}), mcp_base_url)
    elif provider == "keycloak":
        return _create_keycloak_provider(auth_config.get("keycloak", {}), mcp_base_url)
    elif provider == "okta":
        return _create_okta_provider(auth_config.get("okta", {}), mcp_base_url)
    elif provider == "generic_oidc" or provider == "oidc":
        return _create_generic_oidc_provider(auth_config.get("generic_oidc", {}), mcp_base_url)
    else:
        logger.error(f"✗ Unsupported provider: {provider}")
        logger.error("  Supported providers: auth0, keycloak, okta, generic_oidc")
        return None


def _create_auth0_provider(config: Dict[str, Any], mcp_base_url: str) -> Optional[OAuthProxy]:
    """Create OAuthProxy for Auth0."""
    domain = config.get("domain")
    audience = config.get("audience")
    client_id = config.get("client_id") or os.getenv("AUTH0_CLIENT_ID")
    client_secret = config.get("client_secret") or os.getenv("AUTH0_CLIENT_SECRET")

    logger.info("Auth0 Configuration:")
    logger.info(f"  Domain: {domain}")
    logger.info(f"  Audience: {audience}")
    logger.info(f"  Client ID: {'*' * 8 + (client_id[-8:] if client_id else 'MISSING')}")
    logger.info(f"  Client Secret: {'***REDACTED***' if client_secret else 'MISSING'}")
    logger.info(f"  Base URL: {mcp_base_url}")

    if not all([domain, audience, client_id, client_secret]):
        missing = []
        if not domain: missing.append("domain")
        if not audience: missing.append("audience")
        if not client_id: missing.append("client_id")
        if not client_secret: missing.append("client_secret")
        logger.error(f"✗ Missing required Auth0 configuration: {', '.join(missing)}")
        return None

    # Configure JWT token validation using Auth0's JWKS
    token_verifier = JWTVerifier(
        jwks_uri=config.get("jwks_uri", f"https://{domain}/.well-known/jwks.json"),
        issuer=config.get("issuer", f"https://{domain}/"),
        audience=audience
    )

    logger.info("✓ JWTVerifier configured")
    logger.info(f"  JWKS URI: {token_verifier.jwks_uri}")
    logger.info(f"  Issuer: {token_verifier.issuer}")

    # Auth0 requires audience parameter for JWT issuance
    auth = OAuthProxy(
        upstream_authorization_endpoint=config.get("authorization_endpoint", f"https://{domain}/authorize"),
        upstream_token_endpoint=config.get("token_endpoint", f"https://{domain}/oauth/token"),
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=token_verifier,
        base_url=AnyHttpUrl(mcp_base_url),
        extra_authorize_params={"audience": audience},
        extra_token_params={"audience": audience},
        valid_scopes=["openid", "profile", "email"]
    )

    logger.info("✓ OAuthProxy successfully initialized with Auth0")
    return auth


def _create_keycloak_provider(config: Dict[str, Any], mcp_base_url: str) -> Optional[OAuthProxy]:
    """Create OAuthProxy for Keycloak."""
    server_url = config.get("server_url")
    realm = config.get("realm")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    logger.info("Keycloak Configuration:")
    logger.info(f"  Server URL: {server_url}")
    logger.info(f"  Realm: {realm}")
    logger.info(f"  Client ID: {client_id}")
    logger.info(f"  Client Secret: {'***REDACTED***' if client_secret else 'MISSING'}")

    if not all([server_url, realm, client_id, client_secret]):
        missing = []
        if not server_url: missing.append("server_url")
        if not realm: missing.append("realm")
        if not client_id: missing.append("client_id")
        if not client_secret: missing.append("client_secret")
        logger.error(f"✗ Missing required Keycloak configuration: {', '.join(missing)}")
        return None

    # Build Keycloak endpoints
    base = f"{server_url}/realms/{realm}"
    auth_endpoint = config.get("authorization_endpoint", f"{base}/protocol/openid-connect/auth")
    token_endpoint = config.get("token_endpoint", f"{base}/protocol/openid-connect/token")
    jwks_uri = config.get("jwks_uri", f"{base}/protocol/openid-connect/certs")
    issuer = config.get("issuer", base)

    token_verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=client_id  # Keycloak uses client_id as audience
    )

    logger.info("✓ JWTVerifier configured")
    logger.info(f"  JWKS URI: {jwks_uri}")
    logger.info(f"  Issuer: {issuer}")

    auth = OAuthProxy(
        upstream_authorization_endpoint=auth_endpoint,
        upstream_token_endpoint=token_endpoint,
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=token_verifier,
        base_url=AnyHttpUrl(mcp_base_url),
        extra_authorize_params=config.get("extra_authorize_params", {}),
        extra_token_params=config.get("extra_token_params", {}),
        valid_scopes=["openid", "profile", "email"]
    )

    logger.info("✓ OAuthProxy successfully initialized with Keycloak")
    return auth


def _create_okta_provider(config: Dict[str, Any], mcp_base_url: str) -> Optional[OAuthProxy]:
    """Create OAuthProxy for Okta."""
    domain = config.get("domain")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    logger.info("Okta Configuration:")
    logger.info(f"  Domain: {domain}")
    logger.info(f"  Client ID: {client_id}")
    logger.info(f"  Client Secret: {'***REDACTED***' if client_secret else 'MISSING'}")

    if not all([domain, client_id, client_secret]):
        missing = []
        if not domain: missing.append("domain")
        if not client_id: missing.append("client_id")
        if not client_secret: missing.append("client_secret")
        logger.error(f"✗ Missing required Okta configuration: {', '.join(missing)}")
        return None

    # Build Okta endpoints
    auth_endpoint = config.get("authorization_endpoint", f"https://{domain}/oauth2/v1/authorize")
    token_endpoint = config.get("token_endpoint", f"https://{domain}/oauth2/v1/token")
    jwks_uri = config.get("jwks_uri", f"https://{domain}/oauth2/v1/keys")
    issuer = config.get("issuer", f"https://{domain}")
    audience = config.get("audience", "api://default")

    token_verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience
    )

    logger.info("✓ JWTVerifier configured")
    logger.info(f"  JWKS URI: {jwks_uri}")
    logger.info(f"  Issuer: {issuer}")

    auth = OAuthProxy(
        upstream_authorization_endpoint=auth_endpoint,
        upstream_token_endpoint=token_endpoint,
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=token_verifier,
        base_url=AnyHttpUrl(mcp_base_url),
        extra_authorize_params=config.get("extra_authorize_params", {}),
        extra_token_params=config.get("extra_token_params", {}),
        valid_scopes=["openid", "profile", "email"]
    )

    logger.info("✓ OAuthProxy successfully initialized with Okta")
    return auth


def _create_generic_oidc_provider(config: Dict[str, Any], mcp_base_url: str) -> Optional[OAuthProxy]:
    """Create OAuthProxy for any generic OIDC-compliant provider."""
    auth_endpoint = config.get("authorization_endpoint")
    token_endpoint = config.get("token_endpoint")
    jwks_uri = config.get("jwks_uri")
    issuer = config.get("issuer")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    audience = config.get("audience", client_id)

    logger.info("Generic OIDC Configuration:")
    logger.info(f"  Authorization Endpoint: {auth_endpoint}")
    logger.info(f"  Token Endpoint: {token_endpoint}")
    logger.info(f"  JWKS URI: {jwks_uri}")
    logger.info(f"  Issuer: {issuer}")
    logger.info(f"  Client ID: {client_id}")
    logger.info(f"  Audience: {audience}")

    if not all([auth_endpoint, token_endpoint, jwks_uri, issuer, client_id, client_secret]):
        missing = []
        if not auth_endpoint: missing.append("authorization_endpoint")
        if not token_endpoint: missing.append("token_endpoint")
        if not jwks_uri: missing.append("jwks_uri")
        if not issuer: missing.append("issuer")
        if not client_id: missing.append("client_id")
        if not client_secret: missing.append("client_secret")
        logger.error(f"✗ Missing required OIDC configuration: {', '.join(missing)}")
        return None

    token_verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience
    )

    logger.info("✓ JWTVerifier configured")

    auth = OAuthProxy(
        upstream_authorization_endpoint=auth_endpoint,
        upstream_token_endpoint=token_endpoint,
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=token_verifier,
        base_url=AnyHttpUrl(mcp_base_url),
        extra_authorize_params=config.get("extra_authorize_params", {}),
        extra_token_params=config.get("extra_token_params", {}),
        valid_scopes=config.get("valid_scopes", ["openid", "profile", "email"])
    )

    logger.info("✓ OAuthProxy successfully initialized with Generic OIDC")
    return auth


def _create_auth0_from_env(mcp_base_url: str) -> Optional[OAuthProxy]:
    """Legacy: Create OAuthProxy from Auth0 environment variables."""
    auth0_domain = os.getenv("AUTH0_DOMAIN")
    auth0_audience = os.getenv("AUTH0_AUDIENCE")
    auth0_client_id = os.getenv("AUTH0_CLIENT_ID")
    auth0_client_secret = os.getenv("AUTH0_CLIENT_SECRET")

    logger.info("Auth0 Configuration (from environment):")
    logger.info(f"  AUTH0_DOMAIN={auth0_domain}")
    logger.info(f"  AUTH0_AUDIENCE={auth0_audience}")
    logger.info(f"  AUTH0_CLIENT_ID={'*' * 8 + (auth0_client_id[-8:] if auth0_client_id else 'MISSING')}")
    logger.info(f"  AUTH0_CLIENT_SECRET={'***REDACTED***' if auth0_client_secret else 'MISSING'}")
    logger.info(f"  MCP_BASE_URL={mcp_base_url}")

    if not all([auth0_domain, auth0_audience, auth0_client_id, auth0_client_secret]):
        missing = []
        if not auth0_domain: missing.append("AUTH0_DOMAIN")
        if not auth0_audience: missing.append("AUTH0_AUDIENCE")
        if not auth0_client_id: missing.append("AUTH0_CLIENT_ID")
        if not auth0_client_secret: missing.append("AUTH0_CLIENT_SECRET")
        logger.error(f"✗ Missing required Auth0 configuration: {', '.join(missing)}")
        return None

    logger.info("✓ All Auth0 environment variables present")

    # Configure JWT token validation using Auth0's JWKS
    token_verifier = JWTVerifier(
        jwks_uri=f"https://{auth0_domain}/.well-known/jwks.json",
        issuer=f"https://{auth0_domain}/",
        audience=auth0_audience
    )
    logger.info(f"✓ JWTVerifier configured")
    logger.info(f"  JWKS URI: https://{auth0_domain}/.well-known/jwks.json")
    logger.info(f"  Issuer: https://{auth0_domain}/")

    # Create OAuth Proxy wrapping Auth0
    auth = OAuthProxy(
        upstream_authorization_endpoint=f"https://{auth0_domain}/authorize",
        upstream_token_endpoint=f"https://{auth0_domain}/oauth/token",
        upstream_client_id=auth0_client_id,
        upstream_client_secret=auth0_client_secret,
        token_verifier=token_verifier,
        base_url=AnyHttpUrl(mcp_base_url),
        extra_authorize_params={"audience": auth0_audience},
        extra_token_params={"audience": auth0_audience},
        valid_scopes=["openid", "profile", "email"]
    )

    logger.info("✓ OAuthProxy successfully initialized with Auth0 (legacy env vars)")
    return auth


class HybridAuthProvider(OAuthProxy):
    """
    Hybrid authentication provider supporting both OAuth 2.1 and API keys.

    This provider extends OAuthProxy to add API key fallback authentication.
    When both OAuth and API keys are configured, it:
    1. Provides full OAuth 2.1 endpoints (DCR, authorize, token, etc.)
    2. Falls back to API key validation if OAuth token verification fails

    This allows:
    - OAuth 2.1 (via OAuthProxy) for interactive users
    - Static API keys (via StaticTokenVerifier) for service accounts and automation

    Authentication is attempted in order:
    1. OAuth JWT token validation (if OAuth configured)
    2. Static API key validation (if API keys configured)

    Usage:
        Configure via environment variables:
        - MCP_AUTH_PROVIDER=oauth_proxy (enables OAuth)
        - MCP_API_KEYS="key1:client1,key2:client2" (enables API keys)

        Both can be enabled simultaneously for maximum flexibility.
    """

    def __init__(self, oauth_proxy: OAuthProxy, api_keys: Optional[Dict[str, Dict[str, Any]]]):
        """
        Initialize hybrid authentication provider.

        Args:
            oauth_proxy: OAuthProxy instance for OAuth 2.1 authentication (required)
            api_keys: Optional dict mapping API key strings to their claims
                     Format: {"api-key-string": {"client_id": "user", "scopes": ["*"]}}
        """
        # Copy all attributes from the OAuthProxy instance
        self.__dict__.update(oauth_proxy.__dict__)

        # Store reference to OAuth proxy for verify_token delegation
        self._oauth_proxy = oauth_proxy

        # Create API key verifier if keys provided
        self.api_key_verifier = None
        if api_keys:
            self.api_key_verifier = StaticTokenVerifier(
                tokens=api_keys,
                required_scopes=None
            )
            logger.info(f"✓ API key authentication enabled ({len(api_keys)} keys configured)")

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify authentication token using OAuth or API key validation.

        Args:
            token: Bearer token from Authorization header

        Returns:
            AccessToken with claims if valid, None otherwise
        """
        # Try OAuth JWT validation first using the parent OAuthProxy
        try:
            result = await self._oauth_proxy.verify_token(token)
            if result:
                logger.debug(f"Token verified via OAuth for client: {result.client_id}")

                # TODO: Implement user whitelist check here
                # Load users.json and verify result.client_id (or custom claim for email)
                # is in the allowed users list. If not, return None to reject the token.
                # Example:
                # allowed_users = load_users()
                # if result.client_id not in allowed_users:
                #     logger.warning(f"User {result.client_id} not in whitelist")
                #     return None

                return result
        except Exception as e:
            logger.debug(f"OAuth token verification failed: {e}")

        # Fall back to API key validation
        if self.api_key_verifier:
            try:
                result = await self.api_key_verifier.verify_token(token)
                if result:
                    logger.debug(f"Token verified via API key for client: {result.client_id}")

                    # TODO: Optionally check API key client_id against whitelist as well

                    return result
            except Exception as e:
                logger.debug(f"API key verification failed: {e}")

        logger.debug("Token verification failed for all methods")
        return None


def load_api_keys() -> Optional[Dict[str, Dict[str, Any]]]:
    """
    Load API keys from environment variable or JSON file.

    Supports two formats:
    1. Environment variable (MCP_API_KEYS): "key1:client1,key2:client2"
    2. JSON file (MCP_API_KEYS_PATH): {"key1": {"client_id": "client1", "scopes": ["*"]}}

    Returns:
        Dict mapping API key strings to their claims, or None if not configured
    """
    # Try environment variable first
    api_keys_str = os.getenv("MCP_API_KEYS")
    if api_keys_str:
        api_keys = {}
        try:
            for entry in api_keys_str.split(","):
                entry = entry.strip()
                if ":" not in entry:
                    logger.warning(f"Invalid API key entry format (missing ':'): {entry}")
                    continue

                key, client_id = entry.split(":", 1)
                api_keys[key.strip()] = {
                    "client_id": client_id.strip(),
                    "scopes": ["*"]
                }

            if api_keys:
                logger.info(f"✓ Loaded {len(api_keys)} API keys from MCP_API_KEYS")
                logger.info(f"  Clients: {', '.join([v['client_id'] for v in api_keys.values()])}")
                return api_keys
        except Exception as e:
            logger.error(f"Failed to parse MCP_API_KEYS: {e}")
            return None

    # Try JSON file
    api_keys_path = os.getenv("MCP_API_KEYS_PATH")
    if api_keys_path:
        abs_path = os.path.abspath(api_keys_path)
        try:
            with open(api_keys_path, 'r') as f:
                api_keys = json.load(f)

            logger.info(f"✓ Loaded {len(api_keys)} API keys from {abs_path}")
            logger.info(f"  Clients: {', '.join([v.get('client_id', 'unknown') for v in api_keys.values()])}")
            return api_keys
        except FileNotFoundError:
            logger.warning(f"API keys file not found at {abs_path}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in API keys file at {abs_path}: {e}")
            return None

    return None


def expand_env_vars(value: Any) -> Any:
    """
    Recursively expand environment variables in configuration values.
    
    Supports ${VAR_NAME} syntax for environment variable substitution.
    Falls back to empty string if variable is not set.
    
    Args:
        value: Configuration value to expand (can be str, dict, list, or other)
        
    Returns:
        Value with environment variables expanded
        
    Examples:
        "${HOME}/data" -> "/home/user/data"
        {"key": "${API_KEY}"} -> {"key": "actual-api-key-value"}
        ["${VAR1}", "${VAR2}"] -> ["value1", "value2"]
    """
    if isinstance(value, str):
        # Pattern matches ${VAR_NAME} with optional fallback ${VAR_NAME:-default}
        def replace_var(match):
            var_name = match.group(1)
            default_value = match.group(2) if match.lastindex >= 2 else ""
            env_value = os.getenv(var_name)
            
            if env_value is None:
                if default_value:
                    logger.debug(f"Environment variable ${{{var_name}}} not set, using default: {default_value}")
                    return default_value
                else:
                    logger.warning(f"Environment variable ${{{var_name}}} not set, using empty string")
                    return ""
            
            return env_value
        
        # Support both ${VAR} and ${VAR:-default} syntax
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*?)(?::-([^}]*))?\}', replace_var, value)
    
    elif isinstance(value, dict):
        return {key: expand_env_vars(val) for key, val in value.items()}
    
    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    
    else:
        # Return as-is for other types (int, bool, None, etc.)
        return value


class ConfigFileHandler(FileSystemEventHandler):
    """
    File system event handler for monitoring MCP configuration file changes.

    This handler watches for changes to the configuration file and triggers
    a server reload when modifications are detected. It includes debouncing
    to handle editors that save files multiple times in quick succession.

    Features:
    - Debounced reload to prevent multiple rapid reloads
    - Handles file modification, creation, moves, and deletion
    - Works with editors that use atomic saves (temp file + rename)
    """

    def __init__(self, config_path: str, reload_callback):
        """
        Initialize the config file handler.

        Args:
            config_path: Path to the configuration file to monitor
            reload_callback: Function to call when reload should be triggered
        """
        self.config_path = Path(config_path).resolve()
        self.reload_callback = reload_callback
        self.debounce_timer = None
        self.debounce_delay = 1.0  # Wait 1 second after last change to avoid rapid reloads

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        # Check if the modified file is our config file
        if Path(event.src_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_moved(self, event):
        """
        Handle file move/rename events.

        Many editors save files atomically by writing to a temp file
        and then renaming it to the target file.
        """
        if event.is_directory:
            return

        # Handle file renames/moves that affect our config
        if Path(event.dest_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return

        # Handle config file recreation (after deletion)
        if Path(event.src_path).resolve() == self.config_path:
            logger.info(f"Config file {self.config_path} was recreated")
            self._debounced_reload()

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return

        # Handle config file deletion
        if Path(event.src_path).resolve() == self.config_path:
            logger.warning(f"Config file {self.config_path} was deleted")
            # Don't trigger reload on deletion - wait for recreation

    def _debounced_reload(self):
        """
        Implement debouncing to prevent multiple rapid reloads.

        Some editors and file operations can trigger multiple filesystem
        events in quick succession. This method ensures we only reload
        once after the events have settled.
        """
        if self.debounce_timer:
            self.debounce_timer.cancel()

        self.debounce_timer = threading.Timer(self.debounce_delay, self._trigger_reload)
        self.debounce_timer.start()

    def _trigger_reload(self):
        """Execute the actual reload callback."""
        logger.info(f"Config file {self.config_path} changed, triggering reload...")
        self.reload_callback()

class ResilientMCPProxy:
    """
    A resilient MCP proxy server with automatic restart and live reload capabilities.

    This class manages the lifecycle of a FastMCP proxy server, providing:
    - Automatic restart on crashes with exponential backoff
    - Live configuration reloading via file system monitoring
    - Graceful shutdown handling with signal management
    - Retry logic for configuration loading
    - Port availability checking before restart

    The proxy creates a single FastMCP instance that can proxy multiple
    MCP servers as defined in the configuration file.
    """

    def __init__(self, config_path: str, max_retries: int = 3, restart_delay: int = 5, enable_live_reload: bool = True, path_prefix: str = "", host: str = "0.0.0.0", port: int = 8080):
        """
        Initialize the resilient MCP proxy.

        Args:
            config_path: Path to the JSON configuration file
            max_retries: Maximum number of retries for config loading
            restart_delay: Initial delay between restarts (seconds)
            enable_live_reload: Whether to enable live config reloading
            path_prefix: Optional URL path prefix (e.g., "abc123" creates /abc123/mcp/ endpoints)
            host: Host address to bind to (default: 0.0.0.0)
            port: Port number to bind to (default: 8080)
        """
        # Configuration settings
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload
        self.path_prefix = f"/{path_prefix.strip('/')}" if path_prefix else ""
        self.host = host
        self.port = port

        # Runtime state
        self.proxy: Optional[FastMCP] = None
        self.shutdown_requested = False
        self.reload_requested = False
        self.config = None

        # File watching components
        self.file_observer: Optional[Observer] = None
        self.config_handler: Optional[ConfigFileHandler] = None

    def wait_for_port_available(self, timeout: int = 10):
        """
        Wait for a network port to become available.

        This is crucial for live reloading since the previous server process
        may take time to release the port after termination.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            bool: True if port becomes available, False on timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Attempt to bind to the port to test availability
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((self.host, self.port))
                    logger.info(f"✓ Port {self.port} is available")
                    return True
            except OSError:
                # Port still in use, wait a bit more
                logger.info(f"Port {self.port} still in use, waiting...")
                time.sleep(0.5)

        logger.warning(f"Port {self.port} did not become available within {timeout} seconds")
        return False

    def setup_signal_handlers(self):
        """
        Configure signal handlers for graceful shutdown.

        Handles SIGTERM (container stop) and SIGINT (Ctrl+C) to ensure
        the server shuts down cleanly and releases resources.
        """
        def signal_handler(signum, _frame):
            """Handle shutdown signals gracefully."""
            signal_name = signal.Signals(signum).name
            logger.info(f"Received {signal_name}, initiating graceful shutdown...")
            self.shutdown_requested = True

        # Register handlers for common shutdown signals
        signal.signal(signal.SIGTERM, signal_handler)  # Docker stop
        signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C

    def setup_file_watcher(self):
        """
        Initialize file system monitoring for live configuration reloading.

        Sets up a watchdog observer to monitor the config file directory
        for changes. When changes are detected, triggers a server reload.
        """
        if not self.enable_live_reload:
            return

        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Config file {self.config_path} does not exist, file watching disabled")
                return

            # Watch the directory containing the config file (not the file itself)
            # This handles cases where editors create temp files and rename them
            watch_dir = config_file.parent

            # Create handler and observer
            self.config_handler = ConfigFileHandler(self.config_path, self._request_reload)
            self.file_observer = Observer()
            self.file_observer.schedule(self.config_handler, str(watch_dir), recursive=False)
            self.file_observer.start()

            logger.info(f"✓ File watcher enabled for {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to setup file watcher: {e}")
            # Disable live reload if setup fails
            self.enable_live_reload = False

    def stop_file_watcher(self):
        """
        Clean up file system monitoring resources.

        Stops the watchdog observer and cancels any pending debounce timers.
        """
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.file_observer = None

        # Cancel any pending debounce timers
        if self.config_handler and self.config_handler.debounce_timer:
            self.config_handler.debounce_timer.cancel()

        self.config_handler = None

    def _request_reload(self):
        """
        Internal method to request a configuration reload.

        Called by the file watcher when config changes are detected.
        Sets the reload flag which is checked by the monitoring thread.
        """
        if not self.shutdown_requested:
            self.reload_requested = True
            logger.info("Configuration reload requested")

    def load_config_with_retry(self) -> bool:
        """
        Load and validate the MCP configuration with retry logic, including JSON schema validation.

        Implements exponential backoff retry strategy for transient errors
        while immediately failing for permanent errors like file not found or schema validation errors.

        Returns:
            bool: True if config was loaded and validated successfully, False otherwise
        """
        # Schema is always in the same directory as this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(script_dir, "mcp_config.schema.json")

        logger.info(f"Loading configuration from: {os.path.abspath(self.config_path)}")

        try:
            with open(schema_path, "r") as sf:
                schema = json.load(sf)
            logger.info(f"✓ Loaded schema from: {schema_path}")
        except Exception as e:
            logger.error(f"✗ Failed to load config schema from {schema_path}: {e}")
            return False

        for attempt in range(self.max_retries):
            try:
                abs_config_path = os.path.abspath(self.config_path)
                logger.info(f"Attempting to load config from {abs_config_path} (attempt {attempt + 1}/{self.max_retries})")

                # Read and parse JSON configuration
                with open(self.config_path, 'r') as f:
                    raw_config = json.load(f)
                logger.info(f"✓ Loaded config file from {abs_config_path}")

                # Expand environment variables in the config
                self.config = expand_env_vars(raw_config)

                # Validate config against schema
                jsonschema.validate(instance=self.config, schema=schema)

                server_count = len(self.config['mcpServers'])
                logger.info(f"✓ Successfully loaded and validated configuration with {server_count} servers")
                return True

            except FileNotFoundError:
                # File not found is a permanent error - don't retry
                logger.error(f"Configuration file not found: {self.config_path}")
                return False
            except json.JSONDecodeError as e:
                # JSON syntax errors are permanent - don't retry
                logger.error(f"Invalid JSON in config file: {e}")
                return False
            except jsonschema.ValidationError as e:
                logger.error(f"Config schema validation failed: {e.message}")
                return False
            except Exception as e:
                # Other errors might be transient - retry with backoff
                logger.error(f"Config load attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s, 8s...
                    backoff_time = 2 ** attempt
                    logger.info(f"Retrying in {backoff_time} seconds...")
                    time.sleep(backoff_time)
                else:
                    logger.error("Failed to load config after all retries")

        return False

    def create_proxy(self) -> bool:
        """
        Create a single unified FastMCP proxy with all configured MCP servers aggregated.
        All servers are available through a single /mcp/ endpoint.
        Returns True if proxy created successfully, False otherwise.
        """
        try:
            mcp_servers = self.config.get("mcpServers", {})
            if not mcp_servers:
                logger.error("No MCP servers configured!")
                return False

            # Create OAuthProxy (or None if not configured)
            oauth_provider = create_auth_provider()

            # Load API keys (or None if not configured)
            api_keys = load_api_keys()

            # Create auth provider based on configuration
            auth = None
            if oauth_provider and api_keys:
                # Both OAuth and API keys configured - use hybrid
                auth = HybridAuthProvider(oauth_provider, api_keys)
                logger.info("✓ Hybrid authentication enabled")
                logger.info("  - OAuth 2.1 authentication: enabled")
                logger.info("  - API key authentication: enabled")
            elif oauth_provider:
                # OAuth only
                auth = oauth_provider
                logger.info("✓ OAuth 2.1 authentication enabled")
            elif api_keys:
                # API keys only
                auth = StaticTokenVerifier(tokens=api_keys, required_scopes=None)
                logger.info("✓ API key authentication enabled")
                logger.info(f"  - {len(api_keys)} API keys configured")
            else:
                # No authentication configured
                disable_auth = os.getenv("MCP_DISABLE_AUTH", "false").lower() in ("true", "1", "yes")

                if not disable_auth:
                    logger.error("Authentication is required but not properly configured.")
                    logger.error("Set either:")
                    logger.error("  - MCP_AUTH_PROVIDER=oauth_proxy with OAuth credentials")
                    logger.error("  - MCP_API_KEYS=key1:client1,key2:client2 for API key auth")
                    logger.error("  - MCP_DISABLE_AUTH=true to disable (NOT RECOMMENDED)")
                    return False
                else:
                    logger.warning("⚠️  WARNING: Authentication is DISABLED - server is not protected!")

            # Create SINGLE unified FastMCP instance with all servers
            try:
                proxy_config = {"mcpServers": mcp_servers}
                self.proxy = FastMCP.as_proxy(
                    proxy_config,
                    name="mcp-proxy",
                    auth=auth
                )

                # Add health check endpoint
                @self.proxy.custom_route("/health", methods=["GET"])
                async def health_check(request):
                    # If CF-Ray header present, request came through Cloudflare (external)
                    # If no CF-Ray, assume local/Docker request (internal)
                    cf_ray = request.headers.get("CF-Ray")

                    response = {
                        "status": "healthy",
                        "service": "mcp-proxy"
                    }

                    # Only include server list if NOT from Cloudflare (local/internal requests)
                    if not cf_ray:
                        response["servers"] = list(mcp_servers.keys())

                    return JSONResponse(response)

                server_count = len(mcp_servers)
                server_names = ", ".join(mcp_servers.keys())
                logger.info(f"✓ Created unified FastMCP proxy with {server_count} server(s)")
                logger.info(f"  Servers: {server_names}")
                logger.info(f"  Endpoints: /mcp/ (MCP), /health (health check)")

                return True

            except Exception as e:
                logger.error(f"Failed to create FastMCP proxy: {e}", exc_info=True)
                return False

        except Exception as e:
            logger.error(f"Failed to create proxy: {e}", exc_info=True)
            return False

    def run_server(self):
        """Run FastMCP server using native HTTP transport."""
        try:
            logger.info(f"Starting unified FastMCP proxy on {self.host}:{self.port}")
            logger.info(f"  Endpoint: / (root)")
            self.proxy.run(
                transport="http",
                host=self.host,
                port=self.port
            )
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def run_server_with_reload(self):
        """Run FastMCP server with reload support - triggers process exit on config change"""
        try:
            # Start monitoring in a separate thread
            monitor_thread = threading.Thread(target=self._monitor_for_reload, daemon=True)
            monitor_thread.start()
            logger.info(f"Starting unified FastMCP proxy on {self.host}:{self.port} with live reload")
            logger.info(f"  Endpoint: / (root)")
            self.proxy.run(
                transport="http",
                host=self.host,
                port=self.port
            )
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def _monitor_for_reload(self):
        """
        Background thread to monitor for configuration reload requests.
        When a reload is requested, set a restart_requested flag and shut down the server gracefully.
        """
        while not self.shutdown_requested:
            if self.reload_requested:
                logger.info("Config reload detected, requesting graceful restart...")
                self.restart_requested = True
                # Trigger shutdown of the server (uvicorn)
                import threading
                def shutdown():
                    import sys
                    import os
                    import signal
                    os.kill(os.getpid(), signal.SIGINT)
                threading.Thread(target=shutdown, daemon=True).start()
                break
            time.sleep(0.5)

    def run_with_restart(self):
        """
        Main server loop with automatic restart and error recovery.
        Implements graceful reload instead of os._exit().
        """
        self.setup_signal_handlers()

        version_info = get_version_info()
        logger.info(f"Starting MCP Proxy Server v{version_info['full']}")
        logger.info("Starting resilient MCP proxy...")

        restart_count = 0

        while not self.shutdown_requested:
            self.restart_requested = False
            try:
                if not self.load_config_with_retry():
                    logger.error("Cannot start without valid configuration")
                    sys.exit(1)

                if not self.create_proxy():
                    logger.error("Cannot start without valid proxy")
                    sys.exit(1)

                self.setup_file_watcher()

                if restart_count > 0:
                    logger.info(f"Successfully restarted after {restart_count} attempts")
                restart_count = 0

                self.run_server_with_reload()

                self.stop_file_watcher()

                # If reload was requested, wait for port and restart
                if self.restart_requested:
                    logger.info("Graceful reload requested, restarting with new configuration...")
                    if not self.wait_for_port_available():
                        logger.error("Port did not become available, skipping reload")
                        break
                    continue
                else:
                    break

            except Exception as e:
                restart_count += 1
                logger.error(f"Server crashed (restart #{restart_count}): {e}", exc_info=True)
                if self.shutdown_requested:
                    logger.info("Shutdown requested, not restarting")
                    break
                if restart_count >= 10:
                    logger.error("Too many restart attempts, giving up")
                    sys.exit(1)
                logger.info(f"Restarting server in {self.restart_delay} seconds...")
                time.sleep(self.restart_delay)
                self.restart_delay = min(self.restart_delay * 1.5, 30)

        logger.info("Proxy server shutdown complete")
        self.stop_file_watcher()

def main():
    """
    Application entry point and configuration setup.

    Reads configuration from environment variables, creates the resilient
    proxy instance, and starts the main server loop. This function handles
    the initial setup and delegates the complex server management to the
    ResilientMCPProxy class.

    Environment Variables:
        MCP_CONFIG_PATH: Path to JSON config file (default: mcp_config.json)
        MCP_MAX_RETRIES: Config load retry attempts (default: 3)
        MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
        MCP_LIVE_RELOAD: Enable file watching (default: false)
        MCP_PATH_PREFIX: Custom path prefix (default: none, creates /mcp/ endpoint)
                         Example: "3434dc5d-349b-401c-8071-7589df9a0bce" creates /3434dc5d-349b-401c-8071-7589df9a0bce/mcp/
    """
    # Read configuration from environment variables with sensible defaults
    config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")
    max_retries = int(os.getenv("MCP_MAX_RETRIES", "3"))
    restart_delay = int(os.getenv("MCP_RESTART_DELAY", "5"))
    path_prefix = os.getenv("MCP_PATH_PREFIX", "")
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8080"))

    # Parse boolean environment variable for live reload
    # Accepts: true, 1, yes (case insensitive)
    enable_live_reload = os.getenv("MCP_LIVE_RELOAD", "false").lower() in ("true", "1", "yes")

    # Create and configure the resilient proxy instance
    proxy = ResilientMCPProxy(
        config_path=config_path,
        max_retries=max_retries,
        restart_delay=restart_delay,
        enable_live_reload=enable_live_reload,
        path_prefix=path_prefix,
        host=host,
        port=port
    )

    # Start the main server loop with all resilience features
    proxy.run_with_restart()


if __name__ == "__main__":
    # Entry point when script is run directly (not imported)
    main()
