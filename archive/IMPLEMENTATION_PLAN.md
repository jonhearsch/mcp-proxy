# OAuth-Only Simplification Plan (Google OAuth)

**Date**: 2026-01-19
**Goal**: Remove all API key authentication and implement Google OAuth-only authentication for Claude.ai integration

## Background

- Initially tried key-based auth for Letta (didn't work as desired)
- Added HybridAuthProvider (never worked correctly)
- Switched to key-based only temporarily
- Now returning to OAuth-only plan for Claude.ai integration
- **Changed from Auth0 to Google OAuth** (simpler, direct integration)

## Current State (v2.0-oauth tag - commit 274e6ea)

**Issues:**
1. HybridAuthProvider is disabled due to JWT issuer initialization bugs
2. Mixed authentication logic (OAuth + API keys) adds complexity
3. Uses older FastMCP patterns (pre-v2.14 style)
4. Custom OAuth provider functions (~330 lines) for Auth0/Keycloak/Okta

## Implementation Strategy

### Use FastMCP's Built-in GoogleProvider

FastMCP v2.12.0+ includes a native `GoogleProvider` class:

```python
from fastmcp.server.auth.providers.google import GoogleProvider

auth = GoogleProvider(
    client_id="123456789.apps.googleusercontent.com",
    client_secret="GOCSPX-abc123...",
    base_url="https://your-server.com",
    required_scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
    jwt_signing_key=os.environ.get("JWT_SIGNING_KEY"),  # Production
)

proxy = FastMCP.as_proxy(config, auth=auth, name="mcp-proxy")
```

### Why GoogleProvider vs OIDCProxy

- **Built-in optimization** for Google OAuth quirks
- **Tested and maintained** by FastMCP team
- **Simpler API** - no need to specify .well-known URLs
- **Compatible** with Claude.ai, Claude Code, ChatGPT

---

## Implementation Steps

### Phase 1: Update Dependencies

**File**: `requirements.txt`

```
fastmcp[auth]>=2.14.0,<3
python-dotenv
watchdog
jsonschema
```

### Phase 2: Remove API Key Authentication

**Remove from `proxy_server.py`:**
1. `load_api_keys()` function (lines 647-701)
2. `HybridAuthProvider` class (lines 551-644)
3. `load_users()` function (lines 160-186)
4. `load_auth_config()` function (lines 189-220)
5. `expand_env_vars()` function (lines 704-750)
6. All custom OAuth provider functions (lines 223-548):
   - `create_auth_provider()`
   - `_create_auth0_provider()`
   - `_create_keycloak_provider()`
   - `_create_okta_provider()`
   - `_create_generic_oidc_provider()`
   - `_create_auth0_from_env()`

**Total removal**: ~735 lines

### Phase 3: Add Google OAuth Provider

**Replace imports** (lines 26-44):
```python
from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
# Remove: OAuthProxy, AccessToken, TokenVerifier, JWTVerifier, StaticTokenVerifier
```

**Add new function**:
```python
def create_google_auth() -> Optional[GoogleProvider]:
    """
    Create Google OAuth provider for Claude.ai integration.

    Environment Variables:
        GOOGLE_CLIENT_ID: OAuth 2.0 Client ID from Google Cloud Console
        GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
        MCP_BASE_URL: Public URL of this proxy (for OAuth callback)
        GOOGLE_JWT_KEY: JWT signing key (optional, recommended for production)

    Returns:
        GoogleProvider instance or None if not configured
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    base_url = os.getenv("MCP_BASE_URL")
    jwt_key = os.getenv("GOOGLE_JWT_KEY")

    if not all([client_id, client_secret, base_url]):
        return None

    logger.info(f"Configuring Google OAuth with base URL: {base_url}")

    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        required_scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        jwt_signing_key=jwt_key,
    )
```

### Phase 4: Simplify create_proxy()

**Replace lines 1084-1114** with:
```python
def create_proxy(self) -> bool:
    """Create and configure the FastMCP proxy with Google OAuth authentication."""
    try:
        # Load MCP servers config
        mcp_servers = load_config_with_retry(
            max_retries=int(os.getenv("MCP_MAX_RETRIES", 3)),
            retry_delay=int(os.getenv("MCP_RESTART_DELAY", 5))
        )

        # Create Google OAuth provider (required)
        auth = create_google_auth()

        if not auth:
            logger.error("Google OAuth authentication is required but not configured.")
            logger.error("Set these environment variables:")
            logger.error("  - GOOGLE_CLIENT_ID: OAuth 2.0 Client ID")
            logger.error("  - GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret")
            logger.error("  - MCP_BASE_URL: Public URL of this proxy")
            logger.error("")
            logger.error("Get credentials from: https://console.developers.google.com/")
            return False

        logger.info("✓ Google OAuth authentication enabled (Claude.ai compatible)")

        # Create unified FastMCP proxy
        proxy_config = {"mcpServers": mcp_servers}
        self.proxy = FastMCP.as_proxy(
            proxy_config,
            name="mcp-proxy",
            auth=auth
        )

        # Setup custom routes (health check, etc.)
        self._setup_routes()

        return True

    except Exception as e:
        logger.error(f"Failed to create proxy: {e}")
        return False
```

### Phase 5: Update Module Docstring

**Replace lines 1-24**:
```python
"""
MCP Proxy Server - A resilient proxy server for Model Context Protocol (MCP) servers.

This module provides a robust proxy server that can manage multiple MCP servers
through a single FastMCP endpoint with Google OAuth authentication. Features:

- Automatic restart on crashes with exponential backoff
- Live configuration reloading via file system monitoring
- Graceful shutdown handling (SIGTERM, SIGINT)
- Port availability checking before restart
- Google OAuth 2.0 authentication (Claude.ai compatible)
- Multi-transport support (stdio, SSE, HTTP)

Environment Variables:
    # Google OAuth (Required)
    GOOGLE_CLIENT_ID: OAuth 2.0 Client ID from Google Cloud Console
    GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
    MCP_BASE_URL: Public URL for OAuth callbacks
    GOOGLE_JWT_KEY: JWT signing key (optional, recommended for production)

    # MCP Proxy Configuration
    MCP_CONFIG_PATH: Path to MCP servers config (default: mcp_config.json)
    MCP_HOST: Server bind address (default: 0.0.0.0)
    MCP_PORT: Server bind port (default: 8080)
    MCP_LIVE_RELOAD: Enable live config reloading (default: false)
    MCP_PATH_PREFIX: Custom path prefix for MCP endpoint (default: none)

    # Server Resilience
    MCP_MAX_RETRIES: Config load retry attempts (default: 3)
    MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
"""
```

### Phase 6: Update Configuration Files

**`.env.example`**:
```bash
# Google OAuth Configuration (Required)
GOOGLE_CLIENT_ID=123456789.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123def456
MCP_BASE_URL=https://your-domain.com
GOOGLE_JWT_KEY=your_jwt_signing_key_32_bytes  # Optional, for production

# MCP Proxy Configuration
MCP_CONFIG_PATH=mcp_config.json
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_LIVE_RELOAD=true
MCP_PATH_PREFIX=  # Optional: custom path prefix for security

# Logging
MCP_LOG_LEVEL=INFO
```

---

## Google Cloud Console Setup

### Step-by-Step:

1. **Go to Google Cloud Console**: https://console.developers.google.com/

2. **Create/Select Project**
   - Create new project or select existing

3. **Configure OAuth Consent Screen**
   - Navigate to: APIs & Services → OAuth consent screen
   - Choose "External" (for public) or "Internal" (G Workspace only)
   - Fill in:
     - Application name: "MCP Proxy"
     - User support email: your@email.com
     - Developer contact: your@email.com
   - Add scopes: `openid`, `email`

4. **Create OAuth Client ID**
   - Navigate to: APIs & Services → Credentials
   - Click: "+ CREATE CREDENTIALS" → "OAuth client ID"
   - Application type: "Web application"
   - Name: "MCP Proxy Production"
   - **Authorized JavaScript origins**:
     - Production: `https://your-domain.com`
     - Local: `http://localhost:8080`
   - **Authorized redirect URIs**:
     - Production: `https://your-domain.com/auth/callback`
     - Local: `http://localhost:8080/auth/callback`
   - Click "CREATE"

5. **Copy Credentials**
   - Copy Client ID (ends with `.apps.googleusercontent.com`)
   - Copy Client Secret (starts with `GOCSPX-`)
   - Save to `.env` file

### Critical Notes:

- **HTTPS required for production** (except localhost)
- **Redirect URI must match exactly** - include port if non-standard
- **JavaScript origins required** for Claude/ChatGPT connectors
- Google does NOT support Dynamic Client Registration (FastMCP handles this via OAuth Proxy)

---

## Testing

### Local Testing:

```bash
# 1. Set environment variables
export GOOGLE_CLIENT_ID="123456789.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-abc123..."
export MCP_BASE_URL="http://localhost:8080"

# 2. Start proxy
python proxy_server.py

# Expected output:
# ✓ Google OAuth authentication enabled (Claude.ai compatible)
# ✓ Loaded configuration from mcp_config.json
# Server running at http://0.0.0.0:8080

# 3. Test OAuth endpoints
curl http://localhost:8080/.well-known/oauth-authorization-server

# 4. Test DCR endpoint
curl -X POST http://localhost:8080/dcr \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost"]}'

# 5. Test health check
curl http://localhost:8080/health
```

### Claude.ai Integration:

1. Deploy to production with HTTPS
2. Add MCP server in Claude settings:
   - Server URL: `https://your-domain.com/mcp`
3. Complete OAuth flow when prompted
4. Test tool access through Claude interface

### Expected Behavior:

- ✅ Startup shows "✓ Google OAuth authentication enabled"
- ✅ No API key references in logs
- ✅ OAuth endpoints accessible: `/dcr`, `/auth/callback`, `/auth/login`
- ✅ Health check returns successfully
- ✅ Claude.ai completes OAuth flow
- ✅ Tools accessible after authentication

---

## Documentation Updates

### README.md

**Changes:**
- Replace "API Key Authentication" section with "Google OAuth Setup"
- Update Quick Start to use Google Cloud Console
- Remove all API key environment variables
- Add Google OAuth environment variables
- Update deployment examples

### CLAUDE.md

**Changes:**
- Replace "API Key Authentication" section with "Google OAuth Authentication"
- Document `create_google_auth()` function
- Remove references to StaticTokenVerifier, load_api_keys
- Add Google Cloud Console setup guide
- Update environment variables list

### docs/AUTH_PROVIDERS.md

**Simplify to:**
- Google OAuth setup (primary method)
- Note that Auth0/Keycloak/Okta removed (use Google or contribute provider)
- Document FastMCP's GoogleProvider API
- Link to Google Cloud Console docs

---

## Migration Guide

### Breaking Changes:

- ⚠️ **API key authentication removed** - No longer supported
- ⚠️ **MCP_API_KEYS environment variable removed**
- ⚠️ **MCP_DISABLE_AUTH flag removed** - OAuth is required
- ⚠️ **Auth0/Keycloak/Okta providers removed** - Use Google OAuth
- ⚠️ **auth_config.json no longer supported** - Use environment variables

### For Existing Users:

1. Create Google Cloud OAuth application
2. Update environment variables:
   - Remove: `MCP_API_KEYS`, `MCP_AUTH_PROVIDER`
   - Add: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`
3. Update deployment configs (Docker, Kubernetes, etc.)
4. Restart proxy server

### Version Bump:

- **Current**: v2.0.x (OAuth + API keys, HybridAuthProvider)
- **New**: v3.0.0 (Google OAuth only - breaking change)

---

## Summary

### What Gets Removed:
- All API key authentication (~200 lines)
- HybridAuthProvider class (~95 lines)
- Custom OAuth provider functions for Auth0/Keycloak/Okta (~330 lines)
- User whitelist code (~30 lines)
- Helper functions (load_auth_config, expand_env_vars ~80 lines)

**Total: ~735 lines removed**

### What Gets Added:
- Google OAuth provider function (~25 lines)
- Simplified create_proxy() logic (~20 lines)
- Updated documentation (~50 lines)

**Total: ~95 lines added**

### Net Result:
- **~640 line reduction** (48% smaller)
- **Simpler codebase** - single auth method
- **Modern FastMCP v2.14+ patterns**
- **Claude.ai compatible** out of the box
- **Production-ready** with JWT signing support
- **No DCR worries** - FastMCP handles Google's lack of DCR

---

## Additional Resources

- **FastMCP Google OAuth Guide**: https://gofastmcp.com/integrations/google
- **Google OAuth Setup**: https://developers.google.com/identity/protocols/oauth2/web-server
- **Google Cloud Console**: https://console.developers.google.com/
- **FastMCP GitHub**: https://github.com/jlowin/fastmcp
- **Claude.ai MCP Docs**: https://docs.anthropic.com/en/docs/model-context-protocol

---

**Implementation Date**: January 19, 2026
**Target Completion**: Single work session (~2-3 hours)
**Risk Level**: Low (removing broken code, using battle-tested GoogleProvider)
