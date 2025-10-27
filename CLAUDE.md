# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**MCP Proxy Server** is a production-ready, resilient proxy that aggregates multiple Model Context Protocol (MCP) servers through a single unified endpoint with **built-in OAuth 2.1 authentication via Auth0**.

**Key Features:**
- ✅ **Claude Connector Compatible** - Works with Claude's MCP Connector API
- 🔐 **OAuth 2.1 + PKCE** - Secure authentication with Auth0 (or any OAuth 2.1 provider)
- 👤 **User Identity Tracking** - Know which user is accessing which tools
- 🚀 **Multi-Server Aggregation** - Supports stdio-based (uvx/npx), SSE, and Streamable MCP servers
- 🔄 **Live Config Reload** - Update server definitions without restarting
- 🏥 **Resilient** - Automatic restart, exponential backoff, port availability checking

## Architecture

### Core Components

**proxy_server.py** - Main application with key functions and classes:

- `create_auth_provider()` - Initializes OAuth authentication using FastMCP's `OAuthProxy` with Auth0
  - Creates `JWTVerifier` for token validation via Auth0 JWKS endpoint
  - Configures OAuthProxy with Auth0 endpoints, credentials, and audience parameters
  - Enables PKCE forwarding and consent screen for security
- `load_users()` - Loads authorized users from `/data/users.json` (user whitelist)
- `ResilientMCPProxy` - Orchestrates server lifecycle with:
  - Automatic restart on crashes with exponential backoff (max 10 attempts)
  - Live config reloading via file watching
  - Graceful shutdown handling
  - Port availability checking before restart
- `ConfigFileHandler` - Watchdog-based file system monitor with debouncing (1s delay)

**version.py** - Version management with `get_version()` and `get_version_info()` functions. Auto-updated by CI/CD.

**mcp_config.json** - MCP servers configuration (Claude-compatible format):
```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx|uvx",
      "args": ["package-name", "...args"]
    }
  }
}
```

**/data/users.json** - Authorized users whitelist (required for OAuth):
```json
{
  "user@example.com": {
    "name": "User Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  }
}
```

**/data/auth_config.json** - Auth provider configuration (auto-generated):
```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "${AUTH0_DOMAIN}",
    "jwks_uri": "https://${AUTH0_DOMAIN}/.well-known/jwks.json",
    "issuer": "https://${AUTH0_DOMAIN}/",
    "audience": "${AUTH0_AUDIENCE}"
  }
}
```

### Server Lifecycle

1. **Startup** - `ResilientMCPProxy.run_with_restart()` orchestration loop starts
2. **Auth Setup** - `create_auth_provider()` initializes OAuthProxy with Auth0
   - Validates Auth0 environment variables are set
   - Creates JWTVerifier pointing to Auth0 JWKS endpoint
   - Initializes OAuthProxy for DCR and OAuth flow
3. **Config Load** - Configuration loaded with retry logic (`load_config_with_retry()`)
   - Validates JSON schema against `mcp_config.schema.json`
   - Expands environment variables in config
   - Loads user whitelist from `/data/users.json`
4. **FastMCP Creation** - Unified FastMCP instance created via `FastMCP.as_proxy(config, auth=auth)`
   - Single endpoint aggregates all configured MCP servers
   - OAuthProxy middleware handles authentication
5. **HTTP Server** - FastMCP runs native HTTP transport on `0.0.0.0:8080` (or configured host/port)
   - Listens at `/mcp/` endpoint (OAuth discovery at `/.well-known/` endpoints)
6. **File Watching** - Watchdog monitors config directory for changes
   - Debounces events with 1s delay
   - On change, exits with code 42 (triggers clean reload)
7. **Error Handling** - Crashes trigger exponential backoff restart
   - Delays: 1s, 2s, 4s, 8s, 16s, max 30s
   - Max 10 restart attempts
8. **Port Management** - `wait_for_port_available()` checks port before restart
   - Waits up to 10 seconds for port to be available
   - Critical for live reload

### Live Reload Mechanism

- Uses watchdog library to monitor the config file's parent directory
- Debounces events (1 second delay) to handle multiple rapid filesystem events
- Reload triggers `os._exit(42)` to ensure clean port release
- Exit code 42 distinguishes intentional reload from crashes
- `_monitor_for_reload()` runs in daemon thread checking for reload flag

## Development Commands

### Local Development with OAuth

```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env with your Auth0 credentials

# Create data directories
mkdir -p data

# Create authorized users
cat > data/users.json << 'EOF'
{
  "your-email@example.com": {
    "name": "Your Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  }
}
EOF

# Run with OAuth enabled
python proxy_server.py

# Run with live reload enabled
MCP_LIVE_RELOAD=true python proxy_server.py
```

### Docker Development
```bash
# Build locally
docker build -t mcp-proxy .

# Run with custom config
docker run -p 8080:8080 -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro mcp-proxy

# Build multi-arch (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t mcp-proxy .
```

### Testing

```bash
# Check OAuth well-known endpoints
curl http://localhost:8080/.well-known/oauth-protected-resource
curl http://localhost:8080/.well-known/oauth-authorization-server

# Test DCR (Dynamic Client Registration) - should return 201 with credentials
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "test-client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_post"
  }'

# Test MCP endpoint (should be 401 without auth)
curl http://localhost:8080/mcp

# Test with valid token (after OAuth flow)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8080/mcp
```

## Environment Variables

### OAuth Configuration (Required for Authentication)

- `MCP_AUTH_PROVIDER` - Enable OAuth: set to `oauth_proxy` to enable Auth0
- `AUTH0_CLIENT_ID` - Auth0 application client ID (from Dashboard → Applications → Your App)
- `AUTH0_CLIENT_SECRET` - Auth0 application client secret
- `AUTH0_DOMAIN` - Auth0 tenant domain (e.g., `your-tenant.us.auth0.com`)
- `AUTH0_AUDIENCE` - Auth0 API identifier (Audience) - must match configured API

### MCP Proxy Configuration

- `MCP_BASE_URL` - Public URL where proxy is accessible (e.g., `https://mcp.your-domain.com`)
  - **Must match the URL used in Claude Connector**
  - Required for OAuth redirect URI validation
- `MCP_CONFIG_PATH` - Path to MCP servers config (default: `mcp_config.json`)
- `MCP_USERS_PATH` - Path to authorized users whitelist (default: `/data/users.json`)
- `MCP_AUTH_CONFIG_PATH` - Path to auth provider config (default: `/data/auth_config.json`)
- `MCP_HOST` - Bind host address (default: `0.0.0.0`)
- `MCP_PORT` - Bind port (default: `8080`)

### Server Resilience

- `MCP_MAX_RETRIES` - Config load retry attempts (default: 3)
- `MCP_RESTART_DELAY` - Initial restart delay in seconds (default: 5)
- `MCP_LIVE_RELOAD` - Enable live config reload: `true|1|yes` (default: false)

### Optional Security

- `MCP_PATH_PREFIX` - Custom path prefix for MCP endpoint (default: none)
  - Example: `3434dc5d-349b-401c-8071-7589df9a0bce` creates `/3434dc5d-349b-401c-8071-7589df9a0bce/mcp/`
  - Useful for security through obscurity or multi-tenant deployments

## OAuth 2.1 Authentication (Auth0)

### Overview

MCP Proxy uses FastMCP's `OAuthProxy` to wrap Auth0 and provide secure authentication:

1. **Dynamic Client Registration (DCR)** - Claude registers itself and gets fixed Auth0 credentials
2. **Authorization Flow** - User logs into Auth0 with PKCE security
3. **Consent Screen** - User approves which client gets access (prevents confused deputy attacks)
4. **Token Exchange** - Auth0 issues JWT, OAuthProxy wraps in FastMCP JWT
5. **Protected Access** - Subsequent MCP requests validated using JWT signature

### Key Security Features

- **PKCE (Proof Key for Code Exchange)** - End-to-end forwarding prevents token interception
- **JWT Validation** - Tokens validated via Auth0 JWKS endpoint (public key pinning)
- **User Whitelist** - Only users in `/data/users.json` can access tools
- **Consent Screen** - Explicit user approval before client gains access
- **Encrypted Storage** - OAuth tokens encrypted at rest using Fernet encryption
- **Token Expiry** - FastMCP tokens expire when upstream Auth0 tokens expire

### OAuth Endpoints

Automatically provided by OAuthProxy (via FastMCP):

- `POST /.well-known/oauth-protected-resource` - OAuth server metadata
- `GET /.well-known/oauth-authorization-server` - Authorization server info
- `POST /register` - DCR endpoint (clients self-register)
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token exchange endpoint
- `GET /auth/callback` - OAuth callback from Auth0

### Debug Logging

To see OAuth request details, enable httpx debug logging:

```python
import logging
logging.getLogger("httpx").setLevel(logging.DEBUG)
```

This shows:
- Auth0 token requests with audience parameters
- JWKS endpoint calls for key validation
- Token validation successes/failures
- Scope parameter passing

## Versioning

Uses automatic semantic versioning via GitHub Actions:

- **Manual version bumps**: Edit `__version__` in `version.py` for major/minor changes
- **Automatic patch increments**: CI auto-increments patch on main branch pushes
- **Version display**: Logged at startup via `get_version_info()`
- **Build tracking**: `__build__` field contains git commit SHA

To manually bump version:
```bash
# Minor version bump
sed -i 's/__version__ = "1.0.*"/__version__ = "1.1.0"/' version.py

# Major version bump
sed -i 's/__version__ = "1.*"/__version__ = "2.0.0"/' version.py
```

## CI/CD

GitHub Actions workflow (`.github/workflows/docker-build.yml`) handles:

1. **Version job**: Auto-increments patch, updates `version.py`, creates git tag
2. **Build job**: Multi-arch Docker build (amd64/arm64), pushes to GHCR

Tags generated: `latest`, `v1.0.x`, `1.0`, `1`, `sha-abc123`, `main`

## Key Implementation Details

### Signal Handling
- SIGTERM (Docker stop) and SIGINT (Ctrl+C) set `shutdown_requested` flag
- Graceful shutdown stops file watcher and exits main loop

### Port Management
- `wait_for_port_available()` retries binding for 10 seconds with 0.5s intervals
- Critical for live reload since previous process may hold port briefly

### Error Handling
- File not found and JSON syntax errors are permanent (no retry)
- Other errors retry with exponential backoff: 1s, 2s, 4s, 8s...
- Restart delay caps at 30 seconds to prevent excessive waiting
