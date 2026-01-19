# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**MCP Proxy Server** is a production-ready, resilient proxy that aggregates multiple Model Context Protocol (MCP) servers through a single unified endpoint with **built-in Google OAuth 2.0 authentication**.

**Key Features:**

- ✅ **Claude.ai Compatible** - Native Google OAuth integration for Claude MCP support
- 🔐 **Google OAuth 2.0** - Secure, trusted authentication via Google accounts
- 👤 **User Identity Tracking** - Know which user is accessing which tools
- 🚀 **Multi-Server Aggregation** - Supports stdio-based (uvx/npx), SSE, and Streamable MCP servers
- 🔄 **Live Config Reload** - Update server definitions without restarting
- 🏥 **Resilient** - Automatic restart, exponential backoff, port availability checking

## Architecture

### Core Components

**proxy_server.py** - Main application with key functions and classes:

- `create_google_auth()` - Initializes Google OAuth authentication using FastMCP's native `GoogleProvider`
  - Reads environment variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`, `GOOGLE_JWT_KEY`
  - Creates `GoogleProvider` instance with required OAuth scopes for OpenID and email
  - Returns `None` if credentials not configured, triggering clear error messages
  - Handles JWT signing key for production deployments (optional for development)
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

**.env** - Environment configuration (required):

```bash
# Google OAuth (Required)
GOOGLE_CLIENT_ID=123456789-abc123.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123def456
MCP_BASE_URL=https://your-domain.com
GOOGLE_JWT_KEY=your_jwt_signing_key  # Optional, for production

# MCP Proxy Configuration
MCP_CONFIG_PATH=mcp_config.json
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_LIVE_RELOAD=true
```

**Note**: All authentication is handled via Google OAuth. Access control happens at the Google account level - any user with a Google account who completes the OAuth flow can access the proxy.

### Server Lifecycle

1. **Startup** - `ResilientMCPProxy.run_with_restart()` orchestration loop starts
2. **Auth Setup** - `create_google_auth()` initializes Google OAuth authentication
   - Validates required environment variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`
   - Creates `GoogleProvider` instance with OpenID and email scopes
   - Logs configuration details (redacted for security)
   - Returns `None` if not configured, causing startup failure with clear instructions
3. **Config Load** - Configuration loaded with retry logic (`load_config_with_retry()`)
   - Validates JSON schema against `mcp_config.schema.json`
   - Expands environment variables in config
4. **FastMCP Creation** - Unified FastMCP instance created via `FastMCP.as_proxy(config, auth=auth)`
   - Single endpoint aggregates all configured MCP servers
   - GoogleProvider middleware handles OAuth authentication and DCR
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

### Google OAuth (Required)

- `GOOGLE_CLIENT_ID` - OAuth 2.0 Client ID from Google Cloud Console
  - Format: `123456789-abc123def456.apps.googleusercontent.com`
  - Get from: https://console.developers.google.com/ → APIs & Services → Credentials
- `GOOGLE_CLIENT_SECRET` - OAuth 2.0 Client Secret from Google Cloud Console
  - Format: `GOCSPX-abc123def456...`
  - Keep this secret - never commit to git
- `MCP_BASE_URL` - Public URL where proxy is accessible (e.g., `https://mcp.your-domain.com`)
  - **Must match authorized redirect URI in Google Cloud Console**
  - Required for OAuth callback: `{MCP_BASE_URL}/auth/callback`
  - Must use HTTPS in production (HTTP allowed for localhost only)
- `GOOGLE_JWT_KEY` - JWT signing key for production deployments (optional)
  - Generate with: `openssl rand -hex 32`
  - If not set, FastMCP uses a default key (suitable for development only)
  - Recommended for production to ensure token security across restarts

### MCP Proxy Configuration

- `MCP_CONFIG_PATH` - Path to MCP servers config (default: `mcp_config.json`)
- `MCP_HOST` - Bind host address (default: `0.0.0.0`)
- `MCP_PORT` - Bind port (default: `8080`)
- `MCP_LIVE_RELOAD` - Enable live config reload: `true|1|yes` (default: false)
- `MCP_PATH_PREFIX` - Custom path prefix for MCP endpoint (default: none)
  - Example: `3434dc5d-349b-401c-8071-7589df9a0bce` creates `/3434dc5d-349b-401c-8071-7589df9a0bce/mcp/`
  - Useful for security through obscurity or multi-tenant deployments

### Server Resilience

- `MCP_MAX_RETRIES` - Config load retry attempts (default: 3)
- `MCP_RESTART_DELAY` - Initial restart delay in seconds (default: 5)

## Google OAuth 2.0 Authentication

### Overview

MCP Proxy uses FastMCP's built-in `GoogleProvider` for secure, native Google OAuth 2.0 authentication:

1. **Dynamic Client Registration (DCR)** - Claude.ai or other clients register themselves automatically
2. **Authorization Flow** - User logs in with their Google account (supports Google Workspace)
3. **Token Exchange** - Google issues access token, FastMCP validates and wraps in session JWT
4. **Protected Access** - Subsequent MCP requests validated using JWT signature
5. **Session Management** - FastMCP manages OAuth sessions with secure token storage

### Key Security Features

- **Google OAuth** - Leverages Google's trusted authentication infrastructure
- **OpenID Connect** - Uses standard OIDC protocol with email scope
- **JWT Signing** - Optional JWT signing key for production token security
- **HTTPS Required** - Production deployments must use HTTPS (OAuth requirement)
- **Automatic DCR** - FastMCP's GoogleProvider handles Dynamic Client Registration automatically
- **Token Expiry** - Tokens expire based on JWT signing configuration

### OAuth Endpoints

Automatically provided by GoogleProvider (via FastMCP):

- `GET /.well-known/oauth-authorization-server` - Authorization server metadata
- `POST /dcr` - Dynamic Client Registration endpoint
- `GET /auth/login` - Initiates OAuth flow
- `GET /auth/callback` - OAuth callback from Google
- `POST /token` - Token exchange endpoint (for DCR clients)

### Google Cloud Console Setup

1. **Create OAuth Application**: https://console.developers.google.com/
2. **Configure Authorized Origins**: Add `{MCP_BASE_URL}` (e.g., `https://mcp.your-domain.com`)
3. **Configure Redirect URIs**: Add `{MCP_BASE_URL}/auth/callback`
4. **Required Scopes**: `openid`, `https://www.googleapis.com/auth/userinfo.email`
5. **Copy Credentials**: Client ID and Client Secret to `.env` file

See [README.md](README.md) for detailed Google Cloud Console setup instructions.

### Debug Logging

To see OAuth request details, set log level:

```bash
export MCP_LOG_LEVEL=DEBUG
export MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG"
```

This shows:

- Google OAuth token requests
- DCR registration attempts
- Token validation successes/failures
- OAuth callback processing

## Versioning

Uses automatic semantic versioning via GitHub Actions:

- **Current Version**: v3.0.0 (Google OAuth only - breaking change from v2.x)
- **Manual version bumps**: Edit `__version__` in `version.py` for major/minor changes
- **Automatic patch increments**: CI auto-increments patch on main branch pushes
- **Version display**: Logged at startup via `get_version_info()`
- **Build tracking**: `__build__` field contains git commit SHA

### Version History

- **v3.0.0** (2026-01-19) - Google OAuth only, removed API key authentication and Auth0/Keycloak/Okta providers
- **v2.0.x** - Hybrid authentication (OAuth + API keys, now deprecated)
- **v1.x** - Initial release with Auth0 support

To manually bump version:

```bash
# Minor version bump
sed -i 's/__version__ = "3.0.*"/__version__ = "3.1.0"/' version.py

# Major version bump
sed -i 's/__version__ = "3.*"/__version__ = "4.0.0"/' version.py
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
