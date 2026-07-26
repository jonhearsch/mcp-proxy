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

**mcp_proxy/** - Main application package (run with `python -m mcp_proxy`):

**mcp_proxy/auth.py** - Authentication providers:

- `create_google_auth()` - Initializes Google OAuth authentication using FastMCP's native `GoogleProvider`
  - Reads environment variables: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`, `GOOGLE_JWT_KEY`
  - Creates `GoogleProvider` instance with required OAuth scopes for OpenID and email
  - Returns `None` if credentials not configured, triggering clear error messages
  - Handles JWT signing key for production deployments (optional for development)
- `create_static_token_auth()` - Shared static token for gateway-fronted deployments
  - Reads `MCP_AUTH_TOKEN`; returns `None` if unset or shorter than `MIN_TOKEN_LENGTH` (32)
  - Wraps FastMCP's built-in `StaticTokenVerifier` — no custom middleware
  - Never logs the token value, only its length

**mcp_proxy/config.py** - `load_config_with_retry()`, plus `_parse_int_env()` / `_parse_bool_env()` env helpers. Use these rather than parsing env vars inline.

**mcp_proxy/logging.py** - structlog configuration (`configure_logging()`, `get_logger()`). See [LOGGING.md](LOGGING.md).

**mcp_proxy/watcher.py** - `ConfigFileHandler`, the watchdog-based config file monitor.

**mcp_proxy/server.py** - Server orchestration:

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

String values anywhere in the config may reference `${VAR_NAME}` to pull from the process environment (e.g. for API keys in `args`/`env`). Expansion happens in `load_config_with_retry()` before schema validation; a referenced variable that isn't set is a permanent config error (fails startup immediately, naming the missing variable, no retry).

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

**Note**: In Google OAuth mode, access control happens at the Google account level - any user with a Google account who completes the OAuth flow can access the proxy.

### Authentication Modes

Three modes, resolved in strict precedence order in `create_proxy()`. Exactly one is active, and it is logged at startup:

1. `MCP_DISABLE_AUTH` truthy → `auth=None`, logs a warning. Local debugging only.
2. `MCP_AUTH_TOKEN` set → `StaticTokenVerifier` via `create_static_token_auth()`. For deployments behind a gateway (e.g. agentgateway) that terminates OAuth itself. An invalid token (too short) is a **hard failure** — it deliberately does not fall through to OAuth, since silently switching auth modes on a misconfiguration would be a security surprise.
3. Otherwise → `create_google_auth()`. Required for clients like Claude.ai that connect directly and need OAuth/DCR.

See [docs/AUTH_PROVIDERS.md](docs/AUTH_PROVIDERS.md) for the trade-offs of static token mode.

### Server Lifecycle

1. **Startup** - `ResilientMCPProxy.run_with_restart()` orchestration loop starts
2. **Auth Setup** - `create_proxy()` selects one of the three auth modes above
   - Google mode validates `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`
   - Static token mode validates `MCP_AUTH_TOKEN` length (min 32 chars)
   - Logs configuration details (redacted for security)
   - Returns `False` if the selected mode is misconfigured, causing startup failure with clear instructions
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
- `_monitor_for_reload()` runs in a daemon thread; on a debounced change it sets
  `restart_event` and sends the process its own `SIGTERM` to unblock the
  in-progress `proxy.run()` call
- `_handle_signal()` (the shared SIGINT/SIGTERM handler) checks `restart_event`
  first: if set, it's this internal reload self-signal, not a real shutdown
  request, so it returns without touching `shutdown_event`. Only an external
  signal (Ctrl+C, Docker/K8s stop) sets `shutdown_event`
- `run_with_restart()` sees `restart_event` set once `proxy.run()` returns,
  waits for the port to free up, and loops back to rebuild the proxy with the
  freshly reloaded config — all within the same process

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
python -m mcp_proxy

# Run with live reload enabled
MCP_LIVE_RELOAD=true python -m mcp_proxy
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

### Authentication (one mode required)

- `MCP_AUTH_TOKEN` - Shared static token for gateway-fronted deployments (auth mode 2)
  - Generate with: `openssl rand -hex 32`
  - Minimum 32 characters; shorter values are rejected at startup
  - The upstream gateway must **set** `Authorization: Bearer <token>`, not forward the client's header
- `MCP_DISABLE_AUTH` - Disable authentication entirely: `true|1|yes` (default: false)
  - Local debugging only; leaves the proxy open to anything that can reach the port

### Google OAuth (auth mode 3 - required unless a mode above is set)

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
  - Known upstream risk: see [docs/AUTH_PROVIDERS.md](docs/AUTH_PROVIDERS.md#environment-variables) — an open fastmcp issue reports this key can be silently ignored; smoke-test before relying on it

### MCP Proxy Configuration

- `MCP_CONFIG_PATH` - Path to MCP servers config (default: `mcp_config.json`)
- `MCP_HOST` - Bind host address (default: `0.0.0.0`)
  - Set to `127.0.0.1` when a gateway on the same host is the only intended caller
- `MCP_PORT` - Bind port (default: `8080`)
- `MCP_LIVE_RELOAD` - Enable live config reload: `true|1|yes` (default: false)

### Server Resilience

- `MCP_MAX_RETRIES` - Config load retry attempts (default: 3)
- `MCP_RESTART_DELAY` - Initial restart delay in seconds (default: 5)

### Logging

- `MCP_LOG_LEVEL` - Global log level (default: `INFO`)
- `MCP_LOG_LEVELS` - Per-logger overrides, format `name:LEVEL,name:LEVEL`
- `MCP_AUTH_DEBUG` - Verbose auth logging: `true|1|yes` (default: false)

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
