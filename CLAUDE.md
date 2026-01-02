# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**MCP Proxy Server** is a production-ready, resilient proxy that aggregates multiple Model Context Protocol (MCP) servers through a single unified endpoint with **API key authentication**.

**Key Features:**
- 🔐 **API Key Authentication** - Simple Bearer token validation
- 🚀 **Multi-Server Aggregation** - Supports stdio-based (uvx/npx), SSE, and HTTP MCP servers
- 🔄 **Live Config Reload** - Update server definitions without restarting
- 🏥 **Resilient** - Automatic restart, exponential backoff, port availability checking
- 👤 **Client Identity Tracking** - Each API key maps to a client_id for tracking/logging

## Architecture

### Core Components

**proxy_server.py** - Main application with key functions and classes:

- `load_api_keys()` - Loads API keys from environment or JSON file
  - Supports `MCP_API_KEYS` env var (format: `key1:client1,key2:client2`)
  - Supports `MCP_API_KEYS_PATH` for JSON file
  - Returns dict mapping API key strings to their claims
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
    },
    "remote-server": {
      "url": "https://server.com/mcp",
      "transport": "http|sse",
      "headers": {
        "Authorization": "Bearer token"
      }
    }
  }
}
```

**/data/users.json** - User whitelist (future feature, not currently enforced):
```json
{
  "client-id-1": {
    "name": "Client Name",
    "allowed_tools": ["*"]
  }
}
```

**Note**: User whitelisting is planned but not implemented. All valid API keys currently have full access.

### Server Lifecycle

1. **Startup** - `ResilientMCPProxy.run_with_restart()` orchestration loop starts
2. **API Keys Load** - `load_api_keys()` loads authentication credentials
   - Tries `MCP_API_KEYS` environment variable first
   - Falls back to `MCP_API_KEYS_PATH` JSON file if set
   - Validates format and returns key-to-claims mapping
3. **Config Load** - Configuration loaded with retry logic (`load_config_with_retry()`)
   - Validates JSON schema against `mcp_config.schema.json`
   - Expands environment variables in config
4. **Auth Provider Creation** - Creates `StaticTokenVerifier` with loaded API keys
   - Simple Bearer token validation
   - Maps tokens to client_id for tracking
5. **FastMCP Creation** - Unified FastMCP instance created via `FastMCP.as_proxy(config, auth=auth)`
   - Single endpoint aggregates all configured MCP servers
   - StaticTokenVerifier middleware handles authentication
6. **HTTP Server** - FastMCP runs native HTTP transport on `0.0.0.0:8080` (or configured host/port)
   - Listens at `/mcp` endpoint
   - `/health` endpoint for health checks
7. **File Watching** - Watchdog monitors config directory for changes
   - Debounces events with 1s delay
   - On change, exits with code 42 (triggers clean reload)
8. **Error Handling** - Crashes trigger exponential backoff restart
   - Delays: 1s, 2s, 4s, 8s, 16s, max 30s
   - Max 10 restart attempts
9. **Port Management** - `wait_for_port_available()` checks port before restart
   - Waits up to 10 seconds for port to be available
   - Critical for live reload

### Live Reload Mechanism

- Uses watchdog library to monitor the config file's parent directory
- Debounces events (1 second delay) to handle multiple rapid filesystem events
- Reload triggers `os._exit(42)` to ensure clean port release
- Exit code 42 distinguishes intentional reload from crashes
- `_monitor_for_reload()` runs in daemon thread checking for reload flag

## Development Commands

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set API keys
export MCP_API_KEYS="sk-dev-key:local-dev"

# Run the server
python proxy_server.py

# Run with live reload enabled
MCP_LIVE_RELOAD=true python proxy_server.py
```

### Docker Development
```bash
# Build locally
docker build -t mcp-proxy .

# Run with custom config and API keys
docker run -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -e MCP_API_KEYS="sk-dev:local" \
  mcp-proxy

# Build multi-arch (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t mcp-proxy .
```

### Testing

```bash
# Generate an API key
API_KEY="sk-$(openssl rand -hex 16)"

# Start the server
export MCP_API_KEYS="$API_KEY:test-client"
python proxy_server.py &

# Test health endpoint (no auth)
curl http://localhost:8080/health

# Test health endpoint (with auth - shows server list)
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/health

# Test MCP endpoint (requires auth)
curl -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -X POST http://localhost:8080/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Environment Variables

### Authentication (Required)

- `MCP_API_KEYS` - API keys in format `key1:client1,key2:client2`
  - Example: `MCP_API_KEYS="sk-abc123:letta,sk-xyz789:local-dev"`
  - Each key maps to a client_id for tracking
- `MCP_API_KEYS_PATH` - Alternative: path to JSON file with API keys
  - Format: `{"key": {"client_id": "name", "scopes": ["*"]}}`

### MCP Proxy Configuration

- `MCP_CONFIG_PATH` - Path to MCP servers config (default: `mcp_config.json`)
- `MCP_USERS_PATH` - Path to user whitelist (default: `/data/users.json`, not enforced yet)
- `MCP_HOST` - Bind host address (default: `0.0.0.0`)
- `MCP_PORT` - Bind port (default: `8080`)

### Server Resilience

- `MCP_MAX_RETRIES` - Config load retry attempts (default: 3)
- `MCP_RESTART_DELAY` - Initial restart delay in seconds (default: 5)
- `MCP_LIVE_RELOAD` - Enable live config reload: `true|1|yes` (default: false)

### Optional Security

- `MCP_PATH_PREFIX` - Custom path prefix for MCP endpoint (default: none)
  - Example: `3434dc5d-349b-401c-8071-7589df9a0bce` creates `/3434dc5d-349b-401c-8071-7589df9a0bce/mcp`
  - Useful for security through obscurity or multi-tenant deployments
- `MCP_DISABLE_AUTH` - Disable all authentication: `true|1|yes` (default: false, **NOT RECOMMENDED**)

## API Key Authentication

### How It Works

1. Client sends request with `Authorization: Bearer sk-api-key-here` header
2. `StaticTokenVerifier` validates the token against configured keys
3. If valid, request proceeds with client_id from key mapping
4. If invalid, returns 401 Unauthorized

### Configuration Formats

**Environment Variable (Simple):**
```bash
MCP_API_KEYS="key1:client1,key2:client2,key3:client3"
```

**JSON File (Advanced):**
```json
{
  "sk-abc123def456": {
    "client_id": "letta-cloud",
    "scopes": ["*"]
  },
  "sk-xyz789uvw012": {
    "client_id": "local-development",
    "scopes": ["*"]
  }
}
```

Set path:
```bash
MCP_API_KEYS_PATH=/data/api_keys.json
```

## Versioning

Uses automatic semantic versioning via GitHub Actions:

- **Manual version bumps**: Edit `__version__` in `version.py` for major/minor changes
- **Automatic patch increments**: CI auto-increments patch on main branch pushes
- **Version display**: Logged at startup via `get_version_info()`
- **Build tracking**: `__build__` field contains git commit SHA

To manually bump version:
```bash
# Minor version bump
sed -i 's/__version__ = "2.0.*"/__version__ = "2.1.0"/' version.py

# Major version bump
sed -i 's/__version__ = "2.*"/__version__ = "3.0.0"/' version.py
```

## CI/CD

GitHub Actions workflow (`.github/workflows/docker-build.yml`) handles:

1. **Version job**: Auto-increments patch, updates `version.py`, creates git tag
2. **Build job**: Multi-arch Docker build (amd64/arm64), pushes to GHCR

Tags generated: `latest`, `v2.0.x`, `2.0`, `2`, `sha-abc123`, `main`

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

### Security Considerations
- API keys should be generated using cryptographically secure random (e.g., `openssl rand -hex 32`)
- Each key maps to a client_id for auditing/tracking
- In production, always use HTTPS (deploy behind Cloudflare Tunnel, nginx, or load balancer)
- Never commit API keys to git - use environment variables or mounted volumes

## Common Development Tasks

### Adding a New Environment Variable

1. Update docstring in `proxy_server.py`
2. Add default value if applicable
3. Update `.env.example` with description
4. Update `CLAUDE.md` (this file) and `README.md`

### Modifying Authentication

API key authentication is handled in `create_proxy()`:

```python
# Load API keys
api_keys = load_api_keys()

# Create auth provider
if api_keys:
    auth = StaticTokenVerifier(tokens=api_keys, required_scopes=None)
```

To modify validation logic, check `StaticTokenVerifier` in FastMCP library.

### Adding New MCP Server Types

FastMCP's `as_proxy()` supports:
- **stdio**: `command` + `args` (e.g., npx, uvx)
- **http**: `url` + `transport: "http"` + optional `headers`
- **sse**: `url` + `transport: "sse"` + optional `headers`

Add new server to `mcp_config.json` - no code changes needed.

### Debugging

Enable debug logging:
```bash
export MCP_LOG_LEVEL=DEBUG
python proxy_server.py
```

Or set specific loggers:
```bash
export MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:INFO"
```

Check logs for:
- API key validation: `Token verified via API key for client: <client_id>`
- Server startup: `✓ API key authentication enabled`
- Config loading: `✓ Loaded configuration from <path>`

## OAuth Support (Historical)

This project previously supported OAuth 2.1 authentication with Auth0, Keycloak, Okta, and Generic OIDC providers.

**If you need OAuth**: Check out the `v2.0-oauth` git tag:
```bash
git checkout v2.0-oauth
```

OAuth was removed to simplify the codebase and focus on the primary use case (API keys for tools like Letta, local development, and programmatic access).

## Future Enhancements

Planned features (see GitHub Issues):
- User whitelist enforcement (respect `/data/users.json`)
- Rate limiting per API key
- Tool-level access control (granular permissions)
- Metrics and monitoring dashboard
- Request/response logging

## Support & Contributing

- **Issues**: https://github.com/jonhearsch/mcp-proxy/issues
- **Pull Requests**: https://github.com/jonhearsch/mcp-proxy/pulls
- **Discussions**: https://github.com/jonhearsch/mcp-proxy/discussions

When contributing:
1. Follow existing code style
2. Update documentation (README.md, CLAUDE.md)
3. Test with both environment variable and JSON file API key configs
4. Ensure Docker build works: `docker build -t mcp-proxy .`
