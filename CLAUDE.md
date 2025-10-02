# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Proxy Server is a resilient FastAPI-based proxy that aggregates multiple Model Context Protocol (MCP) servers through a single endpoint. It supports stdio-based servers (via uvx/npx), SSE, and Streamable protocols.

## Architecture

### Core Components

**proxy_server.py** - Main application with two key classes:

- `ResilientMCPProxy`: Orchestrates the entire server lifecycle with automatic restart, live config reloading via file watching, graceful shutdown, and exponential backoff retry logic
- `ConfigFileHandler`: Watchdog-based file system monitor that detects config changes with debouncing to prevent rapid reload loops

**version.py** - Version management module that provides `get_version()` and `get_version_info()` functions. The `__version__` and `__build__` variables are automatically updated by CI/CD.

**mcp_config.json** - Runtime configuration defining MCP servers in Claude-compatible format:
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

### Server Lifecycle

1. `ResilientMCPProxy.run_with_restart()` is the main orchestration loop
2. Config is loaded with retry logic (`load_config_with_retry()`)
3. FastMCP proxy instance created via `FastMCP.as_proxy(config)`
4. File watcher monitors config directory (not the file directly) to handle atomic editor saves
5. On config change, process exits with code 42 to trigger clean reload
6. Crashes trigger exponential backoff restart (max 10 attempts)
7. Port availability is checked before restart to prevent bind failures

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
pip install fastmcp watchdog

# Run locally with SSE transport
python proxy_server.py --transport sse

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
# Health check endpoint
curl http://localhost:8080/health
```

## Environment Variables

- `MCP_CONFIG_PATH` - Path to config file (default: `mcp_config.json`)
- `MCP_MAX_RETRIES` - Config load retry attempts (default: 3)
- `MCP_RESTART_DELAY` - Initial restart delay in seconds (default: 5)
- `MCP_LIVE_RELOAD` - Enable file watching: `true|1|yes` (default: false)

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
