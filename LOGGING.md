# Logging Configuration

The MCP Proxy Server supports flexible logging configuration through environment variables.

## Quick Start

### Enable Debug Logging Globally

```bash
MCP_LOG_LEVEL=DEBUG python proxy_server.py
```

### Debug Specific Libraries

```bash
MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG" python proxy_server.py
```

### Mix Global and Library-Specific Levels

```bash
MCP_LOG_LEVEL=INFO MCP_LOG_LEVELS="fastmcp:DEBUG" python proxy_server.py
```

This sets INFO level globally, but DEBUG for fastmcp specifically.

## Environment Variables

### `MCP_LOG_LEVEL`

Sets the global log level for all loggers.

- **Default**: `INFO`
- **Valid Values**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- **Example**: `MCP_LOG_LEVEL=DEBUG`

### `MCP_LOG_LEVELS`

Configure specific log levels for individual loggers. Useful for debugging specific components without overwhelming logs with debug output from everything.

- **Default**: (not set)
- **Format**: `logger_name:LEVEL[,logger_name:LEVEL,...]`
- **Example**: `MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG,proxy_server:INFO"`

## Common Use Cases

### Debug FastMCP Tool Discovery

See what tools are available and how they're being exposed:

```bash
MCP_LOG_LEVELS="fastmcp:DEBUG" python proxy_server.py
```

### Debug OAuth/Authentication

See detailed OAuth request/response logging:

```bash
MCP_LOG_LEVELS="httpx:DEBUG" python proxy_server.py
```

### Debug Everything

Full debug output for all components:

```bash
MCP_LOG_LEVEL=DEBUG python proxy_server.py
```

### Quiet Mode (Errors Only)

```bash
MCP_LOG_LEVEL=ERROR python proxy_server.py
```

## Docker Usage

Pass environment variables to the container:

```bash
docker run -e MCP_LOG_LEVEL=DEBUG \
           -e MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG" \
           ghcr.io/jonhearsch/mcp-proxy:latest
```

Or in `docker-compose.yml`:

```yaml
services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    environment:
      MCP_LOG_LEVEL: DEBUG
      MCP_LOG_LEVELS: "fastmcp:DEBUG,httpx:DEBUG"
```

## Log Format

All logs follow this standard format with fixed-width logger names (15 characters) for easy alignment:

```
YYYY-MM-DD HH:MM:SS - logger_name        - LEVEL - message
```

Example:

```
2025-10-27 14:23:45,123 - proxy_server    - INFO - Starting unified FastMCP proxy
2025-10-27 14:23:45,124 - fastmcp         - DEBUG - Tool discovered: add_numbers
2025-10-27 14:23:45,125 - httpx           - DEBUG - POST https://auth.example.com/oauth/token
2025-10-27 14:23:45,126 - auth_provider   - INFO - ✓ OAuthProxy successfully initialized
```

The fixed-width format ensures all log messages are neatly aligned and easy to follow.

## Available Loggers

- `fastmcp` - FastMCP framework (tool discovery, proxy operations)
- `httpx` - HTTP client (OAuth requests, network calls)
- `proxy_server` - Main proxy server logic
- `__main__` - Root logger

To see logs from a specific logger in debug detail:

```bash
MCP_LOG_LEVELS="fastmcp:DEBUG" python proxy_server.py
```
