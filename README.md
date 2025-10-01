# MCP Proxy Server

A multi-architecture Docker container that proxies multiple MCP (Model Context Protocol) servers through a single FastMCP endpoint.

## Features

- 🚀 Supports stdio (uvx, npx), SSE, and Streamable MCP servers
- 🐳 Multi-architecture support (AMD64 & ARM64)
- 📝 Claude-style JSON configuration
- 🔄 Automatic builds via GitHub Actions
- 🏥 Built-in health checks

## Quick Start

### Using Docker

```bash
# Pull the latest image
docker pull ghcr.io/YOUR_USERNAME/mcp-proxy:latest

# Run with default config
docker run -p 8000:8000 ghcr.io/YOUR_USERNAME/mcp-proxy:latest

# Run with custom config
docker run -p 8000:8000 \
  -v $(pwd)/my-config.json:/app/mcp_config.json:ro \
  -v $(pwd)/data:/data \
  ghcr.io/YOUR_USERNAME/mcp-proxy:latest
```

### Using Docker Compose

```yaml
version: '3.8'

services:
  mcp-proxy:
    image: ghcr.io/YOUR_USERNAME/mcp-proxy:latest
    ports:
      - "8000:8000"
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
      - ./data:/data
    environment:
      - MCP_CONFIG_PATH=/app/mcp_config.json
```

## Configuration

Create a `mcp_config.json` file with your MCP servers:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "sqlite": {
      "command": "uvx",
      "args": ["mcp-server-sqlite", "--db-path", "/data/db.sqlite"]
    },
    "remote-sse": {
      "url": "http://other-server:8000/sse",
      "transport": "sse"
    }
  }
}
```

## Available Images

Images are automatically built for:
- `linux/amd64` (x86_64)
- `linux/arm64` (ARM64/Apple Silicon)

### Tags

- `latest` - Latest build from main branch
- `v1.0.0` - Semantic version tags
- `sha-abc123` - Commit-specific builds
- `main` - Latest main branch build

## Building Locally

```bash
# Build for your platform
docker build -t mcp-proxy .

# Build multi-arch (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t mcp-proxy .
```

## Development

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/mcp-proxy.git
cd mcp-proxy

# Install dependencies
pip install fastmcp

# Run locally
python proxy_server.py --transport sse
```

## Environment Variables

- `MCP_CONFIG_PATH` - Path to the configuration file (default: `mcp_config.json`)
- Any environment variables referenced in your `mcp_config.json` file

## Health Check

The container includes a health check endpoint accessible at `http://localhost:8000/health`

## License

MIT License - see LICENSE file for details
