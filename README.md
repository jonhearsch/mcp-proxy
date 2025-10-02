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
docker pull ghcr.io/jonhearsch/mcp-proxy:latest

# Run with default config
docker run -p 8080:8080 ghcr.io/jonhearsch/mcp-proxy:latest

# Run with custom config
docker run -p 8080:8080 \
  -v $(pwd)/my-config.json:/app/mcp_config.json:ro \
  -v $(pwd)/data:/data \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

### Using Docker Compose

```yaml
version: '3.8'

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    ports:
      - "8080:8080"
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
- `v1.0.x` - Semantic version tags (auto-incremented)
- `1.0` - Major.minor version tags
- `1` - Major version tags
- `sha-abc123` - Commit-specific builds
- `main` - Latest main branch build

### Versioning

This project uses **automatic semantic versioning**:

- **Major.Minor.Patch** format (e.g., `1.0.5`)
- **Patch version auto-increments** on each push to `main` branch
- **Manual version bumps** for major/minor releases
- **Git tags** automatically created for each release
- **Docker images** tagged with multiple version formats

#### Version Management

- `version.py` contains the current version number
- GitHub Actions automatically increments patch version on main branch pushes
- Version info displayed in server logs at startup
- Each build includes commit SHA for traceability

#### Manual Version Bumps

For major or minor version changes, manually update `version.py`:

```bash
# For minor version bump (new features)
sed -i 's/__version__ = "1.0.*"/__version__ = "1.1.0"/' version.py

# For major version bump (breaking changes)
sed -i 's/__version__ = "1.*"/__version__ = "2.0.0"/' version.py

# Commit the change
git add version.py
git commit -m "Bump version to 2.0.0"
git push origin main
```

The next auto-build will use your new base version and continue auto-incrementing from there.

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
git clone https://github.com/jonhearsch/mcp-proxy.git
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
