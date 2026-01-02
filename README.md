# MCP Proxy Server - Remote MCP Server Gateway

**Access your Model Context Protocol (MCP) servers from anywhere** - securely aggregate multiple MCP tools through one remote endpoint with API key authentication.

Use **Claude Desktop, Letta, or any MCP client** with remote MCP servers - filesystem, database, API, and custom tools accessible from any device.

---

## 🎯 Perfect for:
- **Remote MCP access** - Use MCP tools from anywhere, not just localhost
- **Letta Cloud integration** - Connect Letta to your self-hosted MCP servers
- **Multi-device workflows** - Access tools from work laptop, home desktop, or cloud
- **Cloud deployments** - Host MCP tools on VPS, Docker, Kubernetes
- **Centralized tool management** - One endpoint for all your MCP servers
- **Local development** - Simple API-key auth for personal projects

## Why MCP Proxy?

**Problems:**
1. MCP servers only run on your local machine
2. Can't access tools remotely or share with other services
3. Each tool runs separately - hard to manage

**Solution:** MCP Proxy is a **remote MCP server gateway** that lets you:
- ✅ Access MCP tools from **anywhere** (not just localhost)
- ✅ Use with Claude Desktop, Letta, custom apps, or any MCP client
- ✅ Deploy MCP servers once, use everywhere
- ✅ Aggregate multiple MCP servers into one endpoint
- ✅ Simple API key authentication

## Features

### Remote Access & Deployment
- 🌐 **Remote MCP Server Access** - Use MCP from anywhere
- ☁️ **Cloud-Ready** - Deploy to any VPS, Docker, Kubernetes
- 🐳 **Docker Support** - One-line deployment with multi-architecture support (AMD64/ARM64)
- 🔒 **API Key Authentication** - Simple Bearer token auth
- 🔐 **Cloudflare Tunnel Ready** - Expose securely without public IP

### MCP Server Management
- 🚀 **Multi-Server Aggregation** - Combine stdio (uvx, npx), SSE, and HTTP MCP servers
- 📝 **Claude-Compatible Config** - Same JSON format as Claude Desktop
- 🔄 **Live Config Reload** - Add/remove servers without restarting
- ✅ **Multi-Client Support** - Works with any MCP-compatible client
- 🏥 **Auto-Restart & Health Checks** - Resilient server lifecycle management

### Security
- 🔐 **API Key Authentication** - Secure Bearer token validation
- 👤 **Client Identity Tracking** - Know which client is using which tools
- 🔒 **Optional Path Obscurity** - Add UUID prefix to endpoint URL

## Quick Start - Remote MCP in 5 Minutes

Get your MCP proxy running in 3 steps:

### Prerequisites

- **Docker** (easiest) or **Python 3.10+**
- **Public URL** (optional) - Domain, VPS IP, or Cloudflare Tunnel

### 1. Create Configuration

Create `mcp_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "time": {
      "command": "uvx",
      "args": ["mcp-server-time"]
    },
    "remote-server": {
      "url": "https://other-server.com/sse",
      "transport": "sse",
      "headers": {
        "Authorization": "Bearer your-token"
      }
    }
  }
}
```

### 2. Run with Docker

```bash
# Generate an API key (or use your own)
API_KEY="sk-$(openssl rand -hex 16)"
echo "Your API key: $API_KEY"

# Run the proxy
docker run -d \
  --name mcp-proxy \
  -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -e MCP_API_KEYS="$API_KEY:my-client" \
  ghcr.io/jonhearsch/mcp-proxy:latest

# Test it
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/health
```

### 3. Connect Your Client

#### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "remote-proxy": {
      "url": "http://localhost:8080/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer sk-your-api-key-here"
      }
    }
  }
}
```

#### Letta

Configure Letta to use your remote MCP proxy:

```bash
# In Letta configuration or environment
MCP_ENDPOINT=http://your-server:8080/mcp
MCP_API_KEY=sk-your-api-key-here
```

#### Custom Client (Python)

```python
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

client = Client(
    transport=StreamableHttpTransport(
        url="http://localhost:8080/mcp",
        headers={"Authorization": "Bearer sk-your-api-key-here"}
    )
)

async with client:
    # List available tools
    tools = await client.list_tools()

    # Call a tool
    result = await client.call_tool("filesystem:read_file", {"path": "/data/test.txt"})
```

## Deployment Options

### Docker (Recommended)

**Basic deployment:**
```bash
docker run -d \
  --name mcp-proxy \
  -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -e MCP_API_KEYS="sk-abc123:client1,sk-xyz789:client2" \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

**With persistent data:**
```bash
docker run -d \
  --name mcp-proxy \
  -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -v $(pwd)/data:/data \
  -e MCP_API_KEYS="sk-abc123:letta,sk-xyz789:local-tools" \
  -e MCP_LIVE_RELOAD=true \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

**Using API keys file:**
```bash
# Create api_keys.json
cat > api_keys.json << 'EOF'
{
  "sk-abc123": {
    "client_id": "letta-cloud",
    "scopes": ["*"]
  },
  "sk-xyz789": {
    "client_id": "local-dev",
    "scopes": ["*"]
  }
}
EOF

docker run -d \
  --name mcp-proxy \
  -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -v $(pwd)/api_keys.json:/data/api_keys.json:ro \
  -e MCP_API_KEYS_PATH=/data/api_keys.json \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    container_name: mcp-proxy
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
      - ./data:/data
    environment:
      - MCP_API_KEYS=sk-abc123:letta-cloud,sk-xyz789:local-dev
      - MCP_LIVE_RELOAD=true
      - MCP_PORT=8080
```

Run with:
```bash
docker-compose up -d
```

### Python (Development)

```bash
# Clone the repository
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export MCP_API_KEYS="sk-abc123:client1,sk-xyz789:client2"

# Run the server
python proxy_server.py
```

### Cloudflare Tunnel (Free Public Access)

Expose your local proxy securely without a public IP:

```bash
# Install cloudflared
# macOS: brew install cloudflare/cloudflare/cloudflared
# Linux: wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
#        sudo dpkg -i cloudflared-linux-amd64.deb

# Login to Cloudflare
cloudflared tunnel login

# Create a tunnel
cloudflared tunnel create mcp-proxy

# Start the proxy locally
docker run -d --name mcp-proxy -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -e MCP_API_KEYS="sk-abc123:letta" \
  ghcr.io/jonhearsch/mcp-proxy:latest

# Route the tunnel
cloudflared tunnel route dns mcp-proxy mcp.your-domain.com

# Run the tunnel
cloudflared tunnel run mcp-proxy
```

Now accessible at: `https://mcp.your-domain.com`

## Configuration

### Environment Variables

**Required:**
- `MCP_API_KEYS` - API keys in format `key1:client1,key2:client2`
  - OR `MCP_API_KEYS_PATH` - Path to API keys JSON file

**Optional:**
- `MCP_CONFIG_PATH` - Path to mcp_config.json (default: `mcp_config.json`)
- `MCP_HOST` - Host to bind to (default: `0.0.0.0`)
- `MCP_PORT` - Port to listen on (default: `8080`)
- `MCP_LIVE_RELOAD` - Enable live config reload: `true`/`false` (default: `false`)
- `MCP_PATH_PREFIX` - Add UUID prefix to endpoint for obscurity (e.g., `/abc-123-def/mcp`)
- `MCP_DISABLE_AUTH` - Disable authentication (NOT RECOMMENDED, default: `false`)

### MCP Server Configuration

The `mcp_config.json` file uses the same format as Claude Desktop:

**Stdio servers (npx, uvx):**
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
    }
  }
}
```

**HTTP/SSE remote servers:**
```json
{
  "mcpServers": {
    "remote-http": {
      "url": "https://api.example.com/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer remote-server-token",
        "X-Custom-Header": "value"
      }
    },
    "remote-sse": {
      "url": "https://other-server.com/sse",
      "transport": "sse",
      "headers": {
        "X-API-Key": "your-api-key"
      }
    }
  }
}
```

**Mixed configuration:**
```json
{
  "mcpServers": {
    "local-filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "remote-api": {
      "url": "https://api.example.com/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer token"
      }
    },
    "time": {
      "command": "uvx",
      "args": ["mcp-server-time"]
    }
  }
}
```

### API Keys Configuration

**Environment variable (simple):**
```bash
MCP_API_KEYS="sk-abc123:letta-cloud,sk-xyz789:local-dev,sk-def456:ci-bot"
```

**JSON file (advanced):**
```json
{
  "sk-abc123def456": {
    "client_id": "letta-cloud",
    "scopes": ["*"]
  },
  "sk-xyz789uvw012": {
    "client_id": "local-development",
    "scopes": ["*"]
  },
  "sk-ci-bot-key": {
    "client_id": "ci-pipeline",
    "scopes": ["*"]
  }
}
```

Set environment variable:
```bash
MCP_API_KEYS_PATH=/data/api_keys.json
```

## API Reference

### Health Check

```bash
GET /health

# Without auth (returns basic info)
curl http://localhost:8080/health

# With auth (returns server list)
curl -H "Authorization: Bearer sk-your-key" http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "service": "mcp-proxy",
  "servers": ["filesystem", "time", "remote-api"]
}
```

### MCP Endpoint

```bash
POST /mcp
Authorization: Bearer sk-your-api-key
Content-Type: application/json

# MCP protocol messages
```

## Use Cases

### Letta Cloud Integration

Connect Letta Cloud to your self-hosted tools:

```bash
# Run proxy with your tools
docker run -d -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -e MCP_API_KEYS="sk-letta-key:letta-cloud" \
  ghcr.io/jonhearsch/mcp-proxy:latest

# Configure Letta to use it
# In Letta settings or environment:
MCP_ENDPOINT=https://mcp.your-domain.com/mcp
MCP_API_KEY=sk-letta-key
```

### Multi-Device Development

Access the same tools from multiple devices:

```bash
# Work laptop
export MCP_API_KEY="sk-work-laptop"

# Home desktop
export MCP_API_KEY="sk-home-desktop"

# Both connect to: https://mcp.your-domain.com/mcp
```

### CI/CD Integration

Use MCP tools in your automation:

```python
# In your CI/CD pipeline
import os
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

client = Client(
    transport=StreamableHttpTransport(
        url=os.getenv("MCP_ENDPOINT"),
        headers={"Authorization": f"Bearer {os.getenv('MCP_API_KEY')}"}
    )
)

async with client:
    # Use MCP tools in your automation
    result = await client.call_tool("git:commit", {"message": "Deploy"})
```

## Troubleshooting

### Connection Issues

**Check if proxy is running:**
```bash
curl http://localhost:8080/health
```

**Check authentication:**
```bash
curl -H "Authorization: Bearer sk-your-key" http://localhost:8080/health
```

**View logs:**
```bash
docker logs mcp-proxy
```

### Common Errors

**401 Unauthorized:**
- Check your API key is correct
- Ensure `Authorization: Bearer sk-your-key` header is set
- Verify API key is configured in `MCP_API_KEYS` or `MCP_API_KEYS_PATH`

**Server not starting:**
- Check `mcp_config.json` is valid JSON
- Ensure all required environment variables are set
- Check port 8080 is not already in use

**Tools not loading:**
- Verify MCP server commands are correct in `mcp_config.json`
- Check server logs for startup errors
- Ensure required dependencies (npx, uvx) are available in the container

## Security Best Practices

1. **Use strong API keys:**
   ```bash
   # Generate secure random keys
   openssl rand -hex 32  # 64 character key
   ```

2. **Rotate keys regularly:**
   - Update `MCP_API_KEYS` periodically
   - Use different keys for different clients

3. **Use HTTPS in production:**
   - Deploy behind Cloudflare Tunnel, nginx, or load balancer
   - Never expose unencrypted HTTP publicly

4. **Limit network exposure:**
   - Use firewall rules to restrict access
   - Deploy in private network when possible

5. **Monitor access:**
   - Check logs regularly for unauthorized attempts
   - Each API key has a client_id for tracking

## Development

### Building from Source

```bash
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy

# Install dependencies
pip install -r requirements.txt

# Run locally
python proxy_server.py
```

### Running Tests

```bash
# TODO: Add test suite
pytest
```

### Building Docker Image

```bash
docker build -t mcp-proxy .
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Roadmap

- [ ] User whitelist enforcement
- [ ] Rate limiting per API key
- [ ] Metrics and monitoring dashboard
- [ ] WebSocket transport support
- [ ] Tool-level access control

## Version History

See [CHANGELOG.md](CHANGELOG.md) for version history.

**OAuth Support:** If you need OAuth 2.1 authentication (Auth0, Keycloak, Okta), see tag `v2.0-oauth` for the OAuth implementation.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: https://github.com/jonhearsch/mcp-proxy/issues
- **Discussions**: https://github.com/jonhearsch/mcp-proxy/discussions

## Acknowledgments

Built with [FastMCP](https://github.com/jlowin/fastmcp) by [@jlowin](https://github.com/jlowin)

---

**Made with ❤️ for the MCP community**
