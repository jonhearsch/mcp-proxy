# MCP Proxy Server

A production-ready proxy that aggregates multiple Model Context Protocol (MCP) servers through a single unified endpoint with **built-in OAuth 2.1 authentication via Auth0**.

**Works seamlessly with Claude Connectors and any MCP client.**

## Features

- ✅ **Claude Connector Compatible** - Works out-of-the-box with Claude's MCP Connector API
- 🔐 **OAuth 2.1 + PKCE** - Secure authentication with Auth0 (or any OAuth 2.1 provider)
- 👤 **User Identity Tracking** - Know which user is accessing which tools
- 🚀 **Multi-Server Aggregation** - Combine stdio (uvx, npx), SSE, and Streamable servers into one endpoint
- 🐳 **Multi-Architecture Docker** - Runs on AMD64 and ARM64 (including Apple Silicon)
- 📝 **Simple JSON Configuration** - Claude-style MCP configuration format
- 🔄 **Live Config Reload** - Update servers without restarting
- 🏥 **Built-in Health Checks** - Automatic monitoring and resilience
- 🔒 **Zero-Trust Ready** - Works with Cloudflare Tunnel, network segmentation, etc.

## Quick Start

### Prerequisites

- **Docker** (for containerized deployment) or **Python 3.10+** (for local development)
- **Auth0 Account** (free tier available at https://auth0.com)

### 1. Auth0 Setup (5 minutes)

1. Create an Auth0 account at https://auth0.com
2. Create a **Regular Web Application**:
   - Dashboard → Applications → Create Application
   - Type: "Regular Web Application"
   - Name: "MCP Proxy"
3. In the application **Settings** tab:
   - Copy your **Client ID** and **Client Secret**
   - Set **Allowed Callback URLs** to: `https://your-domain.com/auth/callback`
4. Create an **API**:
   - Dashboard → Applications → APIs → Create API
   - Name: "MCP Proxy API"
   - Identifier: `https://your-mcp-api` (or any unique identifier)
5. Copy your **Auth0 Domain** from Settings (e.g., `your-tenant.us.auth0.com`)

### 2. Configure MCP Proxy

#### Create `mcp_config.json`

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "time": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-time"]
    }
  }
}
```

#### Create `/data/users.json`

```json
{
  "you@example.com": {
    "name": "Your Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  }
}
```

#### Create `.env`

```bash
# Auth0 Credentials
AUTH0_CLIENT_ID=your-client-id-from-step-1
AUTH0_CLIENT_SECRET=your-client-secret-from-step-1
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_AUDIENCE=https://your-mcp-api

# MCP Proxy Configuration
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=https://your-domain.com
MCP_USERS_PATH=/data/users.json
MCP_AUTH_CONFIG_PATH=/data/auth_config.json
```

### 3. Run MCP Proxy

#### Using Docker

```bash
docker run -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  -v $(pwd)/data:/data \
  --env-file .env \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

#### Using Docker Compose

```yaml
version: "3.8"

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    ports:
      - "8080:8080"
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
      - ./data:/data
    env_file:
      - .env
    restart: unless-stopped
```

#### Local Development (Python)

```bash
pip install -r requirements.txt
python proxy_server.py
```

### 4. Connect to Claude

1. Visit https://claude.ai
2. Go to **Settings** → **MCP Connectors**
3. Click **+ Add Connection**
4. Enter your server URL: `https://your-domain.com/mcp`
5. Click **Connect**
6. You'll be redirected to Auth0 to log in
7. Approve the consent screen
8. Claude will show available tools from all your configured servers

## Architecture

```
┌─────────────────┐
│  Claude Desktop │
│  or Web App     │
└────────┬────────┘
         │ OAuth 2.1 + PKCE
         ↓
┌─────────────────────────────────┐
│   MCP Proxy (Your Server)       │
│  ┌───────────────────────────┐  │
│  │   OAuthProxy (Auth0)      │  │
│  │  ✓ DCR Registration       │  │
│  │  ✓ JWT Token Validation   │  │
│  │  ✓ User Consent Screen    │  │
│  └───────────────────────────┘  │
│           ↓                      │
│  ┌───────────────────────────┐  │
│  │ Unified FastMCP Endpoint  │  │
│  │  - All servers aggregated │  │
│  │  - Single /mcp/ path      │  │
│  └───────────────────────────┘  │
└────┬────────────────────────┬────┘
     │                        │
     ↓                        ↓
┌─────────────┐         ┌──────────────┐
│  Server 1   │         │  Server 2    │
│ (Filesystem)│         │   (Time)     │
└─────────────┘         └──────────────┘
```

## Configuration

### `mcp_config.json`

Define all MCP servers that should be aggregated:

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
      "url": "https://other-server.com/sse",
      "transport": "sse"
    }
  }
}
```

### `/data/users.json`

Define authorized users (whitelist):

```json
{
  "user@example.com": {
    "name": "User Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  },
  "friend@example.com": {
    "name": "Friend Name",
    "roles": ["user"],
    "allowed_tools": ["filesystem:*", "time:*"]
  }
}
```

### `/data/auth_config.json`

Auth provider configuration (auto-generated, can be customized):

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

## Environment Variables

### Authentication (Required for OAuth)

| Variable | Description | Example |
|----------|-------------|---------|
| `MCP_AUTH_PROVIDER` | Enable OAuth: `oauth_proxy` | `oauth_proxy` |
| `AUTH0_CLIENT_ID` | Auth0 application client ID | From Auth0 Settings |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | From Auth0 Settings |
| `AUTH0_DOMAIN` | Auth0 tenant domain | `your-tenant.us.auth0.com` |
| `AUTH0_AUDIENCE` | Auth0 API identifier | `https://your-mcp-api` |
| `MCP_BASE_URL` | Your public server URL | `https://your-domain.com` |

### File Paths

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_CONFIG_PATH` | MCP servers configuration | `mcp_config.json` |
| `MCP_USERS_PATH` | Authorized users file | `/data/users.json` |
| `MCP_AUTH_CONFIG_PATH` | Auth provider config | `/data/auth_config.json` |

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_HOST` | Bind host address | `0.0.0.0` |
| `MCP_PORT` | Bind port | `8080` |
| `MCP_PATH_PREFIX` | URL path prefix for security | (none) |
| `MCP_LIVE_RELOAD` | Enable live config reload | `false` |
| `MCP_MAX_RETRIES` | Config load retries | `3` |
| `MCP_RESTART_DELAY` | Restart delay (seconds) | `5` |

## Deployment

### Docker Compose Example

```yaml
version: "3.8"

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    ports:
      - "8080:8080"
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
      - ./data:/data
    environment:
      # Auth0 OAuth Configuration
      - MCP_AUTH_PROVIDER=oauth_proxy
      - AUTH0_CLIENT_ID=${AUTH0_CLIENT_ID}
      - AUTH0_CLIENT_SECRET=${AUTH0_CLIENT_SECRET}
      - AUTH0_DOMAIN=${AUTH0_DOMAIN}
      - AUTH0_AUDIENCE=${AUTH0_AUDIENCE}

      # MCP Proxy Configuration
      - MCP_BASE_URL=https://mcp.your-domain.com
      - MCP_USERS_PATH=/data/users.json
      - MCP_AUTH_CONFIG_PATH=/data/auth_config.json

      # Optional: Live reload on config changes
      - MCP_LIVE_RELOAD=true
    restart: unless-stopped

  # Optional: Cloudflare Tunnel for secure public access
  cloudflared:
    image: cloudflare/cloudflared:latest
    command: tunnel --no-autoupdate run
    environment:
      - TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}
    depends_on:
      - mcp-proxy
    restart: unless-stopped
```

### Cloudflare Tunnel Setup

For secure remote access without exposing ports directly:

```bash
# 1. Install cloudflared
brew install cloudflare/cloudflare/cloudflared  # macOS
# or download from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

# 2. Authenticate
cloudflared tunnel login

# 3. Create tunnel
cloudflared tunnel create mcp-proxy

# 4. Create config
cat > ~/.cloudflared/config.yml << EOF
tunnel: mcp-proxy
credentials-file: /path/to/credentials

ingress:
  - hostname: mcp.your-domain.com
    service: http://localhost:8080
  - service: http_status:404
EOF

# 5. Start tunnel
cloudflared tunnel run mcp-proxy
```

Then set `MCP_BASE_URL=https://mcp.your-domain.com` in your `.env`.

## Security

### Best Practices

✅ **Always use HTTPS** - Use Cloudflare Tunnel or similar for public access
✅ **Secure Auth0 credentials** - Store in environment variables only, never in git
✅ **Use `.env` file** - Add to `.gitignore` to prevent accidental commits
✅ **Whitelist users** - Only add authorized users to `/data/users.json`
✅ **Enable Auth0 MFA** - Require multi-factor authentication on your Auth0 account
✅ **Rotate credentials** - Periodically update Auth0 client secret (every 90 days minimum)
✅ **Bind to localhost** - Use `127.0.0.1` instead of `0.0.0.0` when behind a proxy/tunnel
✅ **Strong tokens** - Generate with `openssl rand -hex 32` (minimum 32 bytes)

### Built-in Security

- **OAuth 2.1 + PKCE** - Industry-standard authentication with forward secrecy
- **JWT Token Validation** - Tokens validated using Auth0's public JWKS endpoint
- **Consent Screen** - Users must explicitly approve each client (prevents confused deputy attacks)
- **Encrypted Token Storage** - OAuth tokens encrypted at rest using Fernet encryption
- **User Whitelist** - Only pre-approved users (in `users.json`) can access tools

### Configuration Security

The `mcp_config.json` file supports environment variable substitution using `${VAR_NAME}` or `${VAR_NAME:-default}`:

```json
{
  "mcpServers": {
    "example": {
      "url": "${API_URL}",
      "headers": {
        "api-key": "${API_KEY}"
      }
    }
  }
}
```

**⚠️ Never commit credentials to git!** Always use environment variables for sensitive data.

## Development

### Local Testing

```bash
# Clone and setup
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy

# Create development .env
cat > .env << EOF
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_CLIENT_SECRET=your-auth0-client-secret
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_AUDIENCE=https://localhost:8000
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=http://localhost:8080
MCP_USERS_PATH=./data/users.json
MCP_AUTH_CONFIG_PATH=./data/auth_config.json
EOF

# Install dependencies
pip install -r requirements.txt

# Create data directory and users
mkdir -p data
cat > data/users.json << EOF
{
  "your-email@example.com": {
    "name": "Your Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  }
}
EOF

# Run server
python proxy_server.py
```

Then access at `http://localhost:8080/mcp`

### Testing with cURL

```bash
# Test health endpoint (no auth required)
curl http://localhost:8080/health

# Expected response:
# {
#   "status": "healthy",
#   "version": "1.0.x",
#   "servers": ["filesystem", "time"],
#   "path_prefix": null
# }

# Test OAuth well-known endpoints
curl http://localhost:8080/.well-known/oauth-protected-resource
curl http://localhost:8080/.well-known/oauth-authorization-server
```

### Docker Build

```bash
# Build for local platform
docker build -t mcp-proxy:dev .

# Build multi-arch (requires buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t mcp-proxy:dev .
```

## Troubleshooting

### "There was an error connecting to your server. Please check your server URL and make sure your server handles auth correctly."

**Cause:** DCR (Dynamic Client Registration) failed, usually due to:
- Invalid Auth0 credentials
- Missing or incorrect `MCP_BASE_URL`
- Auth0 domain doesn't match configuration

**Solution:**
1. Verify Auth0 credentials in `.env`
2. Check `MCP_BASE_URL` matches your actual domain
3. Check server logs: `docker logs mcp-proxy`

### "Unauthorized" (401) on MCP requests

**Cause:** OAuth token validation failed

**Solutions:**
1. Verify user email is in `/data/users.json`
2. Check Auth0 domain and JWKS endpoint are reachable
3. Ensure JWT token hasn't expired
4. Check server logs for validation errors

### "Connection refused"

**Cause:** Server not running or port not accessible

**Solutions:**
1. Check container status: `docker-compose ps`
2. View logs: `docker-compose logs -f mcp-proxy`
3. Verify port is exposed: `docker ps | grep mcp-proxy`
4. Check firewall rules

### Tools not showing in Claude

**Cause:** Server responding but tools not listed

**Solutions:**
1. Verify `mcp_config.json` is valid JSON
2. Check MCP servers are actually running: `docker logs mcp-proxy`
3. Verify server configuration paths exist
4. Check network connectivity to remote servers (if using SSE/HTTP servers)
5. Wait 10-15 seconds for MCP servers to initialize (npm/npx servers take time)

## Environment Variables Reference

### Quick Setup Template

```bash
# Auth0 (from https://manage.auth0.com)
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=
AUTH0_DOMAIN=
AUTH0_AUDIENCE=

# MCP Proxy
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=
MCP_USERS_PATH=/data/users.json
MCP_AUTH_CONFIG_PATH=/data/auth_config.json

# Optional
MCP_LIVE_RELOAD=true
```

## Versioning

This project uses automatic semantic versioning:

- **Format:** `Major.Minor.Patch` (e.g., `1.0.5`)
- **Patch auto-increments** on each push to main
- **Manual bumps** for major/minor releases

## License

MIT License - see LICENSE file for details

## Support

- **Issues:** GitHub Issues for bug reports and feature requests
- **Discussions:** GitHub Discussions for questions and ideas
- **Backlog:** See `docs/BACKLOG.md` for planned improvements

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Related Resources

- [FastMCP Documentation](https://gofastmcp.com) - Official FastMCP docs
- [MCP Specification](https://modelcontextprotocol.io) - Official MCP spec
- [Auth0 Documentation](https://auth0.com/docs) - Auth0 guides and references
- [OAuth 2.1 Specification](https://tools.ietf.org/html/draft-ietf-oauth-v2-1-10) - OAuth standards
