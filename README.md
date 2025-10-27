# MCP Proxy Server - Use Claude AI Remotely with Any MCP Server

**Stop working from your local machine.** Access your Model Context Protocol (MCP) servers from anywhere using Claude AI - securely aggregate multiple MCP tools through one remote endpoint with OAuth 2.1 authentication.

**Use Claude Desktop or Web with remote MCP servers** - filesystem, database, API, and custom tools accessible from any device.

---

### 🎯 Perfect for:
- **Remote MCP access** - Use Claude AI tools from anywhere, not just localhost
- **Team collaboration** - Share MCP servers securely across your organization
- **Cloud deployments** - Host MCP tools on VPS, Docker, Kubernetes, or serverless
- **Multi-device workflows** - Switch between work laptop, home desktop, and mobile
- **Centralized tool management** - One endpoint for all your MCP servers

## Why MCP Proxy?

**Problem:** Claude's MCP support only works with servers running on your local machine. You can't access your tools remotely, share with teammates, or use Claude from different devices.

**Solution:** MCP Proxy is a **remote MCP server gateway** that lets you:
- ✅ Access Claude AI tools from **anywhere** (not just localhost)
- ✅ Use Claude Desktop, Claude Web, or any MCP client remotely
- ✅ Deploy MCP servers once, use everywhere
- ✅ Share tools securely with team members
- ✅ Aggregate multiple MCP servers into one endpoint

## Features

### Remote Access & Deployment
- 🌐 **Remote MCP Server Access** - Use Claude AI from anywhere, not just your local machine
- ☁️ **Cloud-Ready** - Deploy to AWS, GCP, Azure, DigitalOcean, Railway, Render, or any VPS
- 🐳 **Docker Support** - One-line deployment with multi-architecture support (AMD64/ARM64)
- 🔒 **Secure Remote Access** - Built-in OAuth 2.1 + PKCE authentication via Auth0
- 🔐 **Cloudflare Tunnel Ready** - Expose securely without public IP or port forwarding

### MCP Server Management
- 🚀 **Multi-Server Aggregation** - Combine stdio (uvx, npx), SSE, and HTTP MCP servers
- 📝 **Claude-Compatible Config** - Same JSON format as Claude Desktop configuration
- 🔄 **Live Config Reload** - Add/remove servers without restarting
- ✅ **Claude Connector Compatible** - Works with Claude AI's official MCP Connector API
- 🏥 **Auto-Restart & Health Checks** - Resilient server lifecycle management

### Security & Control
- 👤 **User Identity Tracking** - Know which team member is using which tools
- 🎫 **Granular Permissions** - Control tool access per user with allow/deny lists
- 🔐 **Zero-Trust Ready** - Works with network segmentation and access policies
- 🔒 **Encrypted Tokens** - OAuth tokens encrypted at rest

## Quick Start - Remote MCP in 10 Minutes

Get Claude AI working with remote MCP servers in 3 steps:

### Prerequisites

- **Docker** (easiest) or **Python 3.10+** (for development)
- **Auth0 Account** - Free tier at https://auth0.com (handles OAuth authentication)
- **Public URL** - Domain, VPS IP, or Cloudflare Tunnel (free options below)

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

### 4. Connect Claude AI to Your Remote MCP Server

Now connect Claude to your remote MCP proxy:

1. **Open Claude** - Visit https://claude.ai or open Claude Desktop
2. **Go to Settings** → **MCP Connectors**
3. **Add Connection** - Click **+ Add Connection**
4. **Enter URL** - Use your remote server: `https://your-domain.com/mcp`
5. **Authenticate** - Log in via Auth0 (opens in browser)
6. **Grant Access** - Approve the consent screen
7. **Done!** - Claude now has access to all your remote MCP tools

**You can now use Claude from any device** - work laptop, home computer, or mobile - all connected to the same remote MCP servers.

## How Remote MCP Access Works

Instead of Claude only talking to localhost MCP servers, it connects to your remote proxy:

```
┌─────────────────────────────┐
│  Claude AI (Any Device)     │
│  • Desktop app              │
│  • Web browser              │
│  • Mobile (future)          │
└────────────┬────────────────┘
             │
             │ HTTPS + OAuth 2.1
             │ (Secure Remote Access)
             ↓
    ┌─────────────────────────────┐
    │   🌐 Your Remote Server     │
    │   (VPS, Cloud, or Home)     │
    │                             │
    │  ┌──────────────────────┐   │
    │  │  MCP Proxy           │   │
    │  │  • Auth0 OAuth       │   │
    │  │  • User validation   │   │
    │  │  • Token encryption  │   │
    │  └──────────┬───────────┘   │
    │             │                │
    │             ↓                │
    │  ┌──────────────────────┐   │
    │  │ Aggregated Endpoint  │   │
    │  │ All tools at /mcp/   │   │
    │  └──────────┬───────────┘   │
    └─────────────┼────────────────┘
                  │
         ┌────────┴────────┐
         ↓                 ↓
    ┌─────────┐      ┌──────────┐
    │  MCP    │      │   MCP    │
    │ Server 1│      │ Server 2 │
    │(Files)  │      │ (DB/API) │
    └─────────┘      └──────────┘
```

**Result:** Use Claude AI from anywhere while your MCP servers run in one central location.

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

## Deployment Options for Remote Access

Choose your hosting strategy based on your needs:

### Option 1: Cloud VPS (DigitalOcean, Linode, AWS, etc.)

**Best for:** Production deployments, team use, always-on access

1. Spin up a $5-10/month VPS with Docker
2. Point a domain to your server IP
3. Deploy with Docker Compose (see below)
4. Access from anywhere: `https://mcp.yourdomain.com`

### Option 2: Home Server + Cloudflare Tunnel (Free!)

**Best for:** Personal use, no VPS cost, secure remote access

1. Run MCP Proxy on a Raspberry Pi or home computer
2. Use Cloudflare Tunnel for free HTTPS access (no port forwarding!)
3. Access from anywhere without exposing your home IP

See [Cloudflare Tunnel Setup](#cloudflare-tunnel-setup) below.

### Option 3: PaaS (Railway, Render, Fly.io)

**Best for:** Zero DevOps, auto-scaling, simple setup

Deploy with one click to platforms that auto-configure HTTPS and domains.

---

### Docker Compose Example (Works for All Options)

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

### Cloudflare Tunnel Setup (Free Remote Access!)

**Use this for:**
- Remote access from anywhere without a VPS
- Exposing your home server securely (no port forwarding)
- Free HTTPS with automatic SSL certificates
- Works with Claude AI from any device

**Setup:**

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

**Now Claude can access your MCP servers remotely** - even if they're running on a home Raspberry Pi!

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

## Use Cases for Remote MCP Access

### 1. **Remote Work & Travel**
Access your development tools, databases, and file systems from anywhere using Claude AI - coffee shop, coworking space, or home office.

### 2. **Team Collaboration**
Share MCP servers across your team. One deployment, multiple users, granular permissions.

### 3. **Multi-Device Workflows**
Start a conversation on your laptop, continue on desktop, check on mobile - same tools, different devices.

### 4. **Cloud-Native Development**
Host MCP servers in your cloud environment (AWS, GCP, Azure) and access via Claude from anywhere.

### 5. **Centralized Tool Management**
Update MCP server configurations once, all team members get changes instantly (with live reload).

### 6. **Home Lab Access**
Run MCP servers on home infrastructure, access remotely via Cloudflare Tunnel - no VPS costs.

---

## Common Questions (SEO FAQ)

**Q: Can Claude AI access remote MCP servers?**
A: Yes, using MCP Proxy. Deploy this server to make any MCP server remotely accessible to Claude Desktop or Web.

**Q: How do I use MCP servers from outside localhost?**
A: MCP Proxy acts as a gateway - deploy it with Docker, point Claude to your remote URL, authenticate via OAuth.

**Q: Can I use Claude AI MCP tools from different computers?**
A: Yes! Once MCP Proxy is deployed remotely, any device with Claude (desktop/web) can connect using the same URL.

**Q: How do I share MCP servers with my team?**
A: Deploy MCP Proxy to a remote server, add team members to `users.json`, they authenticate and get access.

**Q: Does this work with Claude Desktop and Claude Web?**
A: Yes, both. Any client supporting MCP Connectors API works with MCP Proxy.

**Q: Can I deploy MCP servers to the cloud?**
A: Yes, MCP Proxy runs on Docker - deploy to AWS, GCP, DigitalOcean, Railway, Render, or any hosting platform.

---

## Related Resources

- [Model Context Protocol (MCP) Specification](https://modelcontextprotocol.io) - Official MCP protocol docs
- [FastMCP Documentation](https://gofastmcp.com) - Python framework powering this proxy
- [Claude AI MCP Documentation](https://docs.anthropic.com/claude/docs/model-context-protocol) - How Claude uses MCP
- [Auth0 Documentation](https://auth0.com/docs) - OAuth provider setup guides
- [Cloudflare Tunnel Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) - Free remote access setup
