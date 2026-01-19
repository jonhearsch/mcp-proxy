# MCP Proxy Server - Use Claude.ai Remotely with Any MCP Server

**Stop working from your local machine.** Access your Model Context Protocol (MCP) servers from anywhere using Claude.ai - securely aggregate multiple MCP tools through one remote endpoint with Google OAuth authentication.

**Use Claude.ai with remote MCP servers** - filesystem, database, API, and custom tools accessible from any device.

---

### 🎯 Perfect for:

- **Remote MCP access** - Use Claude.ai tools from anywhere, not just localhost
- **Team collaboration** - Share MCP servers securely across your organization
- **Cloud deployments** - Host MCP tools on VPS, Docker, Kubernetes, or serverless
- **Multi-device workflows** - Switch between work laptop, home desktop, and mobile
- **Centralized tool management** - One endpoint for all your MCP servers

## Why MCP Proxy?

**Problems:**

1. Claude's MCP support only works with servers running on your local machine
2. You can't access your tools remotely, share with teammates, or use from different devices
3. Managing authentication for remote MCP access is complex

**Solution:** MCP Proxy is a **remote MCP server gateway** that lets you:

- ✅ Access Claude.ai tools from **anywhere** (not just localhost)
- ✅ Use Claude.ai with any MCP-compatible client remotely
- ✅ Deploy MCP servers once, use everywhere
- ✅ Share tools securely with team members via Google OAuth
- ✅ Aggregate multiple MCP servers into one endpoint

## Features

### Remote Access & Deployment

- 🌐 **Remote MCP Server Access** - Use Claude.ai from anywhere, not just your local machine
- ☁️ **Cloud-Ready** - Deploy to AWS, GCP, Azure, DigitalOcean, Railway, Render, or any VPS
- 🐳 **Docker Support** - One-line deployment with multi-architecture support (AMD64/ARM64)
- 🔒 **Secure Remote Access** - Built-in Google OAuth 2.0 authentication
- 🔐 **Cloudflare Tunnel Ready** - Expose securely without public IP or port forwarding

### MCP Server Management

- 🚀 **Multi-Server Aggregation** - Combine stdio (uvx, npx), SSE, and HTTP MCP servers
- 📝 **Claude-Compatible Config** - Same JSON format as Claude Desktop configuration
- 🔄 **Live Config Reload** - Add/remove servers without restarting
- ✅ **Claude.ai Compatible** - Works seamlessly with Claude.ai and other MCP clients
- 🏥 **Auto-Restart & Health Checks** - Resilient server lifecycle management

### Security & Control

- 🔐 **Google OAuth Authentication** - Secure, trusted authentication via Google accounts
- 👤 **User Identity Tracking** - Know which team member is using which tools
- 🔐 **Zero-Trust Ready** - Works with network segmentation and access policies
- 🔒 **Production-Ready** - JWT signing keys, HTTPS enforcement

## Quick Start - Remote MCP in 10 Minutes

Get Claude.ai working with remote MCP servers in 3 steps:

### Prerequisites

- **Docker** (easiest) or **Python 3.10+** (for development)
- **Google Cloud Account** (free)
- **Public URL** - Domain, VPS IP, or Cloudflare Tunnel (free options below)

### 1. Google Cloud OAuth Setup (5 minutes)

1. **Go to Google Cloud Console**: https://console.developers.google.com/

2. **Create or Select a Project**
   - Click "Select a project" → "New Project"
   - Name: "MCP Proxy"
   - Click "Create"

3. **Configure OAuth Consent Screen**
   - Navigate to: **APIs & Services** → **OAuth consent screen**
   - Choose **External** (for public access) or **Internal** (G Workspace only)
   - Fill in required fields:
     - App name: "MCP Proxy"
     - User support email: your@email.com
     - Developer contact: your@email.com
   - Click "Save and Continue"
   - **Add Scopes**: Click "Add or Remove Scopes"
     - Select: `openid`, `email`
     - Or manually add: `https://www.googleapis.com/auth/userinfo.email`
   - Click "Save and Continue" through remaining screens

4. **Create OAuth Client ID**
   - Navigate to: **APIs & Services** → **Credentials**
   - Click **"+ CREATE CREDENTIALS"** → **"OAuth client ID"**
   - Application type: **"Web application"**
   - Name: "MCP Proxy Production"
   - **Authorized JavaScript origins**:
     - Add: `https://your-domain.com` (replace with your domain)
     - For local dev, also add: `http://localhost:8080`
   - **Authorized redirect URIs**:
     - Add: `https://your-domain.com/auth/callback`
     - For local dev, also add: `http://localhost:8080/auth/callback`
   - Click **"CREATE"**

5. **Copy Credentials**
   - Copy the **Client ID** (ends with `.apps.googleusercontent.com`)
   - Copy the **Client Secret** (starts with `GOCSPX-`)
   - Save these securely - you'll need them in step 2

**Important Notes:**

- HTTPS is required for production (Google only allows HTTP for localhost)
- Redirect URI must match exactly (including port if non-standard)
- For Cloudflare Tunnel, use your tunnel URL

### 2. Configure MCP Proxy

#### Create `mcp_config.json`

Copy the example config and customize with your MCP servers:

```bash
cp mcp_config.example.json mcp_config.json
```

Edit the file to define which MCP servers to proxy:

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

**Supported server types:**

- **stdio servers**: `uvx`, `npx` commands (like above)
- **HTTP servers**: `{"url": "https://server.com/mcp", "transport": "http"}`
- **SSE servers**: `{"url": "https://server.com/sse", "transport": "sse"}`

#### Create `.env`

Create a `.env` file with your Google OAuth credentials:

```bash
# Google OAuth Credentials (from step 1)
GOOGLE_CLIENT_ID=123456789-abc123def456.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123def456ghi789

# Public URL where MCP Proxy is accessible
# IMPORTANT: Must match authorized redirect URI in Google Cloud Console
MCP_BASE_URL=https://your-domain.com

# Optional: JWT signing key for production (generate with: openssl rand -hex 32)
# GOOGLE_JWT_KEY=your-32-byte-hex-key

# MCP Proxy Configuration
MCP_CONFIG_PATH=mcp_config.json
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_LIVE_RELOAD=true
```

### 3. Run MCP Proxy

#### Using Docker (Recommended)

```bash
docker run -d \
  --name mcp-proxy \
  -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  --env-file .env \
  --restart unless-stopped \
  ghcr.io/jonhearsch/mcp-proxy:latest
```

#### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    container_name: mcp-proxy
    ports:
      - "8080:8080"
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

Start with:

```bash
docker-compose up -d
```

#### Using Python (Development)

```bash
# Clone repository
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy

# Install dependencies
pip install -r requirements.txt

# Run server
python proxy_server.py
```

### 4. Connect Claude.ai

1. **Deploy with HTTPS** (required by Google OAuth)
   - Use Cloudflare Tunnel, nginx reverse proxy, or cloud provider load balancer
   - Example Cloudflare Tunnel: See "Production Deployment" section below

2. **Add to Claude.ai**
   - Open Claude.ai settings
   - Navigate to MCP servers configuration
   - Add server URL: `https://your-domain.com/mcp`
   - Complete Google OAuth flow when prompted

3. **Test Tools**
   - Ask Claude: "What tools do you have available?"
   - Claude should list your configured MCP servers
   - Try using a tool: "List files in the current directory"

---

## Production Deployment

### Option 1: Cloudflare Tunnel (Easiest, Free HTTPS)

Cloudflare Tunnel provides free HTTPS without exposing ports or managing certificates.

#### Setup Cloudflare Tunnel

1. **Install cloudflared**

   ```bash
   # macOS
   brew install cloudflared

   # Linux
   wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
   sudo dpkg -i cloudflared-linux-amd64.deb
   ```

2. **Login to Cloudflare**

   ```bash
   cloudflared tunnel login
   ```

3. **Create Tunnel**

   ```bash
   cloudflared tunnel create mcp-proxy
   ```

4. **Create config file** (`~/.cloudflared/config.yml`):

   ```yaml
   tunnel: <your-tunnel-id>
   credentials-file: /home/user/.cloudflared/<your-tunnel-id>.json

   ingress:
     - hostname: mcp.your-domain.com
       service: http://localhost:8080
     - service: http_status:404
   ```

5. **Route DNS**

   ```bash
   cloudflared tunnel route dns mcp-proxy mcp.your-domain.com
   ```

6. **Run tunnel**

   ```bash
   cloudflared tunnel run mcp-proxy
   ```

7. **Update Google OAuth**
   - Add authorized origin: `https://mcp.your-domain.com`
   - Add redirect URI: `https://mcp.your-domain.com/auth/callback`
   - Update `.env`: `MCP_BASE_URL=https://mcp.your-domain.com`

### Option 2: VPS with Nginx (Traditional)

#### Install on Ubuntu/Debian VPS

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Clone and configure
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy
cp .env.example .env
nano .env  # Edit with your Google OAuth credentials

# Run with Docker Compose
docker-compose up -d
```

#### Nginx Reverse Proxy

Install nginx and certbot:

```bash
sudo apt install nginx certbot python3-certbot-nginx -y
```

Create `/etc/nginx/sites-available/mcp-proxy`:

```nginx
server {
    listen 80;
    server_name mcp.your-domain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Enable and get SSL certificate:

```bash
sudo ln -s /etc/nginx/sites-available/mcp-proxy /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d mcp.your-domain.com
```

### Option 3: Cloud Platforms

#### Railway.app

1. Connect GitHub repository
2. Add environment variables from `.env`
3. Deploy - Railway provides HTTPS automatically

#### Render.com

1. New Web Service → Connect repository
2. Add environment variables
3. Deploy - Render provides HTTPS automatically

#### DigitalOcean App Platform

1. Create new app → GitHub repository
2. Add environment variables
3. Deploy - Automatic HTTPS

---

## Configuration

### Environment Variables

| Variable               | Required | Description                                   | Default           |
| ---------------------- | -------- | --------------------------------------------- | ----------------- |
| `GOOGLE_CLIENT_ID`     | ✅       | OAuth 2.0 Client ID from Google Cloud Console | -                 |
| `GOOGLE_CLIENT_SECRET` | ✅       | OAuth 2.0 Client Secret                       | -                 |
| `MCP_BASE_URL`         | ✅       | Public URL for OAuth callbacks                | -                 |
| `GOOGLE_JWT_KEY`       | ⚠️       | JWT signing key (recommended for production)  | auto-generated    |
| `MCP_CONFIG_PATH`      | ❌       | Path to MCP servers config                    | `mcp_config.json` |
| `MCP_HOST`             | ❌       | Server bind address                           | `0.0.0.0`         |
| `MCP_PORT`             | ❌       | Server bind port                              | `8080`            |
| `MCP_LIVE_RELOAD`      | ❌       | Enable live config reload                     | `false`           |
| `MCP_MAX_RETRIES`      | ❌       | Config load retry attempts                    | `3`               |
| `MCP_RESTART_DELAY`    | ❌       | Initial restart delay (seconds)               | `5`               |
| `MCP_LOG_LEVEL`        | ❌       | Global log level                              | `INFO`            |

### MCP Server Configuration

The `mcp_config.json` file uses the same format as Claude Desktop.

**Getting Started**: Copy the example config to create your own:

```bash
cp mcp_config.example.json mcp_config.json
```

Your `mcp_config.json` is automatically ignored by git to prevent committing sensitive server URLs or credentials.

**Note**: Copy `mcp_config.example.json` to `mcp_config.json` to get started. The example file is version controlled; your `mcp_config.json` is gitignored to prevent committing sensitive configs.

#### Stdio Servers (npx, uvx)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "python-server": {
      "command": "uvx",
      "args": ["mcp-server-git", "--repository", "/path/to/repo"]
    }
  }
}
```

#### Remote HTTP/SSE Servers

```json
{
  "mcpServers": {
    "remote-api": {
      "url": "https://api.example.com/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}"
      }
    },
    "sse-server": {
      "url": "https://events.example.com/sse",
      "transport": "sse"
    }
  }
}
```

#### Mixed Configuration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    },
    "remote-api": {
      "url": "https://api.example.com/mcp",
      "transport": "http"
    },
    "database": {
      "command": "uvx",
      "args": ["mcp-server-postgres", "--connection-string", "${DATABASE_URL}"]
    }
  }
}
```

---

## Security Best Practices

### Production Checklist

- [ ] **Use HTTPS** - Required by Google OAuth (use Cloudflare Tunnel, Let's Encrypt, or cloud provider)
- [ ] **Set JWT signing key** - Generate with `openssl rand -hex 32`, set `GOOGLE_JWT_KEY`
- [ ] **Restrict origins** - Only add necessary domains to Google Cloud Console authorized origins
- [ ] **Use environment variables** - Never commit `.env` to git (add to `.gitignore`)
- [ ] **Regular updates** - Keep Docker image updated: `docker pull ghcr.io/jonhearsch/mcp-proxy:latest`
- [ ] **Monitor logs** - Check for authentication failures: `docker logs mcp-proxy`
- [ ] **Firewall rules** - Only expose ports 80/443 publicly
- [ ] **Backup configuration** - Keep `mcp_config.json` backed up

### Securing MCP Servers

```json
{
  "mcpServers": {
    "sensitive-api": {
      "command": "npx",
      "args": ["-y", "mcp-server-custom"],
      "env": {
        "API_KEY": "${SENSITIVE_API_KEY}",
        "DATABASE_URL": "${DATABASE_URL}"
      }
    }
  }
}
```

Store secrets in `.env`:

```bash
SENSITIVE_API_KEY=sk-prod-abc123...
DATABASE_URL=postgresql://user:pass@host/db
```

---

## Troubleshooting

### OAuth Authentication Issues

**Problem:** "OAuth authentication is required but not configured"

```
Solution: Check environment variables are set correctly:
  export GOOGLE_CLIENT_ID="123456789-abc.apps.googleusercontent.com"
  export GOOGLE_CLIENT_SECRET="GOCSPX-abc123..."
  export MCP_BASE_URL="https://your-domain.com"
```

**Problem:** "Redirect URI mismatch" error

```
Solution: Ensure Google Cloud Console redirect URI matches exactly:
  - Authorized redirect URI: https://your-domain.com/auth/callback
  - MCP_BASE_URL must match: https://your-domain.com
  - No trailing slashes, must include protocol
```

**Problem:** "JavaScript origin blocked"

```
Solution: Add authorized JavaScript origin in Google Cloud Console:
  - Authorized JavaScript origins: https://your-domain.com
  - Must match your MCP_BASE_URL domain
```

### Server Connection Issues

**Problem:** MCP servers fail to start

```bash
# Check logs
docker logs mcp-proxy

# Verify mcp_config.json is valid JSON
cat mcp_config.json | jq .

# Test individual server manually
npx -y @modelcontextprotocol/server-filesystem /data
```

**Problem:** "Port already in use"

```bash
# Find process using port 8080
sudo lsof -i :8080

# Stop existing process or use different port
MCP_PORT=8081 python proxy_server.py
```

**Problem:** Health check fails

```bash
# Test health endpoint
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","service":"mcp-proxy"}
```

### Google OAuth Setup Issues

**Problem:** Can't find OAuth consent screen

```
Solution: Ensure you've selected the correct project in Google Cloud Console
  - Top navigation bar → Select correct project
  - If no projects exist, create one first
```

**Problem:** "App not verified" warning

```
Solution: Normal for test/dev. For production:
  - Complete OAuth consent screen verification process
  - Or limit to Google Workspace organization (Internal app)
```

---

## Development

### Local Development

```bash
# Clone repository
git clone https://github.com/jonhearsch/mcp-proxy.git
cd mcp-proxy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up local OAuth (use http://localhost:8080)
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
export MCP_BASE_URL="http://localhost:8080"

# Run with live reload
export MCP_LIVE_RELOAD=true
python proxy_server.py
```

### Testing OAuth Flow

```bash
# 1. Start server
python proxy_server.py

# 2. Visit in browser (will redirect to Google OAuth)
open http://localhost:8080/.well-known/oauth-authorization-server

# 3. Check DCR endpoint
curl -X POST http://localhost:8080/dcr \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost"]}'

# 4. Check health (no auth required)
curl http://localhost:8080/health
```

### Building Docker Image

```bash
# Build
docker build -t mcp-proxy:local .

# Test locally
docker run -p 8080:8080 \
  -v $(pwd)/mcp_config.json:/app/mcp_config.json:ro \
  --env-file .env \
  mcp-proxy:local
```

---

## FAQ

### Why Google OAuth instead of API keys?

Claude.ai requires OAuth with Dynamic Client Registration (DCR). Google OAuth provides:

- Trusted authentication via Google accounts
- No manual API key management
- Built-in user identity tracking
- Compatible with Claude.ai's security requirements

### Can I use a different OAuth provider?

The current version is optimized for Google OAuth for Claude.ai compatibility. For other providers, check out the git history for previous OAuth implementations or contribute a provider!

### What MCP servers are supported?

All MCP servers that support:

- **stdio transport**: npx, uvx commands
- **HTTP transport**: REST API-style servers
- **SSE transport**: Server-Sent Events servers

Examples: filesystem, git, postgres, slack, github, custom servers.

### How do I update to the latest version?

```bash
# Docker
docker pull ghcr.io/jonhearsch/mcp-proxy:latest
docker-compose down && docker-compose up -d

# Python
git pull
pip install -r requirements.txt --upgrade
```

### Can I run multiple MCP Proxy instances?

Yes! Each instance can have different configurations:

```bash
# Instance 1 - Production
MCP_PORT=8080 MCP_CONFIG_PATH=prod_config.json python proxy_server.py &

# Instance 2 - Development
MCP_PORT=8081 MCP_CONFIG_PATH=dev_config.json python proxy_server.py &
```

### How do I monitor the server?

```bash
# Docker logs
docker logs -f mcp-proxy

# Health check
curl http://localhost:8080/health

# Detailed logs
MCP_LOG_LEVEL=DEBUG python proxy_server.py
```

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- **Issues**: https://github.com/jonhearsch/mcp-proxy/issues
- **Discussions**: https://github.com/jonhearsch/mcp-proxy/discussions
- **Documentation**: [CLAUDE.md](CLAUDE.md)

---

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp) by [@jlowin](https://github.com/jlowin)
- Model Context Protocol by [Anthropic](https://www.anthropic.com/)
- Inspired by the MCP community

---

**Made with ❤️ for the Claude.ai community**
