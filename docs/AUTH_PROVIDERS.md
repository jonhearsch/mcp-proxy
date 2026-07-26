# Google OAuth Authentication

**MCP Proxy v3.0+ uses Google OAuth 2.0 exclusively** for secure, trusted authentication that's compatible with Claude.ai, Claude Code, and other MCP clients.

## Why Google OAuth?

- ✅ **Native Claude.ai Support** - Claude.ai requires OAuth with Dynamic Client Registration (DCR)
- 🔐 **Trusted Authentication** - Leverages Google's secure authentication infrastructure
- 🎯 **Simple Setup** - Single provider, no complex configuration files
- 🔧 **Built-in DCR** - FastMCP's GoogleProvider handles DCR automatically
- 🌍 **Universal Access** - Anyone with a Google account can authenticate
- 📊 **Google Workspace** - Supports both personal and Google Workspace accounts

## Breaking Changes from v2.x

**MCP Proxy v3.0.0 removed support for:**

- ❌ API key authentication (`MCP_API_KEYS`)
- ❌ Auth0 provider
- ❌ Keycloak provider
- ❌ Okta provider
- ❌ Generic OIDC provider
- ❌ `auth_config.json` configuration file
- ❌ `MCP_DISABLE_AUTH` flag

**Migration**: If you need Auth0/Keycloak/Okta, check out the v2.0.x branch or contribute a provider implementation!

---

## Google Cloud Console Setup

### Step-by-Step Guide

#### 1. Access Google Cloud Console

Go to https://console.developers.google.com/

#### 2. Create or Select a Project

- Click "Select a project" → "New Project"
- Name: "MCP Proxy" (or your preferred name)
- Click "Create"

#### 3. Configure OAuth Consent Screen

- Navigate to: **APIs & Services** → **OAuth consent screen**
- Choose:
  - **External** - For public access (any Google account)
  - **Internal** - For Google Workspace only (restricts to your organization)
- Fill in required fields:
  - **App name**: "MCP Proxy"
  - **User support email**: your@email.com
  - **Developer contact**: your@email.com
- Click "Save and Continue"
- **Add Scopes**:
  - Click "Add or Remove Scopes"
  - Select: `openid`, `email`
  - Or manually add: `https://www.googleapis.com/auth/userinfo.email`
- Click "Save and Continue" through remaining screens
- Click "Back to Dashboard"

#### 4. Create OAuth Client ID

- Navigate to: **APIs & Services** → **Credentials**
- Click **"+ CREATE CREDENTIALS"** → **"OAuth client ID"**
- Application type: **"Web application"**
- Name: "MCP Proxy Production"
- **Authorized JavaScript origins**:
  - Production: `https://your-domain.com`
  - Local dev: `http://localhost:8080`
- **Authorized redirect URIs**:
  - Production: `https://your-domain.com/auth/callback`
  - Local dev: `http://localhost:8080/auth/callback`
- Click **"CREATE"**

#### 5. Copy Credentials

- Copy the **Client ID** (ends with `.apps.googleusercontent.com`)
- Copy the **Client Secret** (starts with `GOCSPX-`)
- Download JSON (optional, for backup)

### Environment Variables

Create a `.env` file in your project root:

```bash
# Google OAuth (Required)
GOOGLE_CLIENT_ID=123456789-abc123def456.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123def456ghi789
MCP_BASE_URL=https://mcp.your-domain.com

# Optional: JWT signing key for production
GOOGLE_JWT_KEY=  # Generate with: openssl rand -hex 32

# MCP Proxy Configuration
MCP_CONFIG_PATH=mcp_config.json
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_LIVE_RELOAD=true
```

**Security Notes:**

- ⚠️ **Never commit `.env` to git** - Add to `.gitignore`
- ⚠️ **Keep Client Secret private** - Treat like a password
- ⚠️ **Use HTTPS in production** - OAuth requires HTTPS (except localhost)
- ✅ **Generate JWT key for production** - Ensures token security across restarts
- ⚠️ **Known upstream risk**: [PrefectHQ/fastmcp#2867](https://github.com/PrefectHQ/fastmcp/issues/2867) reports that `GoogleProvider`'s `jwt_signing_key` can be silently ignored in favor of an internal ephemeral key, which would mean sessions don't actually survive a restart even with `GOOGLE_JWT_KEY` set. It was filed against an older fastmcp release; we haven't confirmed whether it reproduces on the version pinned in `requirements.txt`. Before relying on this in production, do a manual smoke test: obtain a client token, restart the proxy, and confirm the existing token is still accepted rather than forcing re-auth.

---

## FastMCP GoogleProvider API

MCP Proxy uses FastMCP's built-in `GoogleProvider` class:

```python
from fastmcp.server.auth.providers.google import GoogleProvider

# Create Google OAuth provider
auth = GoogleProvider(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    base_url=os.getenv("MCP_BASE_URL"),
    required_scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
    jwt_signing_key=os.getenv("GOOGLE_JWT_KEY"),  # Optional
)

# Use with FastMCP proxy
proxy = FastMCP.as_proxy(config, auth=auth, name="mcp-proxy")
```

### GoogleProvider Features

- ✅ **Automatic DCR** - Handles Dynamic Client Registration for Claude.ai
- ✅ **OAuth 2.0 Flow** - Manages authorization code flow with Google
- ✅ **Token Management** - Handles token exchange and validation
- ✅ **Session Storage** - Secure JWT-based session management
- ✅ **Scope Validation** - Ensures required scopes are granted
- ✅ **HTTPS Enforcement** - Validates proper OAuth security (except localhost)

### Implementation in mcp_proxy/auth.py

The `create_google_auth()` function in [mcp_proxy/auth.py](../mcp_proxy/auth.py):

```python
def create_google_auth() -> Optional[GoogleProvider]:
    """Create Google OAuth provider for Claude.ai integration."""
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    base_url = os.getenv("MCP_BASE_URL")
    jwt_key = os.getenv("GOOGLE_JWT_KEY")

    if not all([client_id, client_secret, base_url]):
        return None

    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        required_scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        jwt_signing_key=jwt_key if jwt_key else None,
    )
```

---

## Static Token Authentication (Gateway-Fronted)

Google OAuth is the right choice when an MCP client connects **directly** to this proxy. When the proxy sits **behind a gateway** that terminates OAuth itself, the proxy never participates in an OAuth flow — it only needs to verify that the caller is the gateway. For that, use a shared static token.

```
Claude.ai  ──OAuth──▶  agentgateway  ──Bearer <MCP_AUTH_TOKEN>──▶  mcp-proxy
```

### Configuration

```bash
# Generate a strong token
openssl rand -hex 32

# Set it in .env
MCP_AUTH_TOKEN=<generated-token>
```

Configure the gateway to **set** (not forward) this header on upstream requests:

```
Authorization: Bearer <MCP_AUTH_TOKEN>
```

### Implementation in mcp_proxy/auth.py

`create_static_token_auth()` uses FastMCP's built-in `StaticTokenVerifier`, so no custom middleware is involved — it is passed to the same `auth=` parameter as `GoogleProvider`:

```python
from fastmcp.server.auth import StaticTokenVerifier

auth = StaticTokenVerifier(
    tokens={token: {"client_id": "agentgateway", "scopes": []}}
)
```

The function returns `None` (and the server refuses to start) if the token is shorter than 32 characters, so a placeholder value cannot reach a deployed instance. The token is never written to logs — only its length.

### Security Properties

| Property | Google OAuth | Static Token |
| -------- | ------------ | ------------ |
| Per-user identity | ✅ | ❌ (single `client_id`) |
| Token expiry | ✅ | ❌ |
| Rotation | ✅ | ❌ (manual) |
| Constant-time comparison | ✅ | ❌ (plain dict lookup) |
| Works with direct Claude.ai | ✅ | ❌ |

`StaticTokenVerifier.verify_token()` performs a plain dictionary lookup rather than a constant-time comparison. Across a LAN behind a gateway this is not a practical concern, but it is worth knowing when deciding where to deploy this mode.

FastMCP's own docstring advises against `StaticTokenVerifier` in production. That warning targets multi-tenant deployments storing many users' tokens in plaintext; a single machine-to-machine credential shared between two services you control is the "API key-style authentication" case the same docstring describes. Use it accordingly.

### Not a Substitute for Network Scoping

The token stops casual access; the network boundary is what actually keeps untrusted traffic out. Apply both:

- Set `MCP_HOST=127.0.0.1` when the gateway runs on the same host.
- In Docker, put the proxy on a shared network with the gateway rather than publishing the port. Note `docker-compose.yml` uses `network_mode: "host"`, which binds directly to the host interface.

### Troubleshooting

**Every request returns 401 through the gateway.** The most likely cause is that the gateway is *forwarding* the client's `Authorization` header instead of *setting* a fixed one — the client's token overwrites the static token. Check the gateway's upstream header policy. If it cannot set a fixed `Authorization` header, a custom header such as `X-Proxy-Key` would require an ASGI shim, as `StaticTokenVerifier` only reads `Authorization`.

**Server exits at startup with "MCP_AUTH_TOKEN is too short".** The token is under 32 characters. Regenerate with `openssl rand -hex 32`.

---

## Testing Your Configuration

### Quick Setup

1. Create an Okta account at https://developer.okta.com (free tier available)
2. Create an **Application** → **Web Application**
3. Configure:
   - Sign-in redirect URIs: `https://your-domain.com/auth/callback`
   - Grant types: Authorization Code, Refresh Token
4. Copy Client ID and Client Secret

### 1. Check OAuth Metadata

```bash
# Authorization Server metadata
curl http://localhost:8080/.well-known/oauth-authorization-server

# Expected: JSON with authorization_endpoint, token_endpoint, etc.
```

### 2. Test Dynamic Client Registration (DCR)

```bash
curl -X POST http://localhost:8080/dcr \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "test-client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'

# Expected: 201 response with client_id and client_secret
```

### 3. Check Health Endpoint

```bash
curl http://localhost:8080/health

# Expected: {"status": "healthy", "service": "mcp-proxy"}
```

### 4. Check Server Logs

```bash
# If running with Docker
docker logs mcp-proxy

# If running locally
python -m mcp_proxy

# Look for:
# ✓ GoogleProvider successfully initialized
# ✓ Google OAuth authentication enabled (Claude.ai compatible)
# ✓ Created unified FastMCP proxy with N server(s)
```

### 5. Test with Claude.ai

1. Deploy proxy with HTTPS (required for OAuth)
2. Add MCP server in Claude settings:
   - Server URL: `https://your-domain.com/mcp`
3. Complete Google OAuth flow when prompted
4. Test tool access through Claude interface

---

## Troubleshooting

### "Google OAuth authentication is required but not configured"

**Cause:** Missing environment variables.

**Solution:** Set all required variables in `.env`:

```bash
GOOGLE_CLIENT_ID=123456789-abc123.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abc123def456
MCP_BASE_URL=https://your-domain.com
```

### "redirect_uri_mismatch" error

**Cause:** Redirect URI doesn't match Google Cloud Console configuration.

**Solution:**

1. Check `MCP_BASE_URL` matches your domain exactly
2. In Google Cloud Console, add `{MCP_BASE_URL}/auth/callback` to authorized redirect URIs
3. Add `{MCP_BASE_URL}` to authorized JavaScript origins

### "Invalid Client" error

**Cause:** Client ID or Client Secret is incorrect.

**Solution:**

1. Verify credentials in Google Cloud Console → APIs & Services → Credentials
2. Copy fresh Client ID and Client Secret
3. Update `.env` file
4. Restart proxy server

### OAuth flow redirects to wrong URL

**Cause:** `MCP_BASE_URL` doesn't match actual deployment URL.

**Solution:**

- Local: `MCP_BASE_URL=http://localhost:8080`
- Production: `MCP_BASE_URL=https://your-domain.com` (must use HTTPS)

### "Failed to create GoogleProvider" error

**Cause:** FastMCP version incompatible or Google OAuth not available.

**Solution:**

1. Update FastMCP: `pip install 'fastmcp>=3.4.4'`
2. Verify `from fastmcp.server.auth.providers.google import GoogleProvider` works
3. Check logs for specific error details

### HTTPS requirement

**Issue:** Google OAuth requires HTTPS in production.

**Solution:**

- **Local development**: Use `http://localhost:8080` (HTTP allowed)
- **Production**: Must use HTTPS - options include:
  - Cloudflare Tunnel (free, easy)
  - Let's Encrypt with Nginx/Caddy
  - Cloud provider load balancer (AWS ALB, GCP HTTPS LB)
  - Reverse proxy with SSL termination

---

## Debugging

### Enable Debug Logging

```bash
# Set in .env or environment
export MCP_LOG_LEVEL=DEBUG
export MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG"

# Start proxy
python -m mcp_proxy
```

This shows:

- Google OAuth configuration details (redacted)
- OAuth endpoint requests
- DCR registration attempts
- Token validation successes/failures
- HTTP requests to/from Google

### Check Google Cloud Console

**Verify OAuth Client Configuration:**

1. Go to: https://console.developers.google.com/
2. Navigate to: APIs & Services → Credentials
3. Click your OAuth Client ID
4. Verify:
   - ✅ Authorized JavaScript origins includes `{MCP_BASE_URL}`
   - ✅ Authorized redirect URIs includes `{MCP_BASE_URL}/auth/callback`
   - ✅ Client ID matches `GOOGLE_CLIENT_ID` in `.env`
   - ✅ Client Secret is valid (regenerate if unsure)

### Common Log Messages

**Success:**

```
✓ GoogleProvider successfully initialized
✓ Google OAuth authentication enabled (Claude.ai compatible)
✓ Created unified FastMCP proxy with 3 server(s)
Server running at http://0.0.0.0:8080
```

**Missing Configuration:**

```
Google OAuth authentication is required but not configured.
Set these environment variables:
  - GOOGLE_CLIENT_ID: OAuth 2.0 Client ID
  - GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
  - MCP_BASE_URL: Public URL of this proxy
```

---

## Security Best Practices

✅ **Never commit secrets to git** - Add `.env` to `.gitignore`
✅ **Use HTTPS in production** - OAuth requires HTTPS (except localhost)
✅ **Generate JWT signing key** - Use `openssl rand -hex 32` for `GOOGLE_JWT_KEY`
✅ **Rotate credentials regularly** - Update Client Secret every 90 days
✅ **Restrict redirect URIs** - Only whitelist exact URLs you control
✅ **Monitor OAuth logs** - Watch for suspicious authentication attempts
✅ **Use Google Workspace Internal** - If applicable, restrict to your organization

---

## Additional Resources

- **Google OAuth Documentation**: https://developers.google.com/identity/protocols/oauth2
- **Google Cloud Console**: https://console.developers.google.com/
- **FastMCP Documentation**: https://gofastmcp.com/
- **FastMCP Google Provider**: https://gofastmcp.com/integrations/google
- **Claude.ai MCP Support**: https://docs.anthropic.com/en/docs/model-context-protocol
- **MCP Proxy GitHub**: https://github.com/jlowin/mcp-proxy (or your repo URL)

---

## Contributing

Want to add support for other OAuth providers (Auth0, Keycloak, Okta, etc.)?

1. Check FastMCP's provider implementations for reference
2. Create a new provider class following FastMCP's provider API
3. Submit a pull request with documentation
4. See v2.0.x branch for historical Auth0/Keycloak/Okta implementations

**Note:** MCP Proxy v3.0+ focuses on Google OAuth for simplicity and Claude.ai compatibility. Other providers were removed to reduce complexity and maintenance burden.
✅ **Use HTTPS** - Always use TLS/SSL for production (Cloudflare Tunnel, Let's Encrypt, etc.)
✅ **Audit access** - Review user whitelist in `/data/users.json` regularly

---

## Need Help?

- **Provider Setup Issues:** Check provider-specific documentation linked above
- **Configuration Questions:** See example files in `docs/auth_examples/`
- **Bugs/Features:** Open an issue on GitHub
