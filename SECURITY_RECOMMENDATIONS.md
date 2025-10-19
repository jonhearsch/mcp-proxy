# Security Recommendations

Security implementation guide for MCP Proxy Server based on MCP specification best practices and FastMCP capabilities.

## Overview

This document outlines security approaches for protecting the MCP Proxy endpoint, ranging from simple token-based authentication to enterprise OAuth 2.1 implementations.

## Recommended Approach: Multi-Layer Defense

**Best Practice:** Combine application-layer and network-layer security for defense-in-depth.

### Recommended Stack

1. **FastMCP OAuth 2.1 or Bearer Token** (Application layer)
2. **Cloudflare Tunnel with Service Tokens** (Network layer)

---

## Security Implementation Options

### Option 1: FastMCP OAuth 2.1 ⭐ Recommended for Production

Enterprise-grade authentication with per-user access control.

```python
from fastmcp import FastMCP
from fastmcp.auth import OAuthProvider
import os

# Create proxy with OAuth
proxy = FastMCP.as_proxy(
    config,
    name="MCP Proxy Hub",
    auth=OAuthProvider(
        provider="google",  # or github, azure, auth0, workos
        client_id=os.getenv("OAUTH_CLIENT_ID"),
        client_secret=os.getenv("OAUTH_CLIENT_SECRET"),
        scopes=["mcp:read", "mcp:write"]
    )
)
```

**Pros:**

- ✅ Industry standard OAuth 2.1 compliance
- ✅ User-level authentication and attribution
- ✅ Fine-grained permissions per user
- ✅ Audit trail for compliance
- ✅ Enterprise providers (Google, GitHub, Azure, Auth0, WorkOS)
- ✅ PKCE support for public clients
- ✅ Token refresh mechanism

**Cons:**

- ❌ Requires OAuth provider setup and configuration
- ❌ More complex initial implementation
- ❌ User consent flow required
- ❌ External dependency on OAuth provider

**Use Cases:**

- Multi-tenant deployments
- User-facing applications
- Compliance/audit requirements
- Enterprise environments

---

### Option 2: FastMCP Bearer Token ⭐ Recommended for Quick Start

Simple token-based authentication with multi-tier access control.

**Note:** As of the latest version, `MCP_BEARER_TOKEN` is **REQUIRED** by default. The server will fail to start if not set (unless auth is explicitly disabled with `MCP_DISABLE_AUTH=true`).

```python
from fastmcp import FastMCP
from fastmcp.auth import BearerTokenAuth
import os

# Simple token-based auth with JWT
proxy = FastMCP.as_proxy(
    config,
    name="MCP Proxy Hub",
    auth=BearerTokenAuth(
        tokens={
            os.getenv("MCP_READ_TOKEN"): {
                "scopes": ["tools:list", "resources:read"]
            },
            os.getenv("MCP_WRITE_TOKEN"): {
                "scopes": ["tools:call", "resources:write"]
            },
            os.getenv("MCP_ADMIN_TOKEN"): {
                "scopes": ["*"]
            }
        },
        verify_signature=True,
        issuer="mcp-proxy",
        secret=os.getenv("JWT_SECRET")
    )
)
```

**Environment Variables:**

```bash
# Generate secure tokens - REQUIRED (unless MCP_DISABLE_AUTH=true)
MCP_BEARER_TOKEN=$(openssl rand -hex 32)

# For multi-tier access (optional):
MCP_READ_TOKEN=$(openssl rand -hex 32)
MCP_WRITE_TOKEN=$(openssl rand -hex 32)
MCP_ADMIN_TOKEN=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 64)
```

**Pros:**

- ✅ Quick to implement
- ✅ No external dependencies
- ✅ Multi-tier access control (read/write/admin)
- ✅ Good for service-to-service auth
- ✅ JWT signature verification available
- ✅ Low operational overhead

**Cons:**

- ❌ Manual token management required
- ❌ No user attribution
- ❌ Token rotation is manual process
- ❌ Shared secrets model

**Use Cases:**

- Internal services
- Service-to-service communication
- Development/staging environments
- Simple deployments

---

### Option 3: Permit.io Middleware (ABAC)

Attribute-based access control with policy-as-code.

```python
from fastmcp import FastMCP
from permit_fastmcp import PermitMiddleware
import os

proxy = FastMCP.as_proxy(config, name="MCP Proxy Hub")

# Add Permit.io authorization middleware
proxy.add_middleware(
    PermitMiddleware(
        api_key=os.getenv("PERMIT_API_KEY"),
        pdp_url=os.getenv("PERMIT_PDP_URL"),
        # Optional: custom policy evaluation
        resource_mapper=lambda request: {
            "type": "mcp_tool",
            "attributes": {
                "tool_name": request.tool,
                "sensitivity": get_tool_sensitivity(request.tool)
            }
        }
    )
)
```

**Installation:**

```bash
pip install permit-fastmcp
```

**Pros:**

- ✅ Attribute-based access control (ABAC)
- ✅ Policy-as-code with version control
- ✅ Fine-grained per-tool authorization
- ✅ Built-in audit logging
- ✅ Dynamic policy updates without code changes
- ✅ ReBAC (relationship-based) support

**Cons:**

- ❌ External service dependency
- ❌ Additional cost (SaaS)
- ❌ Learning curve for policy language
- ❌ Network latency for policy checks

**Use Cases:**

- Complex authorization requirements
- Dynamic permission models
- Compliance-heavy environments
- Multi-tenant with complex hierarchies

---

### Option 4: Cloudflare Tunnel + Service Tokens

Zero-trust network access without exposing ports.

**Setup:**

```bash
# Install cloudflared
brew install cloudflare/cloudflare/cloudflared  # macOS
# or
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb  # Linux

# Authenticate
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create mcp-proxy

# Configure tunnel
cat > ~/.cloudflared/config.yml <<EOF
tunnel: <tunnel-id>
credentials-file: /path/to/<tunnel-id>.json

ingress:
  - hostname: mcp-proxy.yourdomain.com
    service: http://localhost:8080
    originRequest:
      noTLSVerify: false
      connectTimeout: 30s
      access:
        required: true
        teamName: your-team
        audTag: mcp-proxy
  - service: http_status:404
EOF

# Run tunnel
cloudflared tunnel run mcp-proxy
```

**Service Token Authentication:**

```bash
# Create service token in Cloudflare dashboard
# Add to requests:
curl -H "CF-Access-Client-Id: <client-id>" \
     -H "CF-Access-Client-Secret: <client-secret>" \
     https://mcp-proxy.yourdomain.com
```

**Pros:**

- ✅ Zero exposed ports (no inbound firewall rules)
- ✅ DDoS protection and rate limiting
- ✅ Service-to-service authentication via tokens
- ✅ WAF capabilities built-in
- ✅ Automatic TLS/HTTPS
- ✅ Free tier available
- ✅ Easy certificate management

**Cons:**

- ❌ Network-level only (no per-user auth)
- ❌ Cloudflare vendor dependency
- ❌ Doesn't solve MCP-level authorization
- ❌ Requires DNS control

**Use Cases:**

- Exposing internal services securely
- DDoS protection requirements
- Zero-trust network architecture
- Complement to application-layer auth

---

## Production Deployment: Layered Security

### Recommended Stack

```python
# proxy_server.py modifications
from fastmcp import FastMCP
from fastmcp.auth import BearerTokenAuth
import os

def create_proxy(config):
    """Create MCP proxy with security enabled."""

    # Authentication is enabled by default - MCP_BEARER_TOKEN is REQUIRED
    # Server will fail to start if not set (unless MCP_DISABLE_AUTH=true)

    auth = None
    disable_auth = os.getenv("MCP_DISABLE_AUTH", "false").lower() in ("true", "1", "yes")

    if not disable_auth:
        token = os.getenv("MCP_BEARER_TOKEN")
        if not token:
            raise ValueError(
                "MCP_BEARER_TOKEN is required! "
                "Generate one with: openssl rand -hex 32 "
                "Or disable auth with MCP_DISABLE_AUTH=true (not recommended)"
            )

        auth = BearerTokenAuth(
            tokens={
                token: {
                    "scopes": ["tools:*", "resources:*"]
                },
            },
            verify_signature=True,
            issuer="mcp-proxy",
            secret=os.getenv("JWT_SECRET", token)  # Use token as secret if JWT_SECRET not set
        )

    proxy = FastMCP.as_proxy(
        config,
        name="MCP Proxy Hub",
        auth=auth
    )

    return proxy
```

### Docker Compose with Security

```yaml
version: "3.8"

services:
  mcp-proxy:
    image: ghcr.io/jonhearsch/mcp-proxy:latest
    ports:
      - "127.0.0.1:8080:8080" # Only bind to localhost
    volumes:
      - ./mcp_config.json:/app/mcp_config.json:ro
      - ./data:/data
    environment:
      # REQUIRED: Bearer token authentication
      - MCP_BEARER_TOKEN=${MCP_BEARER_TOKEN}

      # Optional configuration
      - MCP_CONFIG_PATH=/app/mcp_config.json
      - MCP_HOST=0.0.0.0
      - MCP_PORT=8080

      # Optional: URL path prefix for security through obscurity
      # - MCP_PATH_PREFIX=e9415487-f3b9-4186-ade3-da8586ddf96b

      # To disable auth (NOT RECOMMENDED):
      # - MCP_DISABLE_AUTH=true
    restart: unless-stopped

  cloudflared:
    image: cloudflare/cloudflared:latest
    command: tunnel --no-autoupdate run
    environment:
      - TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}
    depends_on:
      - mcp-proxy
    restart: unless-stopped
```

### Environment Variables (.env)

```bash
# REQUIRED: Bearer token for authentication
# Generate with: openssl rand -hex 32
MCP_BEARER_TOKEN=<generate-with-openssl-rand-hex-32>

# Cloudflare Tunnel
CLOUDFLARE_TUNNEL_TOKEN=<from-cloudflare-dashboard>

# Optional: Disable auth (NOT RECOMMENDED)
# MCP_DISABLE_AUTH=true
```

---

## Security Checklist

### Application Layer

- [ ] Enable FastMCP authentication (Bearer Token or OAuth)
- [ ] Use strong, randomly generated tokens (min 32 bytes)
- [ ] Store secrets in environment variables, not code
- [ ] Implement JWT signature verification
- [ ] Define appropriate scopes for different access levels
- [ ] Rotate tokens regularly (every 90 days minimum)
- [ ] Log authentication attempts and failures

### Network Layer

- [ ] Use Cloudflare Tunnel or VPN for network access
- [ ] Never expose port 8080 directly to internet (bind to 127.0.0.1)
- [ ] Enable TLS/HTTPS for all connections
- [ ] Implement rate limiting (Cloudflare WAF)
- [ ] Configure DDoS protection
- [ ] Use service tokens for machine-to-machine auth

### Configuration

- [ ] Validate config before reload (prevent bad config injection)
- [ ] Use read-only volume mounts for config files
- [ ] Implement config schema validation
- [ ] Audit config changes with version control
- [ ] Separate secrets from configuration

### Monitoring & Incident Response

- [ ] Enable structured logging with auth events
- [ ] Monitor failed authentication attempts
- [ ] Set up alerts for security events (5+ failed auths)
- [ ] Implement audit trail for all actions
- [ ] Regular security reviews of logs
- [ ] Document incident response procedures

### Container Security

- [ ] Run as non-root user (already implemented)
- [ ] Use read-only filesystem where possible
- [ ] Scan images for vulnerabilities (Trivy, Snyk)
- [ ] Pin base image versions
- [ ] Keep dependencies updated
- [ ] Limit container capabilities

---

## Migration Path

### Phase 1: Quick Wins (Day 1)

1. Implement FastMCP Bearer Token auth
2. Bind to 127.0.0.1 only (not 0.0.0.0)
3. Generate strong tokens with `openssl rand -hex 32`
4. Store tokens in environment variables

### Phase 2: Network Security (Week 1)

1. Set up Cloudflare Tunnel
2. Configure service tokens
3. Enable rate limiting
4. Add WAF rules

### Phase 3: Advanced Auth (Month 1)

1. Migrate to OAuth 2.1 if user-level auth needed
2. Implement per-tool authorization
3. Add audit logging
4. Set up monitoring and alerts

### Phase 4: Enterprise (Quarter 1)

1. Consider Permit.io for ABAC
2. Implement role-based access control (RBAC)
3. Add compliance logging
4. Regular security audits

---

## MCP Specification Requirements

Per the MCP specification, production implementations **MUST**:

1. **OAuth 2.1 Compliance**: Auth implementations MUST implement OAuth 2.1 with appropriate security measures
2. **PKCE Required**: All auth flows must use PKCE to protect authorization code exchanges
3. **Token Verification**: Servers MUST verify all inbound requests and reject invalid tokens
4. **No Session Auth**: Servers MUST NOT use sessions for authentication (use tokens)
5. **Secure Session IDs**: If using sessions for other purposes, MUST use secure, non-deterministic IDs
6. **Token Scope**: Servers MUST NOT accept tokens not explicitly issued for the MCP server

---

## Additional Resources

- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [FastMCP Authentication Docs](https://gofastmcp.com/servers/auth/authentication)
- [Cloudflare Tunnel Documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [OAuth 2.1 Specification](https://oauth.net/2.1/)
- [Permit.io Documentation](https://docs.permit.io/)

---

## Support

For security issues or questions:

- Review BACKLOG.md for planned security improvements
- Check GitHub issues for known security topics
- Consult MCP specification for protocol requirements
