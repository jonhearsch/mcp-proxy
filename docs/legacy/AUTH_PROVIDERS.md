# OAuth Provider Configuration

MCP Proxy supports multiple OAuth 2.1 / OIDC providers through a flexible configuration system.

## Supported Providers

- **Auth0** - Industry-leading auth platform with easy setup
- **Keycloak** - Open-source identity and access management
- **Okta** - Enterprise identity platform
- **Generic OIDC** - Any OAuth 2.1 / OpenID Connect compliant provider

## Configuration Methods

### Method 1: auth_config.json (Recommended)

Create `/data/auth_config.json` with your provider configuration. This method supports:
- Multiple providers without code changes
- Environment variable expansion for secrets
- Provider-specific customization

### Method 2: Environment Variables (Legacy Auth0 Only)

For backward compatibility, Auth0 can be configured using environment variables:
- `AUTH0_DOMAIN`
- `AUTH0_AUDIENCE`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`

**Note:** If `auth_config.json` exists, it takes priority over environment variables.

---

## Auth0 Configuration

### Quick Setup

1. Create an Auth0 account at https://auth0.com (free tier available)
2. Create a **Regular Web Application**
3. Create an **API** with a unique identifier
4. Copy your credentials

### Configuration File

Create `/data/auth_config.json`:

```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "${AUTH0_DOMAIN}",
    "audience": "${AUTH0_AUDIENCE}",
    "client_id": "${AUTH0_CLIENT_ID}",
    "client_secret": "${AUTH0_CLIENT_SECRET}"
  }
}
```

### Environment Variables

```bash
# Required
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_AUDIENCE=https://your-mcp-api
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret

# MCP Proxy
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=https://your-domain.com
```

### Optional Advanced Fields

```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "your-tenant.us.auth0.com",
    "audience": "https://your-mcp-api",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",

    "authorization_endpoint": "https://your-tenant.us.auth0.com/authorize",
    "token_endpoint": "https://your-tenant.us.auth0.com/oauth/token",
    "jwks_uri": "https://your-tenant.us.auth0.com/.well-known/jwks.json",
    "issuer": "https://your-tenant.us.auth0.com/"
  }
}
```

---

## Keycloak Configuration

### Quick Setup

1. Install Keycloak server (Docker: `quay.io/keycloak/keycloak`)
2. Create a realm (e.g., "mcp-realm")
3. Create a client with:
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://your-domain.com/auth/callback`
4. Copy client credentials from "Credentials" tab

### Configuration File

Create `/data/auth_config.json`:

```json
{
  "provider": "keycloak",
  "keycloak": {
    "server_url": "${KEYCLOAK_SERVER_URL}",
    "realm": "${KEYCLOAK_REALM}",
    "client_id": "${KEYCLOAK_CLIENT_ID}",
    "client_secret": "${KEYCLOAK_CLIENT_SECRET}"
  }
}
```

### Environment Variables

```bash
# Required
KEYCLOAK_SERVER_URL=https://keycloak.your-domain.com
KEYCLOAK_REALM=mcp-realm
KEYCLOAK_CLIENT_ID=mcp-proxy-client
KEYCLOAK_CLIENT_SECRET=your-client-secret

# MCP Proxy
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=https://your-domain.com
```

### Example with Defaults

The proxy auto-generates standard Keycloak endpoints:

```json
{
  "provider": "keycloak",
  "keycloak": {
    "server_url": "https://keycloak.example.com",
    "realm": "master",
    "client_id": "mcp-client",
    "client_secret": "abc123"
  }
}
```

Auto-generated endpoints:
- Authorization: `{server_url}/realms/{realm}/protocol/openid-connect/auth`
- Token: `{server_url}/realms/{realm}/protocol/openid-connect/token`
- JWKS: `{server_url}/realms/{realm}/protocol/openid-connect/certs`
- Issuer: `{server_url}/realms/{realm}`

---

## Okta Configuration

### Quick Setup

1. Create an Okta account at https://developer.okta.com (free tier available)
2. Create an **Application** → **Web Application**
3. Configure:
   - Sign-in redirect URIs: `https://your-domain.com/auth/callback`
   - Grant types: Authorization Code, Refresh Token
4. Copy Client ID and Client Secret

### Configuration File

Create `/data/auth_config.json`:

```json
{
  "provider": "okta",
  "okta": {
    "domain": "${OKTA_DOMAIN}",
    "client_id": "${OKTA_CLIENT_ID}",
    "client_secret": "${OKTA_CLIENT_SECRET}",
    "audience": "${OKTA_AUDIENCE:-api://default}"
  }
}
```

### Environment Variables

```bash
# Required
OKTA_DOMAIN=dev-12345.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret

# Optional
OKTA_AUDIENCE=api://default

# MCP Proxy
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=https://your-domain.com
```

### Example with Custom Authorization Server

```json
{
  "provider": "okta",
  "okta": {
    "domain": "dev-12345.okta.com",
    "client_id": "0oa1abc2def3ghi4jkl5",
    "client_secret": "your-secret",
    "audience": "api://my-custom-api",
    "authorization_endpoint": "https://dev-12345.okta.com/oauth2/aus123/v1/authorize",
    "token_endpoint": "https://dev-12345.okta.com/oauth2/aus123/v1/token",
    "jwks_uri": "https://dev-12345.okta.com/oauth2/aus123/v1/keys",
    "issuer": "https://dev-12345.okta.com/oauth2/aus123"
  }
}
```

---

## Generic OIDC Provider

Use this for any OAuth 2.1 / OpenID Connect compliant provider:
- Google Cloud Identity
- Azure AD / Entra ID
- GitLab
- GitHub (Enterprise)
- Custom OIDC implementations

### Configuration File

Create `/data/auth_config.json`:

```json
{
  "provider": "generic_oidc",
  "generic_oidc": {
    "authorization_endpoint": "${OIDC_AUTHORIZATION_ENDPOINT}",
    "token_endpoint": "${OIDC_TOKEN_ENDPOINT}",
    "jwks_uri": "${OIDC_JWKS_URI}",
    "issuer": "${OIDC_ISSUER}",
    "client_id": "${OIDC_CLIENT_ID}",
    "client_secret": "${OIDC_CLIENT_SECRET}",
    "audience": "${OIDC_AUDIENCE:-${OIDC_CLIENT_ID}}"
  }
}
```

### Environment Variables

```bash
# Required
OIDC_AUTHORIZATION_ENDPOINT=https://provider.com/oauth/authorize
OIDC_TOKEN_ENDPOINT=https://provider.com/oauth/token
OIDC_JWKS_URI=https://provider.com/.well-known/jwks.json
OIDC_ISSUER=https://provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret

# Optional
OIDC_AUDIENCE=your-audience  # Defaults to client_id if not set

# MCP Proxy
MCP_AUTH_PROVIDER=oauth_proxy
MCP_BASE_URL=https://your-domain.com
```

### Google Cloud Identity Example

```json
{
  "provider": "generic_oidc",
  "generic_oidc": {
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "issuer": "https://accounts.google.com",
    "client_id": "your-client-id.apps.googleusercontent.com",
    "client_secret": "your-client-secret",
    "audience": "your-client-id.apps.googleusercontent.com",
    "valid_scopes": ["openid", "email", "profile"]
  }
}
```

### Azure AD / Entra ID Example

```json
{
  "provider": "generic_oidc",
  "generic_oidc": {
    "authorization_endpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize",
    "token_endpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
    "jwks_uri": "https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys",
    "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "audience": "api://your-client-id"
  }
}
```

---

## Advanced Configuration

### Custom Scopes

All providers support custom scopes:

```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "your-tenant.auth0.com",
    "...": "...",
    "valid_scopes": ["openid", "profile", "email", "custom:scope"]
  }
}
```

### Extra OAuth Parameters

Add provider-specific parameters:

```json
{
  "provider": "keycloak",
  "keycloak": {
    "...": "...",
    "extra_authorize_params": {
      "prompt": "login",
      "max_age": "3600"
    },
    "extra_token_params": {
      "client_assertion_type": "custom-value"
    }
  }
}
```

### Environment Variable Expansion

All config values support environment variable substitution:

```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "${AUTH0_DOMAIN}",
    "audience": "${AUTH0_AUDIENCE}",
    "client_id": "${AUTH0_CLIENT_ID}",
    "client_secret": "${AUTH0_CLIENT_SECRET}"
  }
}
```

With fallback defaults:

```json
{
  "provider": "okta",
  "okta": {
    "audience": "${OKTA_AUDIENCE:-api://default}"
  }
}
```

---

## Testing Your Configuration

### 1. Check OAuth Metadata

```bash
# OAuth Protected Resource metadata
curl https://your-domain.com/.well-known/oauth-protected-resource

# Authorization Server metadata
curl https://your-domain.com/.well-known/oauth-authorization-server
```

### 2. Test Dynamic Client Registration

```bash
curl -X POST https://your-domain.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "test-client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "response_types": ["code"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
```

Expected: 201 response with client credentials.

### 3. Check Server Logs

```bash
docker logs mcp-proxy

# Look for:
# ✓ Loaded auth_config.json from /data/auth_config.json
# ✓ JWTVerifier configured
# ✓ OAuthProxy successfully initialized with [Provider]
```

---

## Migration from Environment Variables

If you're currently using Auth0 environment variables and want to migrate:

1. **Create auth_config.json** with same values:

```json
{
  "provider": "auth0",
  "auth0": {
    "domain": "${AUTH0_DOMAIN}",
    "audience": "${AUTH0_AUDIENCE}",
    "client_id": "${AUTH0_CLIENT_ID}",
    "client_secret": "${AUTH0_CLIENT_SECRET}"
  }
}
```

2. **Keep environment variables** - they'll be expanded in the config
3. **Test** - Existing setup should work identically
4. **(Optional) Switch providers** - Just update `auth_config.json`

---

## Troubleshooting

### "Unsupported provider" error

**Cause:** `provider` field doesn't match a supported type.

**Solution:** Use one of: `auth0`, `keycloak`, `okta`, `generic_oidc`

### "Missing required configuration" error

**Cause:** Required fields for the provider are not set.

**Solution:** Check provider-specific required fields above. Use logs to see what's missing.

### "Invalid JSON in auth_config.json"

**Cause:** Syntax error in JSON file.

**Solution:** Validate JSON at https://jsonlint.com

### Token validation fails

**Cause:** JWKS URI, issuer, or audience mismatch.

**Solution:**
1. Check provider logs for exact values
2. Enable debug logging: `logging.getLogger("httpx").setLevel(logging.DEBUG)`
3. Verify JWKS endpoint is accessible: `curl {jwks_uri}`

---

## Security Best Practices

✅ **Use environment variables for secrets** - Never commit `client_secret` to git
✅ **Validate redirect URIs** - Whitelist exact callback URLs in your provider
✅ **Enable MFA** - Require multi-factor authentication on your auth provider
✅ **Rotate credentials** - Update client secrets every 90 days minimum
✅ **Use HTTPS** - Always use TLS/SSL for production (Cloudflare Tunnel, Let's Encrypt, etc.)
✅ **Audit access** - Review user whitelist in `/data/users.json` regularly

---

## Need Help?

- **Provider Setup Issues:** Check provider-specific documentation linked above
- **Configuration Questions:** See example files in `docs/auth_examples/`
- **Bugs/Features:** Open an issue on GitHub
