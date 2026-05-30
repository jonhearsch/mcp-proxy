# External Integrations

**Analysis Date:** 2026-05-30

## APIs & External Services

**Google OAuth 2.0:**
- Service: Google Identity Platform (accounts.google.com)
- Purpose: User authentication for Claude.ai MCP access
  - SDK/Client: `fastmcp[auth]` — `GoogleProvider` class (`proxy_server.py:35`)
  - Import: `from fastmcp.server.auth.providers.google import GoogleProvider`
  - Auth: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` env vars
  - Callback URL: `{MCP_BASE_URL}/auth/callback`
  - Required scopes: `openid`, `https://www.googleapis.com/auth/userinfo.email`
  - Google Cloud Console setup required: https://console.developers.google.com/

**Model Context Protocol (MCP) Servers (downstream):**
- Service: Any stdio/SSE/HTTP MCP-compliant server
- Purpose: Proxied tool/resource providers aggregated behind this proxy
- Config: `mcp_config.json` — each entry defines a downstream server
- Transport types supported:
  - `stdio` via `npx` (Node.js-based MCP packages, e.g. `@kevinwatt/mcp-server-searxng`)
  - `stdio` via `uvx` (Python-based MCP packages, e.g. `mcp-server-time`)
  - `SSE` or `HTTP` via `url` + `transport` fields
- Example: `mcp_config.example.json`

## Data Storage

**Databases:**
- None — no database integration detected

**File Storage:**
- Local filesystem: `mcp_config.json` read at startup and watched for changes
- Docker volume mount: `./mcp_config_dev.json:/app/mcp_config.json:ro` (in `docker-compose.yml`)

**Caching:**
- None — no caching layer detected

## Authentication & Identity

**Auth Provider:**
- Google OAuth 2.0 via FastMCP's `GoogleProvider`
  - Implementation: Dynamic Client Registration (DCR) + Authorization Code flow
  - Token type: JWT (signed with `GOOGLE_JWT_KEY` if set, else FastMCP default key)
  - Access control: Any Google-authenticated user with a valid Google account
  - No per-user allowlist — authorization is at OAuth consent level only

**OAuth Endpoints (auto-provided by FastMCP/GoogleProvider):**
- `GET /.well-known/oauth-authorization-server` — server metadata
- `POST /dcr` — Dynamic Client Registration
- `GET /auth/login` — initiates OAuth flow
- `GET /auth/callback` — OAuth callback from Google
- `POST /token` — token exchange (for DCR clients)

## Monitoring & Observability

**Health Check:**
- `GET /health` — custom route returning `{"status": "healthy", "service": "mcp-proxy"}` (`proxy_server.py:571-573`)
- Docker HEALTHCHECK: `curl -f http://localhost:8080/health` every 30s (`Dockerfile`, `docker-compose.yml`)

**Error Tracking:**
- None — no external error tracking (Sentry etc.) detected

**Logs:**
- Structured logging to stdout (INFO/DEBUG) and stderr (WARNING+)
- Format: `%(asctime)s - %(name)-15s - %(levelname)s - %(message)s`
- Level control: `MCP_LOG_LEVEL` (global), `MCP_LOG_LEVELS` (per-logger)
- Auth debug: `MCP_AUTH_DEBUG=true` enables debug on `fastmcp.auth` loggers

## CI/CD & Deployment

**Hosting:**
- Container: Docker (multi-arch `linux/amd64`, `linux/arm64`)
- Registry: GitHub Container Registry (GHCR) — `ghcr.io/{github.repository}`
- Tags generated: `latest`, `v{major}.{minor}.{patch}`, `{major}.{minor}`, `{major}`, `sha-{sha}`, `main`
- Optional: Cloudflare Tunnel (mentioned in `.env.example`, not integrated in code)

**CI Pipeline:**
- GitHub Actions: `.github/workflows/docker-build.yml`
  - Trigger: push to `main`/`develop`, tags `v*`, PRs to `main`, manual dispatch
  - Jobs: auto-increment patch version → commit `version.py` → multi-arch Docker build → push to GHCR
  - Version bump: only on push to `main`; uses `secrets.GITHUB_TOKEN`

## Environment Configuration

**Required env vars:**
- `GOOGLE_CLIENT_ID` — Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` — Google OAuth Client Secret
- `MCP_BASE_URL` — Public HTTPS URL of the proxy (must match Google Cloud Console redirect URI)

**Optional env vars:**
- `GOOGLE_JWT_KEY` — JWT signing key (generate: `openssl rand -hex 32`)
- `MCP_CONFIG_PATH` — config file path (default: `mcp_config.json`)
- `MCP_HOST` — bind address (default: `0.0.0.0`)
- `MCP_PORT` — bind port (default: `8080`)
- `MCP_LIVE_RELOAD` — enable file watching (default: `false`)
- `MCP_MAX_RETRIES` — config load retries (default: `3`)
- `MCP_RESTART_DELAY` — initial restart delay in seconds (default: `5`)
- `MCP_LOG_LEVEL` — global log level (default: `INFO`)
- `MCP_LOG_LEVELS` — per-logger overrides (e.g. `fastmcp:DEBUG,httpx:INFO`)
- `MCP_AUTH_DEBUG` — enable auth debug logging (default: off)

**Secrets location:**
- `.env` file (excluded from git via `.gitignore`)
- Template: `.env.example`

## Webhooks & Callbacks

**Incoming:**
- `GET /auth/callback` — Google OAuth callback after user consent (handled by FastMCP `GoogleProvider`)

**Outgoing:**
- Google OAuth token exchange requests to `https://accounts.google.com` (via FastMCP internals)
- Downstream MCP server connections (stdio subprocess or HTTP/SSE — configured in `mcp_config.json`)

---

*Integration audit: 2026-05-30*
