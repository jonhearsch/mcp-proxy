# Technology Stack

**Analysis Date:** 2026-05-30

## Languages

**Primary:**
- Python 3.11 - All application logic (`proxy_server.py`, `version.py`)

**Secondary:**
- JSON - Configuration format (`mcp_config.json`, `mcp_config.schema.json`)
- Bash - CI/CD scripts (`.github/workflows/docker-build.yml`)

## Runtime

**Environment:**
- CPython 3.11 (pinned in `FROM python:3.11-slim` in `Dockerfile`)

**Package Manager:**
- pip (standard) — `requirements.txt` present
- Lockfile: Not present (no `requirements.lock` or `pip-compile` output)

**Additional Runtimes (in Docker image):**
- Node.js + npm — installed via `apt-get` for `npx`-based MCP servers
- uv/uvx — installed via `astral.sh/uv` for `uvx`-based MCP servers

## Frameworks

**Core:**
- `fastmcp[auth]>=2.13.0.2` — MCP server framework, proxy aggregation, Google OAuth middleware, HTTP transport

**Build/Dev:**
- Docker + Docker Buildx — multi-arch container builds (amd64/arm64)
- docker-compose — local dev orchestration (`docker-compose.yml`)

## Key Dependencies

**Critical:**
- `fastmcp[auth]>=2.13.0.2` — Entire MCP proxy, OAuth, and transport logic depends on this
  - Provides: `FastMCP`, `GoogleProvider`, HTTP transport, DCR, OAuth endpoints
  - Source import: `from fastmcp import FastMCP` / `from fastmcp.server.auth.providers.google import GoogleProvider`
- `watchdog` — File system monitoring for live config reload (`proxy_server.py:67-68`)
- `jsonschema` — Config validation against `mcp_config.schema.json` (`proxy_server.py:64`)
- `python-dotenv` — `.env` file loading at startup (`proxy_server.py:52-61`)

**Infrastructure:**
- `starlette` — HTTP response primitives (via fastmcp transitive dep); `JSONResponse` used for `/health` endpoint (`proxy_server.py:36`)

## Configuration

**Environment:**
- All runtime config via environment variables (`.env` file or injected)
- Required vars: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `MCP_BASE_URL`
- Optional vars: `GOOGLE_JWT_KEY`, `MCP_CONFIG_PATH`, `MCP_HOST`, `MCP_PORT`, `MCP_LIVE_RELOAD`, `MCP_MAX_RETRIES`, `MCP_RESTART_DELAY`, `MCP_LOG_LEVEL`, `MCP_LOG_LEVELS`, `MCP_AUTH_DEBUG`
- Template: `.env.example`

**MCP Server Config:**
- `mcp_config.json` — JSON file defining downstream MCP servers
- Schema: `mcp_config.schema.json` (JSON Schema Draft 2020-12)
- Each server entry requires either `{command, args}` (stdio) or `{url, transport}` (SSE/HTTP)

**Build:**
- `Dockerfile` — single-stage `python:3.11-slim` with Node.js and uv added
- `docker-compose.yml` — dev/local compose with host networking

## Platform Requirements

**Development:**
- Python 3.11+
- pip
- Optional: Node.js/npm (for npx-based MCP servers)
- Optional: uv/uvx (for uvx-based MCP servers)
- Google OAuth credentials

**Production:**
- Docker (multi-arch: linux/amd64, linux/arm64)
- Public HTTPS URL required by Google OAuth (`MCP_BASE_URL`)
- GitHub Container Registry (GHCR) for image hosting
- Port 8080 exposed

---

*Stack analysis: 2026-05-30*
