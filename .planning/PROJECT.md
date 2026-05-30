# MCP Proxy

## What This Is

MCP Proxy is an open-source remote gateway for Model Context Protocol servers. It lets anyone deploy a single authenticated endpoint that aggregates multiple MCP servers, making Claude.ai tools accessible from anywhere — not just localhost. Authentication is handled via Google OAuth 2.0 with Claude.ai-compatible Dynamic Client Registration.

## Core Value

Any MCP client (Claude.ai, custom apps) can securely access any combination of MCP servers from anywhere, with per-user access control and credentials — without running servers locally.

## Requirements

### Validated

- ✓ Google OAuth 2.0 authentication (Claude.ai compatible DCR) — existing
- ✓ Multi-server aggregation (stdio, SSE, HTTP transports) — existing
- ✓ Live config reload without restart — existing
- ✓ Auto-restart with exponential backoff — existing
- ✓ Docker support (multi-arch, GHCR publishing) — existing
- ✓ JSON schema validation for mcp_config.json — existing
- ✓ Health check endpoint — existing
- ✓ Environment variable expansion in config — existing

### Active

**Hardening**
- [ ] User access control — allowlist/domain restriction so not every Google account can auth
- [ ] SIGTERM signal handling — Docker stop triggers clean shutdown (currently only SIGINT handled)
- [ ] Test suite — unit and integration tests for core proxy logic
- [ ] Code structure — refactor 759-line proxy_server.py into modules
- [ ] Observability — structured logging improvements, clearer startup/error messages

**New Capabilities**
- [ ] Admin dashboard — web UI for viewing connected servers, active sessions, tool usage
- [ ] Per-user tool access — restrict which MCP tools each user can invoke
- [ ] Usage logging — audit trail of who used which tools and when
- [ ] Additional auth providers — support Auth0, Keycloak, and other OIDC providers alongside Google
- [ ] Monitoring & metrics — Prometheus-compatible metrics endpoint, alerting hooks
- [ ] Per-user credential vault — users authenticate with Google, then store their own API keys/tokens for downstream MCP servers; proxy injects credentials when routing requests

### Out of Scope

- SaaS hosting — self-hosted only; we don't run the infrastructure
- Mobile app — CLI/Docker deployment tool, not a consumer app
- Real-time collaboration features — not a multiplayer tool
- MCP server development — this proxies servers, doesn't help build them

## Context

- Single Python file (`proxy_server.py`, 759 lines) wrapping FastMCP's `GoogleProvider` and `as_proxy()`. The architecture is simple: load config → create auth → create proxy → run HTTP server → watch config file → restart on change.
- Published to GHCR (`ghcr.io/jonhearsch/mcp-proxy:latest`), auto-built via GitHub Actions on main branch pushes.
- Currently at v3.0.0 — previous versions had Auth0/API key support, removed in v3 to go Google-only.
- CONCERNS.md documents key gaps: no tests, SIGTERM not handled, no user allowlist, fragile reload mechanism using `os.kill(SIGINT)`.
- Codebase map: `.planning/codebase/` (mapped 2026-05-30)

## Constraints

- **Tech Stack**: Python 3.10+, FastMCP — changes to these require significant rework
- **Compatibility**: Must remain Claude.ai compatible (DCR spec, OAuth flow)
- **Deployment**: Must run in Docker; keep single-container deployment model
- **Open Source**: MIT license; no proprietary dependencies
- **Backward Compat**: Existing `mcp_config.json` format must remain valid

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Google OAuth only (v3.0 breaking change) | Simplify auth, align with Claude.ai requirements | — Pending validation |
| FastMCP.as_proxy() as core engine | Avoid reinventing MCP protocol handling | ✓ Good |
| Single unified endpoint `/mcp/` | Simpler than per-server routing | — Pending |
| Per-user credential vault (new) | Users need credentials for downstream OAuth MCP servers | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-30 after initialization*
