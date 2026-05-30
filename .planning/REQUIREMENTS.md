# Requirements: MCP Proxy

**Defined:** 2026-05-30
**Core Value:** Any MCP client can securely access any combination of MCP servers from anywhere, with per-user access control — without running servers locally.

## v1 Requirements

Requirements for the hardening milestone. Each maps to a roadmap phase.

### Foundation

- [ ] **FOUND-01**: SIGTERM signal handler registered so Docker stop triggers clean graceful shutdown
- [ ] **FOUND-02**: `proxy_server.py` refactored into modules (e.g. `auth/`, `proxy/`, `config/`, `admin/`) — no functional changes, structure only
- [ ] **FOUND-03**: Live reload replaced with clean asyncio-based shutdown signal (remove `os.kill(SIGINT)` pattern)
- [ ] **FOUND-04**: pytest + pytest-asyncio test suite covering config loading, auth initialization, restart logic, and signal handling
- [ ] **FOUND-05**: Structured logging via structlog with JSON output format replacing current print-style logging

## v2 Requirements

Deferred to future milestone. Tracked but not in current roadmap.

### Access Control

- **AUTH-01**: Admin can configure an email allowlist or Google Workspace domain restriction — unknown Google accounts are denied at auth time
- **AUTH-02**: Admin can configure per-user allowed tool list — users can only invoke tools explicitly granted to them
- **AUTH-03**: Tool ACL enforced on both `list_tools` and `call_tool` — listing without call enforcement is security theater

### Observability

- **OBS-01**: Audit trail — log user, tool, timestamp, result for every tool call (SQLite)
- **OBS-02**: Prometheus-compatible `/metrics` endpoint (request counts, latency, error rates)
- **OBS-03**: Configurable log retention — purge audit records older than N days
- **OBS-04**: Structured log correlation IDs across request lifecycle

### Admin Dashboard

- **DASH-01**: Web UI showing connected MCP servers and their status
- **DASH-02**: Active session list with user identity
- **DASH-03**: Recent tool call history viewer
- **DASH-04**: User management UI (allowlist, tool ACL configuration)

### Credential Vault

- **VAULT-01**: Users store API keys/tokens for downstream MCP servers
- **VAULT-02**: Credentials encrypted at rest (AES-256, key outside data volume)
- **VAULT-03**: Proxy automatically injects stored credentials when routing to downstream server
- **VAULT-04**: Self-service credential management UI
- **VAULT-05**: Feasibility spike required — HTTP/SSE credential injection into FastMCP internals unverified

### Tool Discovery

- **TOOL-01**: `search_tools(query)` meta-tool exposed to LLM — returns full schema + call instructions for matching tools
- **TOOL-02**: BM25 lexical search over tool names and descriptions
- **TOOL-03**: Semantic hybrid search (sentence-transformers + BM25 reranking)
- **TOOL-04**: Admin sets per-tool exposure tier: Always Exposed / Searchable / Hidden
- **TOOL-05**: User-configurable Docker runtimes (pip, cargo, go) via config without image rebuild

### Auth Providers

- **OIDC-01**: Support Auth0 as an OIDC provider alongside Google
- **OIDC-02**: Support Keycloak as an OIDC provider
- **OIDC-03**: OIDC provider selected via environment variable — no code changes required

### Access Control (Extended)

- **ACL-01**: Per-request allowlist enforcement (handles user offboarding without token wait)
- **ACL-02**: Role-based user tiers — admin / user / readonly

## Out of Scope

| Feature | Reason |
|---------|--------|
| SaaS hosting | Self-hosted only — we don't run infrastructure |
| Mobile app | CLI/Docker deployment tool, not consumer app |
| Real-time collaboration | Not a multiplayer tool |
| MCP server development | This proxies servers, doesn't help build them |
| API key auth | Removed in v3.0 — OAuth is the standard for Claude.ai |
| mcpproxy-go feature parity | Different use case (remote multi-user vs local single-user) |

## Traceability

Populated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| FOUND-01 | Phase 1 | Pending |
| FOUND-02 | Phase 1 | Pending |
| FOUND-03 | Phase 1 | Pending |
| FOUND-04 | Phase 1 | Pending |
| FOUND-05 | Phase 1 | Pending |

**Coverage:**
- v1 requirements: 5 total
- Mapped to phases: 5
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-30*
*Last updated: 2026-05-30 after initial definition*
