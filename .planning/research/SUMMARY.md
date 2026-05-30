# Project Research Summary

**Project:** MCP Proxy — Hardening & Extension
**Domain:** MCP aggregation proxy / API gateway with per-user auth, credential vault, and tool search
**Researched:** 2026-05-30
**Confidence:** HIGH

## Executive Summary

MCP Proxy sits at the intersection of two mature patterns: API gateway (Kong, AWS API Gateway) and the emerging MCP proxy ecosystem (mcpproxy-go, hyprmcp/jetski, Sentinelgate). The research is unambiguous: this project currently ships as an **open proxy** — any Google-authenticated user can call any tool with no allowlist, no per-user tool access control, no audit trail, and a fragile reload mechanism. These are production-blocking gaps, not polish items. The first milestone must harden these fundamentals before any new capabilities are added.

The recommended approach is to build in four dependency-ordered phases using FastMCP 3.x's native Middleware API and built-in auth providers — no third-party auth libraries needed. Every new capability (user allowlist, tool filtering, audit log, credential vault) slots into the existing FastMCP proxy as middleware. The 759-line `proxy_server.py` must be extracted into a `src/` module structure first; without this, security middleware is untestable and the codebase becomes unmaintainable. The critical dependency chain is: **module refactor → reliable user identity → middleware stack → vault → dashboard**.

The two differentiated features — a **per-user credential vault** (unique in the OSS MCP proxy space) and **server-side BM25/semantic tool search** (which solves the LLM tool-limit problem at scale) — are both high-complexity but high-value. The vault requires careful security design before any code is written (master key separation, MultiFernet key versioning, credential injection that never leaks into logs). Tool search should be deferred until the vault is complete and stable. The combination of server-side deployment + Claude.ai DCR compatibility + per-user credential vault is a genuinely differentiated position in the market.

---

## Key Findings

### Recommended Stack

The existing stack (FastMCP, watchdog, jsonschema, python-dotenv) is correct and should be kept. The primary action is **upgrading FastMCP to ≥3.3.1**, which unlocks the Middleware API and built-in Auth0/Keycloak/OIDC providers that are the foundation for every new capability. No third-party OIDC or authz library (authlib, Casbin, OPA) is needed or wanted — they create dual-stack conflicts with FastMCP's internals.

New additions are surgical: SQLite+SQLAlchemy+aiosqlite+Alembic for the vault and audit DB; `cryptography` for Fernet encryption; `structlog` for structured JSON logging; `fastapi`+`jinja2` for the admin dashboard (FastAPI is already a FastMCP transitive dependency); `prometheus-client` for metrics; and pytest+pytest-asyncio+httpx for the test suite. All libraries are verified on PyPI as of 2026-05-30.

**Core technologies to add:**
- `fastmcp[auth]>=3.3.1` — unlocks Middleware API, Auth0Provider, KeycloakProvider, OIDCProxy
- `sqlalchemy[asyncio]>=2.0.50` + `aiosqlite>=0.22.1` + `alembic>=1.18.4` — async ORM for vault + audit DB; zero-ops SQLite backend
- `cryptography>=48.0.0` — Fernet AES-256-GCM encryption for vault; PyCA reference implementation
- `structlog>=25.5.0` — structured JSON logging with async context binding
- `fastapi>=0.136.3` + `jinja2>=3.1.6` + `python-multipart>=0.0.20` — admin dashboard (FastAPI already a transitive dep)
- `prometheus-client>=0.25.0` — `/metrics` endpoint for Grafana/Prometheus
- `pytest>=9.0.3` + `pytest-asyncio>=1.4.0` + `httpx>=0.28.1` + `pytest-cov>=6.0` — test suite

See [STACK.md](STACK.md) for full rationale and alternatives rejected.

### Expected Features

The feature comparison across 74 GitHub repos shows this project has **gaps in every table-stakes category** while having a unique opportunity in the credential vault space.

**Must have (table stakes — current gaps):**
- **User allowlist / domain restriction** — all OSS MCP proxies have this; current state is an open proxy
- **SIGTERM handling** — Docker `docker stop` breaks without it; already flagged in CONCERNS.md
- **Per-user tool access control** — core security primitive; blocks multi-user production deployment
- **Usage audit trail** — MCP spec explicitly requires it; expected by enterprise deployers
- **Admin dashboard** — server status, tool inventory, session list, audit viewer; makes the product feel finished

**Should have (differentiators):**
- **Per-user credential vault** — essentially unique in OSS MCP proxy space; enables "my GitHub token goes to the GitHub MCP server" without any local config
- **Tool search: one `search_tools(query)` meta-tool** — solves LLM tool-limit problem (Cursor: 40 tools, OpenAI: 128 functions); BM25 lexical + semantic reranking; admin UI exposes three tiers: Always Exposed / Searchable / Hidden
- **Multi-auth OIDC provider support** — restore Auth0/Keycloak from v2; Auth0Provider and KeycloakProvider are now built into FastMCP 3.x
- **Prometheus metrics** — enterprises expect `/metrics`; 3-line setup

**Defer (v2+):**
- Semantic tool search (requires embedding infrastructure)
- Rate limiting / per-user quotas
- Per-user MCP server instances (advanced vault feature)
- Policy engine (CEL/OPA) — allowlist config is sufficient

See [FEATURES.md](FEATURES.md) for full ecosystem comparison table.

### Architecture Approach

All new capabilities are implemented as **FastMCP Middleware** — the only sanctioned extension point for request interception, verified in FastMCP docs. The `proxy_server.py` monolith splits cleanly along existing class boundaries into a `src/` module structure with no logic changes. User identity flows through `get_access_token()` (FastMCP-native, works identically across all auth providers), making it the single source of truth for all middleware. SQLite is shared between the vault and audit log in a single `data/vault.db` file — appropriate for single-container self-hosted deployment. The admin dashboard is embedded as custom routes on the same FastMCP instance (not a separate service) to avoid IPC complexity and maintain single-container deployment.

**Major components:**
1. `src/auth/` — provider factory (Google/Auth0/Keycloak/OIDC) + per-request allowlist middleware
2. `src/vault/` — encrypted credential store (SQLite + Fernet) + REST API + credential injection middleware
3. `src/tools/` — tool access control middleware (filters both `on_list_tools` AND `on_call_tool`)
4. `src/logging/` — structured audit log middleware (fire-and-forget async writes)
5. `src/dashboard/` — admin routes (`/admin/*`) as custom FastMCP routes, Jinja2 templates
6. `src/config/` + `src/lifecycle/` — extracted config loader, file watcher, resilient proxy loop

See [ARCHITECTURE.md](ARCHITECTURE.md) for full data flows, code samples, and extraction plan.

### Critical Pitfalls

See [PITFALLS.md](PITFALLS.md) for all 7 critical + 6 moderate + 4 minor pitfalls with prevention code.

1. **Vault master key co-located with ciphertext** (C1) — store key in Docker secret or injected env var *separate* from the data volume; use HKDF to derive per-user keys so single exposure doesn't compromise all users
2. **Tool list filtered but tool calls not blocked** (C2) — always implement BOTH `on_list_tools` AND `on_call_tool` in the same middleware; testing only the list is a false pass
3. **Allowlist checked at login only, not per-request** (C6) — add middleware that checks the email claim on every MCP request with a 30s cached allowlist; short JWT expiry (≤1 hour)
4. **Admin dashboard accessible to any authenticated user** (C3) — check `token.claims["email"] in ADMIN_EMAILS` on every admin route; consider binding admin to `127.0.0.1:8081` only
5. **Decrypted credentials leak into logs** (C4) — inject via env vars (stdio) or HTTP headers (SSE/HTTP), never as tool arguments; mark credential fields `sensitive=True`; audit log stores **metadata only**, never arguments/results

---

## Implications for Roadmap

The architecture research defines a clear 4-phase dependency order. Nothing in Phase 2 is safe to build without Phase 1; the vault cannot be safely implemented before the reload race condition is fixed.

### Phase 1: Foundation & Hardening

**Rationale:** The current proxy has production-blocking gaps (open proxy, fragile reload, monolithic file). These must be fixed before any new capability is built — they are the foundation every subsequent phase depends on.
**Delivers:** A production-safe, modular, testable proxy with correct signal handling and user access control
**Addresses features:** User allowlist, SIGTERM fix, RBAC roles (admin vs user), test suite bootstrap, code modularization
**Avoids pitfalls:** M1 (untestable monolith), m2 (JWT key validation at startup), C6 (per-request allowlist check), code structure pitfalls
**Components built:** `src/auth/allowlist.py`, `src/config/`, `src/lifecycle/` extraction, signal handling fix, test harness

### Phase 2: Observability & Per-User Tool Access

**Rationale:** With stable user identity (from Phase 1), tool filtering and audit logging can be added. These are table-stakes features that complete the security model and provide operational visibility. The audit DB establishes the SQLite foundation the vault will share.
**Delivers:** Per-user tool filtering, usage audit trail, structured logging, admin auth provider abstraction
**Addresses features:** Per-user tool access, usage audit trail, structured logging, multi-auth OIDC support
**Avoids pitfalls:** C2 (paired list+call filtering), C7 (metadata-only audit log), M4 (stale config after reload), M5 (DCR ambiguity with multi-OIDC)
**Components built:** `src/tools/filter.py`, `src/logging/audit.py`, `src/auth/factory.py`, SQLite schema + Alembic migrations

### Phase 3: Credential Vault & Admin Dashboard

**Rationale:** The vault requires stable user identity (Phase 1) and tool filtering (Phase 2, so only vault-authorized tools are visible). The admin dashboard requires the audit log (main data source) and tool filter state. Reload race condition must be fixed before vault writes begin.
**Delivers:** Encrypted per-user credential storage, credential management UI, full admin dashboard
**Addresses features:** Credential vault (biggest differentiator), admin dashboard (server status, tool inventory, sessions, audit log viewer)
**Avoids pitfalls:** C1 (master key separation + MultiFernet), C3 (admin role check), C4 (credential injection via env/headers), M2 (reload race fixed before vault), M3 (CSRF protection), M6 (key versioning from day one)
**Components built:** `src/vault/` (store, API, middleware), `src/dashboard/` (Jinja2 admin routes), prometheus metrics endpoint

### Phase 4: Tool Search & Discovery

**Rationale:** Tool search (BM25 + semantic reranking) is the highest-complexity feature and requires the full tool inventory from Phase 2 and stable user identity from Phase 1. Deferred until core platform is hardened. The user-configurable runtime support (pip, cargo, go) for Docker also lands here.
**Delivers:** `search_tools(query)` meta-tool with BM25 lexical + semantic reranking; three-tier admin tool exposure (Always Exposed / Searchable / Hidden); user-configurable additional Docker runtimes
**Addresses features:** Tool search (highest-value differentiator for 100+ tool deployments), tool namespace prefixing, tool enable/disable per server
**Avoids pitfalls:** Ensure `search_tools` respects per-user tool access control from Phase 2 (hidden tools must not appear in search results)
**Components built:** `src/tools/search.py` (BM25 index, embedding reranker), admin tool tier configuration UI, Docker runtime extension config

### Phase Ordering Rationale

- **Dependency chain is strict:** user identity → middleware → vault → search. Each phase adds capabilities that the next phase builds on.
- **Security-first:** Allowlist and per-request auth checks precede any persistent user data (vault). You cannot safely store user credentials until you can reliably identify and authorize users.
- **Reload race before vault:** The `os.kill(SIGINT)` reload fragility becomes a data-corruption risk once vault writes exist. Fix it in Phase 1 before vault work in Phase 3.
- **Vault before tool search:** Tool search is high-value but not security-sensitive; vault is high-value AND security-sensitive. Get the security-sensitive feature right first.
- **Monolith refactor first:** Cannot unit-test security middleware without module extraction. Refactor is Phase 1, task 1.

### Research Flags

Phases likely needing deeper research during planning:

- **Phase 3 (Credential Injection into HTTP/SSE upstreams):** ARCHITECTURE.md explicitly flags this as LOW confidence. FastMCP's `as_proxy()` manages upstream HTTP connections internally and may not expose a clean hook for injecting Authorization headers. **Needs a feasibility spike** before vault middleware implementation.
- **Phase 4 (Semantic search / embedding model):** Requires embedding model selection (sentence-transformers? OpenAI embeddings? local vs. remote?), vector storage choice, and latency budget. Significant infra decisions not researched yet.
- **Phase 4 (User-configurable Docker runtimes):** pip/cargo/go runtime support in container needs design — security surface of running arbitrary build tools in production container needs careful thought.

Phases with standard patterns (skip research-phase):
- **Phase 1 (Foundation):** Well-documented FastMCP middleware + Python module extraction; no unknowns
- **Phase 2 (Tool filtering + audit log):** ARCHITECTURE.md has verified code samples from FastMCP docs; BM25 and SQLite patterns are standard
- **Phase 3 (Vault encryption):** Fernet encryption + SQLite schema patterns are well-established; the credential injection spike (above) is the only unknown

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All libraries verified on PyPI; FastMCP 3.x API verified via Context7 with code samples |
| Features | HIGH | Cross-referenced MCP spec, Kong enterprise, AWS API Gateway, and 74-repo GitHub ecosystem scan |
| Architecture | HIGH | FastMCP Middleware, ASGI mounting, and auth provider patterns all verified via Context7 official docs |
| Pitfalls | HIGH | FastMCP auth docs + CONCERNS.md first-party audit + established API gateway security literature |

**Overall confidence:** HIGH

### Gaps to Address

- **Credential injection into HTTP/SSE upstreams (LOW confidence):** FastMCP's internal httpx transport layer for proxy connections may not expose an env/header injection hook. Needs a spike: attempt to wrap the httpx client used by `as_proxy()` to inject per-user headers. If not feasible, fallback is vault-only for stdio servers in v1.
- **FastMCP 3.x `as_proxy()` + custom middleware ordering:** The exact API for `proxy.add_middleware()` ordering semantics (is it LIFO or FIFO?) should be validated with a test before building the full middleware stack in Phase 2.
- **Tool search three-tier admin UI design:** The "Always Exposed / Searchable / Hidden" tier system needs a data model design. Where are tier assignments stored (mcp_config.json extension? SQLite `tool_tiers` table?)? This needs definition before Phase 4 planning.
- **JWT expiry configuration:** No research into how to configure token lifetime in FastMCP's GoogleProvider. Short expiry (≤1 hour) is recommended for the allowlist revocation pattern (C6) — needs verification that this is configurable.

---

## Sources

### Primary (HIGH confidence)
- FastMCP 3.x docs via Context7 (`/prefecthq/fastmcp`) — Middleware API, Auth providers, ASGI mounting, Testing utilities
- MCP Specification: https://modelcontextprotocol.io/docs/concepts/tools — tool security requirements
- Kong API Gateway feature matrix: https://konghq.com/products/kong-gateway — table-stakes benchmark
- PyPI package versions verified: 2026-05-30

### Secondary (MEDIUM confidence)
- mcpproxy-go (236★, 178 releases): https://github.com/smart-mcp-proxy/mcpproxy-go — BM25 tool search, feature comparison
- hyprmcp/jetski (210★): https://github.com/hyprmcp/jetski — multi-OIDC, passthrough architecture
- anythingmcp (108★): https://github.com/HelpCode-ai/anythingmcp — OAuth2 downstream support
- GitHub topic `mcp-proxy` 74-repo scan: https://github.com/topics/mcp-proxy — ecosystem feature matrix

### Tertiary (LOW confidence / needs validation)
- Credential injection into HTTP/SSE upstreams — inferred from FastMCP architecture; not directly documented; flagged for spike
- Sentinelgate (25★): https://github.com/Sentinel-Gate/Sentinelgate — RBAC+CEL pattern (over-engineered for this use case)

---

*Research completed: 2026-05-30*
*Ready for roadmap: yes*
