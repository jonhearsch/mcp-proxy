# Architecture Patterns: MCP Proxy Extensions

**Domain:** FastMCP-based MCP proxy with auth, multi-user capabilities
**Researched:** 2026-05-30
**Overall confidence:** HIGH (FastMCP docs verified via Context7)

---

## Current Architecture (Baseline)

The existing proxy is a single Python file wrapping `FastMCP.as_proxy()`. All
extension capabilities slot into or around this wrapper via:

1. **Middleware** — FastMCP's `Middleware` class with hooks for every MCP
   operation (`on_list_tools`, `on_call_tool`, `on_list_resources`, etc.)
2. **Custom routes** — `proxy.custom_route(path, methods=[...])` for web
   endpoints (dashboard, metrics, admin API)
3. **Auth provider swap** — `auth=` kwarg to `FastMCP.as_proxy()` accepts any
   provider; FastMCP ships Google, Auth0, Keycloak, OIDCProxy, PropelAuth

---

## Component Map (Target State)

```
mcp-proxy/
├── proxy_server.py          ← thin orchestrator (main, ResilientMCPProxy)
├── version.py
├── mcp_config.json
├── mcp_config.schema.json
│
├── src/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── factory.py        ← provider factory (Google, Auth0, Keycloak, OIDC)
│   │   └── allowlist.py      ← email/domain access control middleware
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   ├── loader.py         ← load_config_with_retry, schema validation
│   │   └── watcher.py        ← ConfigFileHandler (watchdog)
│   │
│   ├── lifecycle/
│   │   ├── __init__.py
│   │   └── resilient_proxy.py ← ResilientMCPProxy, signal handling, port mgmt
│   │
│   ├── vault/
│   │   ├── __init__.py
│   │   ├── store.py          ← encrypted key-value store (SQLite + Fernet)
│   │   ├── api.py            ← /vault/* REST routes
│   │   └── middleware.py     ← CredentialInjectionMiddleware
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   └── filter.py         ← ToolAccessMiddleware (per-user allowlist/denylist)
│   │
│   ├── logging/
│   │   ├── __init__.py
│   │   └── audit.py          ← UsageLoggingMiddleware, SQLite audit log
│   │
│   └── dashboard/
│       ├── __init__.py
│       └── routes.py         ← /admin/* routes (sessions, tools, audit)
```

---

## Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `proxy_server.py` | Process entry, env parsing, wires modules together | All modules |
| `lifecycle/resilient_proxy.py` | Crash recovery loop, reload, port management | `config/loader`, `config/watcher`, `auth/factory` |
| `auth/factory.py` | Constructs correct FastMCP auth provider from env | FastMCP auth providers |
| `auth/allowlist.py` | Post-auth middleware: blocks non-allowlisted users | `get_access_token()`, user config |
| `config/loader.py` | Reads, validates, and returns `mcp_config.json` | `mcp_config.schema.json` |
| `config/watcher.py` | Watchdog adapter → debounced reload signal | `lifecycle/resilient_proxy.py` |
| `vault/store.py` | Encrypted per-user credential storage (SQLite) | None (standalone) |
| `vault/api.py` | REST routes for CRUD on user credentials | `vault/store.py`, `get_access_token()` |
| `vault/middleware.py` | Reads vault, injects creds into MCP context state | `vault/store.py`, `get_access_token()` |
| `tools/filter.py` | Filters tool list and blocks calls per user config | `get_access_token()`, user config |
| `logging/audit.py` | Async-writes one row per tool call to SQLite | `get_access_token()`, SQLite |
| `dashboard/routes.py` | HTML/JSON admin views (same process, custom routes) | audit DB, FastMCP internals |

---

## Data Flow: Per-User Credential Vault

**Problem:** Users need their own API keys for downstream MCP servers (e.g., GitHub
PAT, Notion token). The proxy injects these when routing requests.

**Where stored:** SQLite database (`data/vault.db`) with per-row Fernet encryption.
Row key = `(user_sub, credential_name)`. The Fernet key is an env var
(`VAULT_ENCRYPTION_KEY`). SQLite keeps it single-container with no external
dependency.

**How injected:** FastMCP `Middleware` stores credentials in MCP context state before
the request reaches the upstream MCP server. Downstream stdio/SSE MCP servers that
need credentials receive them as environment variables (for stdio) or request headers
(for HTTP/SSE) — set by the middleware before the upstream call.

```
HTTP client → /mcp/ request (Bearer JWT)
     │
     ▼
[FastMCP GoogleProvider validates JWT]
     │
     ▼
[CredentialInjectionMiddleware.on_call_tool]
  1. token = get_access_token()          ← FastMCP dependency
  2. user_sub = token.claims["sub"]
  3. creds = vault.get_credentials(user_sub, tool_server_name)
  4. ctx.set_state("injected_creds", creds)   ← FastMCP context state
     │
     ▼
[FastMCP routes call to upstream MCP server]
  - For stdio servers: injected as env vars on subprocess
  - For HTTP/SSE servers: injected as Authorization header via httpx middleware
     │
     ▼
[Response returned to client]
```

> **FastMCP constraint:** `as_proxy()` manages upstream connections internally.
> Env var injection for stdio subprocesses is only possible if the proxy starts those
> subprocesses itself (which `as_proxy()` does for `command`/`args` config). For
> HTTP/SSE upstreams, header injection requires a custom transport wrapper around
> FastMCP's internal httpx client — this needs validation during implementation as
> FastMCP's internal transport layer may not expose this hook cleanly.
> **Flag:** Credential injection into HTTP/SSE upstreams is LOW confidence and needs
> a feasibility spike.

---

## Data Flow: Tool Search / Filtering

FastMCP exposes a clean `Middleware` API — verified in docs.

```python
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_access_token
from fastmcp.exceptions import ToolError

class ToolAccessMiddleware(Middleware):
    def __init__(self, policy_store):
        self.policy = policy_store  # user_sub → set of allowed tool names

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        tools = await call_next(context)
        token = get_access_token()
        if token is None:
            return []
        allowed = self.policy.get_allowed_tools(token.claims["sub"])
        if allowed == "*":
            return tools
        return [t for t in tools if t.name in allowed]

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        if token is None:
            raise ToolError("Not authenticated")
        allowed = self.policy.get_allowed_tools(token.claims["sub"])
        if allowed != "*" and context.message.name not in allowed:
            raise ToolError("Tool not found")  # opaque — don't leak existence
        return await call_next(context)
```

**Policy storage:** Simple JSON config per user in `users.json` (or a `users` table in
SQLite once the vault DB exists). Structure:
```json
{
  "user@example.com": {
    "allowed_tools": ["*"],
    "denied_tools": []
  }
}
```

**Middleware is added via:**
```python
proxy = FastMCP.as_proxy(config, auth=auth)
proxy.add_middleware(ToolAccessMiddleware(policy_store))
proxy.add_middleware(CredentialInjectionMiddleware(vault))
proxy.add_middleware(UsageLoggingMiddleware(audit_db))
```

**Middleware execution order matters:** Allowlist check → credential injection →
logging. Register in reverse order (FastMCP applies middleware as a stack).

---

## Data Flow: Usage Logging

**Where captured:** `Middleware.on_call_tool` hook wraps every tool invocation.
This fires after auth, after tool filtering, giving access to: tool name, user identity, arguments, result, timing.

**Sync vs async:** Use `asyncio` with background task queue. Log write is fire-and-forget — do not await inside the middleware hook, as this adds latency to every tool call.

```python
import asyncio
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_access_token
import time

class UsageLoggingMiddleware(Middleware):
    def __init__(self, audit_log):
        self.audit_log = audit_log  # AsyncAuditLog instance

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        start = time.monotonic()
        token = get_access_token()
        user_sub = token.claims.get("sub") if token else "anonymous"
        user_email = token.claims.get("email") if token else None

        try:
            result = await call_next(context)
            duration_ms = int((time.monotonic() - start) * 1000)
            asyncio.create_task(self.audit_log.write(
                user_sub=user_sub,
                user_email=user_email,
                tool_name=context.message.name,
                success=True,
                duration_ms=duration_ms,
            ))
            return result
        except Exception as e:
            asyncio.create_task(self.audit_log.write(
                user_sub=user_sub,
                user_email=user_email,
                tool_name=context.message.name,
                success=False,
                error=str(e),
            ))
            raise
```

**Storage:** SQLite `audit_log` table. Async writes via `aiosqlite`. Schema:
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,           -- unix timestamp
    user_sub TEXT NOT NULL,
    user_email TEXT,
    tool_name TEXT NOT NULL,
    success INTEGER NOT NULL,   -- 0/1
    duration_ms INTEGER,
    error TEXT
);
CREATE INDEX idx_audit_user ON audit_log(user_sub, ts);
CREATE INDEX idx_audit_tool ON audit_log(tool_name, ts);
```

---

## Admin Dashboard: Same Process via Custom Routes

**Recommendation:** Embedded in same process, not a separate service.

**Rationale:**
- `proxy.custom_route(path, methods=[...])` is already used for `/health`
- A separate service requires IPC or a shared database — adds ops burden
- Single-container deployment constraint is explicit in PROJECT.md
- Dashboard can read directly from in-process state (connected servers, active sessions via FastMCP internals) and the shared SQLite audit DB

**Routes:**
```
GET  /admin/              → dashboard HTML
GET  /admin/api/sessions  → active OAuth sessions (JSON)
GET  /admin/api/tools     → all available tools across servers (JSON)
GET  /admin/api/audit     → recent tool calls, filterable (JSON)
GET  /admin/api/servers   → configured MCP servers + health status (JSON)
POST /admin/api/reload    → trigger config reload (admin-only)
```

**Access control:** Admin routes protected by checking `token.claims["email"]`
against an `ADMIN_EMAILS` env var (comma-separated). Non-admin authenticated
users get 403.

**UI:** Minimal server-rendered HTML (Jinja2 templates) or a single-page
JSON-consuming page. No JS build toolchain — keeps Docker image simple.

---

## OIDC Provider Abstraction

**FastMCP already ships multiple providers** — no custom abstraction needed.
Verified from docs:

| Provider | Class | Use Case |
|----------|-------|----------|
| Google | `fastmcp.server.auth.providers.google.GoogleProvider` | Current implementation |
| Auth0 | `fastmcp.server.auth.providers.auth0.Auth0Provider` | Enterprise SaaS |
| Keycloak | `fastmcp.server.auth.providers.keycloak.KeycloakProvider` | Self-hosted enterprise |
| Generic OIDC | `fastmcp.server.auth.oidc_proxy.OIDCProxy` | Any OIDC-compliant provider |
| PropelAuth | `fastmcp.server.auth.providers.propelauth.PropelAuthProvider` | Managed auth |

**`auth/factory.py` pattern** — select provider based on `MCP_AUTH_PROVIDER` env var:

```python
def create_auth_provider() -> AuthProvider:
    provider = os.getenv("MCP_AUTH_PROVIDER", "google").lower()
    if provider == "google":
        return _create_google_provider()
    elif provider == "auth0":
        return _create_auth0_provider()
    elif provider == "keycloak":
        return _create_keycloak_provider()
    elif provider == "oidc":
        return _create_oidc_provider()
    else:
        raise ValueError(f"Unknown auth provider: {provider!r}")
```

All providers expose the same `auth=` interface to `FastMCP.as_proxy()`. The
`get_access_token()` function and `token.claims` dict work identically regardless
of provider. The `allowlist.py` middleware reads `email` claim — this claim name
is standard across all OIDC providers.

---

## Module Refactoring: Extraction Plan

The 759-line `proxy_server.py` splits cleanly along existing class/function
boundaries. No logic changes needed for extraction — only imports:

| Lines | Current | Extracted To |
|-------|---------|-------------|
| 81–168 | `setup_logging()`, logger setup | `src/logging/setup.py` |
| 170–225 | `create_google_auth()` | `src/auth/factory.py` |
| 226–313 | `ConfigFileHandler` | `src/config/watcher.py` |
| 315–710 | `ResilientMCPProxy` | `src/lifecycle/resilient_proxy.py` |
| 704–713 | `_parse_int_env()` | `src/config/loader.py` |
| 714–759 | `main()`, `__main__` block | `proxy_server.py` (stays thin) |

`proxy_server.py` becomes ~50 lines: imports, `main()`, `__main__` guard.

---

## Build Order (Phase Dependencies)

What must exist before what:

```
Phase 1: Foundation (no dependencies)
  ├── Module refactor (extract src/ modules)
  ├── SIGTERM fix + signal handling cleanup
  ├── User allowlist middleware (auth/allowlist.py)
  └── Test suite bootstrap

Phase 2: Requires Phase 1
  ├── Auth provider abstraction (auth/factory.py)
  │     └── requires: module structure, test harness
  ├── Tool access control middleware (tools/filter.py)
  │     └── requires: allowlist (user identity pattern established)
  └── Usage logging middleware (logging/audit.py)
        └── requires: SQLite setup, user identity via get_access_token()

Phase 3: Requires Phase 2
  ├── Credential vault (vault/)
  │     └── requires: user identity (sub claim), SQLite (shared with audit)
  │     └── requires: tool filtering (so only vault-authorized tools visible)
  └── Admin dashboard (dashboard/)
        └── requires: audit log (main data source), tool filter state

Phase 4: Requires Phase 3
  └── Credential injection into upstream MCP servers
        └── requires: vault (credential store), feasibility spike for HTTP/SSE injection
```

**Critical path:** Module refactor → user identity pattern → middleware stack →
vault → dashboard. Every new capability hangs off user identity being reliably
available at the middleware layer.

---

## Scalability Considerations

| Concern | Single-container (current) | Multi-container (future) |
|---------|---------------------------|-------------------------|
| Audit log | SQLite, fine up to ~100k rows/day | Postgres or external log service |
| Vault DB | SQLite + Fernet, fine for <1000 users | Postgres + HSM or dedicated secrets manager |
| Sessions | FastMCP in-memory (JWT-stateless) | No change needed |
| Tool filter policy | JSON file or SQLite | No change needed |
| Dashboard | Embedded custom routes | Extract to separate service if load warrants |

SQLite is the right choice for the single-container, self-hosted constraint. The
schema should be designed so migrating to Postgres later requires only swapping the
connection string and minimal query changes (use standard SQL, no SQLite-isms).

---

## Anti-Patterns to Avoid

### 1. Blocking I/O in Middleware Hooks
**What goes wrong:** `audit_log.write()` awaited synchronously in `on_call_tool` adds
database latency to every tool invocation.
**Instead:** `asyncio.create_task()` for fire-and-forget writes.

### 2. Separate Dashboard Service
**What goes wrong:** Separate service needs IPC or shared DB to read proxy state;
adds Docker Compose complexity; breaks single-container deployment model.
**Instead:** Custom routes on the same FastMCP instance via `proxy.custom_route()`.

### 3. Custom OIDC Implementation
**What goes wrong:** Rolling a custom OAuth provider duplicates what FastMCP already
ships (and ships correctly for DCR compatibility with Claude.ai).
**Instead:** Use `OIDCProxy` or the built-in provider classes; only write `factory.py`
to select among them.

### 4. Credential Vault as External Service
**What goes wrong:** Requires network dependency (HashiCorp Vault, AWS Secrets Manager)
that breaks self-hosted, no-external-dependency deployment model.
**Instead:** SQLite + Fernet encryption. Acceptable for the user base; documents
upgrade path to external secrets manager for enterprise users.

### 5. In-memory Tool Policy State
**What goes wrong:** Policy lives only in RAM; restarting proxy resets per-user
customizations if they aren't persisted.
**Instead:** Policy stored in SQLite (same `data/` volume); loaded into memory at
startup and on reload.

---

## Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| Middleware stack for all cross-cutting concerns | FastMCP's `Middleware` API is the only sanctioned extension point for request interception; avoids monkey-patching internals |
| SQLite for vault + audit (shared `data/vault.db`) | Single-container constraint; no ops overhead; Fernet satisfies encryption-at-rest requirement |
| Auth provider factory, not custom provider | FastMCP ships all needed providers; only routing logic needed |
| Admin dashboard as custom routes (same process) | Avoids separate service; direct access to proxy state and shared SQLite |
| `get_access_token()` as user identity source | FastMCP-native; works identically across all auth providers; gives email + sub claims |

---

## Sources

- FastMCP Middleware docs: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/middleware.mdx (verified via Context7, HIGH confidence)
- FastMCP Authorization docs: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/authorization.mdx (verified via Context7, HIGH confidence)
- FastMCP OIDC Proxy docs: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/auth/oidc-proxy.mdx (verified via Context7, HIGH confidence)
- FastMCP Dependency Injection docs: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/dependency-injection.mdx (verified via Context7, HIGH confidence)
- Existing codebase analysis: `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/CONCERNS.md`

---

*Architecture research: 2026-05-30*
