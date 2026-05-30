# Technology Stack — MCP Proxy Extensions

**Project:** MCP Proxy (hardening & new capabilities)
**Researched:** 2026-05-30
**Confidence:** HIGH (all libraries verified via PyPI + Context7 FastMCP docs)

---

## Existing Stack (Do Not Change)

| Technology | Version | Role |
|------------|---------|------|
| Python | 3.10+ | Runtime — locked by constraint |
| FastMCP | ≥2.13.0 (latest: 3.3.1) | Core proxy engine — locked |
| python-dotenv | * | Env config — keep |
| watchdog | * | Config file watcher — keep |
| jsonschema | * | Config validation — keep |

**Upgrade FastMCP to `>=3.3.1`** — v3.x adds Auth0Provider, KeycloakProvider, PropelAuthProvider, and Middleware API. These are the foundation for most new capabilities.

---

## New Libraries Required

### 1. Additional OIDC Providers — FastMCP built-in

**Library:** `fastmcp[auth]>=3.3.1` (already in stack, upgrade constraint)

FastMCP 3.x includes native providers for Auth0, Keycloak, and others — no additional library needed. Verified via Context7:

```python
from fastmcp.server.auth.providers.auth0 import Auth0Provider
from fastmcp.server.auth.providers.keycloak import KeycloakAuthProvider
```

Both support DCR and `get_access_token()` for identity propagation. **Do not add `authlib` or `python-jose` as standalone OIDC libraries** — FastMCP already handles all token validation internally.

---

### 2. User Access Control & Per-User Tool Filtering — FastMCP Middleware

**Library:** None new — uses `fastmcp.server.middleware.Middleware`

FastMCP 3.x middleware handles both concerns:

```python
class UserAllowlistMiddleware(Middleware):
    async def on_call_tool(self, context, call_next):
        token = get_access_token()
        if token.claims.get("email") not in ALLOWLIST:
            raise ToolError("Access denied")
        return await call_next(context)
```

Tool filtering (hide/block tools per user) uses `on_list_tools` + `on_call_tool` hooks.
**No third-party authz library (Casbin, OPA) needed for v1** — middleware is sufficient and keeps the dependency tree small.

---

### 3. Per-User Credential Vault — SQLite + SQLAlchemy + cryptography

Store encrypted API keys scoped per user identity (`sub` claim from Google/OIDC token).

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `sqlalchemy[asyncio]` | ≥2.0.50 | Async ORM for vault + audit storage | Industry standard; async support via `asyncio` extra; single file for SQLite; migrations via Alembic |
| `aiosqlite` | ≥0.22.1 | Async SQLite driver (used by SQLAlchemy) | Zero-config embedded DB; perfect for single-container deploy; no external DB required |
| `alembic` | ≥1.18.4 | Schema migrations | Same author as SQLAlchemy; handles vault schema evolution without data loss |
| `cryptography` | ≥48.0.0 | AES-256-GCM encryption of stored credentials | PyCA library; used by Python stdlib internals; `Fernet` recipe provides authenticated encryption in ~5 lines |

**Why not Postgres/Redis?** Self-hosted single-container constraint. SQLite handles dozens of users with zero ops burden. Upgrade path exists if needed.

**Why `cryptography` not `pycryptodome`?** cryptography is the PyCA reference implementation, actively maintained, no known CVEs in Fernet, recommended by OWASP for Python.

**Encryption pattern:**
```python
from cryptography.fernet import Fernet
# Key derived from VAULT_MASTER_KEY env var via PBKDF2
# Each stored credential: encrypt(api_key) → store ciphertext
```

---

### 4. Usage Logging / Audit Trail — structlog + SQLAlchemy (same DB)

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `structlog` | ≥25.5.0 | Structured JSON logging | Drop-in for stdlib logging; outputs JSON for log aggregators (Loki, CloudWatch); context binding fits FastMCP middleware pattern perfectly |

Audit records (who called what tool, when, result) go into the same SQLite DB via SQLAlchemy. **Do not use a separate logging database** — SQLite is sufficient for audit trails at self-hosted scale; structured logs go to stdout for external aggregation.

**Why not stdlib `logging`?** structlog produces machine-parseable JSON, supports async contexts without configuration, and binds per-request context (user email, tool name) cleanly.

---

### 5. Admin Dashboard — FastAPI + Jinja2

FastMCP exposes an ASGI app that can be mounted inside a parent Starlette/FastAPI app. This is the cleanest path: add admin routes to the same process, same port.

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `fastapi` | ≥0.136.3 | Admin HTTP routes (REST API + HTML) | Already available since FastMCP itself depends on Starlette; FastAPI is a superset; zero extra install weight |
| `jinja2` | ≥3.1.6 | Server-side rendered admin templates | Already installed (FastMCP dependency); avoids frontend build tooling for a simple ops dashboard |
| `python-multipart` | ≥0.0.20 | Form handling for admin UI | Required by FastAPI for form posts |

**Why not a SPA (React/Vue)?** Self-hosted ops tool with ~1-5 admins. Server-side Jinja2 templates ship in the same Docker image with zero JS build pipeline. No node_modules in production.

**Mounting pattern (verified via Context7):**
```python
mcp_app = mcp.http_app(path='/mcp')
app = FastAPI(lifespan=mcp_app.lifespan)
app.mount("/mcp", mcp_app)
app.include_router(admin_router, prefix="/admin")
```

---

### 6. Monitoring & Metrics — prometheus-client

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `prometheus-client` | ≥0.25.0 | Expose `/metrics` endpoint | Official Prometheus Python client; standard in Docker/K8s deployments; Grafana-compatible; 3-line setup for counters/histograms |

**Pattern:**
```python
from prometheus_client import Counter, Histogram, make_asgi_app
tool_calls = Counter("mcp_tool_calls_total", "...", ["user", "tool", "status"])
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)
```

**Why not OpenTelemetry?** OTEL is significantly more complex (exporters, collectors, OTLP). Prometheus scrape + Grafana is the self-hosted standard. OTEL can layer on later.

---

### 7. Test Suite — pytest ecosystem

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| `pytest` | ≥9.0.3 | Test runner | Standard |
| `pytest-asyncio` | ≥1.4.0 | Async test support | Required for FastMCP async middleware tests |
| `anyio` | ≥4.13.0 | Async test utilities | FastMCP uses anyio internally; consistent backend |
| `httpx` | ≥0.28.1 | HTTP client for integration tests | FastMCP's `run_server_async` test helper works with httpx; replaces requests for async |
| `pytest-cov` | ≥6.0 | Coverage reporting | Standard coverage tooling |

**FastMCP testing pattern (verified via Context7):**

```python
from fastmcp.utilities.tests import run_server_async
from fastmcp import Client

async def test_tool_filter():
    async with run_server_async(server) as url:
        async with Client(url) as client:
            tools = await client.list_tools()
            assert "private_tool" not in [t.name for t in tools]
```

Use in-process `run_server_async` for unit/integration tests — no external server process needed. **Do not use `requests` or `unittest`** — async-incompatible with FastMCP's transport layer.

---

## Complete New Dependencies

```
# requirements.txt additions

# Core upgrade (unlock Auth0/Keycloak providers + Middleware API)
fastmcp[auth]>=3.3.1

# Credential vault + audit DB
sqlalchemy[asyncio]>=2.0.50
aiosqlite>=0.22.1
alembic>=1.18.4
cryptography>=48.0.0

# Structured logging
structlog>=25.5.0

# Admin dashboard
fastapi>=0.136.3
jinja2>=3.1.6
python-multipart>=0.0.20

# Metrics
prometheus-client>=0.25.0

# Dev/test only
pytest>=9.0.3
pytest-asyncio>=1.4.0
anyio>=4.13.0
httpx>=0.28.1
pytest-cov>=6.0
```

---

## Alternatives Rejected

| Category | Recommended | Rejected | Reason |
|----------|-------------|----------|--------|
| OIDC auth | FastMCP built-in providers | authlib, python-jose | FastMCP 3.x handles all token validation; adding authlib creates dual-stack conflict |
| Authz | FastMCP Middleware | Casbin, OPA | Over-engineered for allowlist + tool ACL; middleware is 20 lines vs 200 |
| DB | SQLite + SQLAlchemy | Postgres, Redis | Self-hosted single container; SQLite has zero ops burden; SQLAlchemy makes switching trivial |
| Encryption | cryptography (Fernet) | pycryptodome, PyNaCl | PyCA reference impl; Fernet is authenticated encryption with minimal API surface |
| Admin UI | Jinja2 SSR | React, Vue, HTMX | No JS build pipeline; ops dashboard not user-facing; Jinja2 already installed |
| Metrics | prometheus-client | OpenTelemetry | OTel adds collector complexity; Prometheus scrape is simpler for self-hosted |
| Testing | pytest + httpx | unittest, requests | requests is sync; unittest has no async support; FastMCP test utilities require httpx |
| Logging | structlog | python-logging, loguru | structlog binds async context cleanly; loguru is opinionated in ways that conflict with existing log config |

---

## Sources

- FastMCP Auth Providers: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/auth/oidc-proxy.mdx (Context7, HIGH)
- FastMCP Middleware: https://github.com/prefecthq/fastmcp/blob/main/docs/servers/middleware.mdx (Context7, HIGH)
- FastMCP Testing: https://github.com/prefecthq/fastmcp/blob/main/docs/development/tests.mdx (Context7, HIGH)
- FastMCP ASGI Mounting: https://github.com/prefecthq/fastmcp/blob/main/docs/integrations/fastapi.mdx (Context7, HIGH)
- PyPI versions verified: 2026-05-30 (prometheus-client 0.25.0, cryptography 48.0.0, sqlalchemy 2.0.50, fastmcp 3.3.1, pytest-asyncio 1.4.0, httpx 0.28.1, alembic 1.18.4, structlog 25.5.0)
