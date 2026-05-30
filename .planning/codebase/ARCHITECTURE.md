<!-- refreshed: 2026-05-30 -->
# Architecture

**Analysis Date:** 2026-05-30

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        HTTP Clients (Claude.ai, etc.)                │
│                  GET/POST https://{MCP_BASE_URL}/mcp/                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         proxy_server.py                              │
│                                                                      │
│  ┌────────────────────┐   ┌───────────────────────────────────────┐ │
│  │  ResilientMCPProxy │   │         ConfigFileHandler             │ │
│  │  (lifecycle mgr)   │   │   (watchdog FileSystemEventHandler)   │ │
│  └────────┬───────────┘   └──────────────────┬────────────────────┘ │
│           │                                  │ file change events   │
│           │ run_with_restart()               │ (debounced 1s)       │
│           ▼                                  ▼                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │              FastMCP.as_proxy(config, auth=auth)               │ │
│  │                  (FastMCP library - HTTP transport)            │ │
│  └────────────────────────────────────────────────────────────────┘ │
│           │                                  │                      │
│           ▼                                  ▼                      │
│  ┌────────────────────┐   ┌───────────────────────────────────────┐ │
│  │    GoogleProvider  │   │          mcp_config.json              │ │
│  │  (Google OAuth 2.0)│   │   (validated by mcp_config.schema.json│ │
│  └────────────────────┘   └───────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         stdio MCP       SSE MCP      HTTP MCP
         servers        servers       servers
     (uvx/npx cmds)  (remote URLs) (remote URLs)
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| `main()` | Entry point; reads env vars, creates `ResilientMCPProxy`, calls `run_with_restart()` | `proxy_server.py:714` |
| `ResilientMCPProxy` | Full lifecycle: config loading, proxy creation, file watching, crash recovery, port mgmt | `proxy_server.py:315` |
| `ConfigFileHandler` | Watchdog event handler; debounces filesystem events, calls reload callback | `proxy_server.py:226` |
| `create_google_auth()` | Reads env vars, constructs `GoogleProvider` for OAuth; returns `None` if not configured | `proxy_server.py:170` |
| `setup_logging()` | Configures structured logging with per-logger level overrides via env vars | `proxy_server.py:81` |
| `_parse_int_env()` | Safe integer env var parser with fallback | `proxy_server.py:704` |
| `version.py` | Exposes `get_version()` / `get_version_info()` — auto-updated by CI | `version.py` |
| `mcp_config.schema.json` | JSON Schema (draft 2020-12) validates `mcp_config.json` on every load | `mcp_config.schema.json` |

## Pattern Overview

**Overall:** Single-file Resilience Wrapper around a third-party proxy framework

**Key Characteristics:**
- All application logic lives in one file (`proxy_server.py`, 759 lines)
- `FastMCP.as_proxy()` handles all actual MCP protocol work — the proxy adds only lifecycle management, auth wiring, and config watching
- Process-level reload: config changes send `SIGINT` to self, outer `run_with_restart()` loop re-initializes everything
- No custom routing logic — all MCP traffic handled by FastMCP's HTTP transport at `/mcp/`
- Authentication is mandatory: startup aborts if Google OAuth env vars are missing

## Layers

**Entry / Configuration Layer:**
- Purpose: Parse environment variables, instantiate `ResilientMCPProxy`
- Location: `proxy_server.py:714` (`main()`)
- Contains: Env var reading, boolean/int parsing, proxy construction
- Depends on: `ResilientMCPProxy`, environment
- Used by: Process init (`__main__` block at line 757)

**Lifecycle Management Layer:**
- Purpose: Orchestrate startup, restart, config reload, and shutdown
- Location: `proxy_server.py:315` (`ResilientMCPProxy`)
- Contains: `run_with_restart()`, `load_config_with_retry()`, `create_proxy()`, signal handlers, port checks
- Depends on: FastMCP library, `ConfigFileHandler`, `create_google_auth()`
- Used by: `main()`

**File Watching Layer:**
- Purpose: Detect config file changes and signal a reload
- Location: `proxy_server.py:226` (`ConfigFileHandler`)
- Contains: Watchdog event handlers (`on_modified`, `on_moved`, `on_created`, `on_deleted`), debounce timer
- Depends on: `watchdog` library, `threading.Timer`
- Used by: `ResilientMCPProxy.setup_file_watcher()`

**Auth Layer:**
- Purpose: Create Google OAuth 2.0 provider for Claude.ai-compatible DCR flow
- Location: `proxy_server.py:170` (`create_google_auth()`)
- Contains: `GoogleProvider` construction with required OIDC scopes and optional JWT signing key
- Depends on: `fastmcp.server.auth.providers.google.GoogleProvider`, env vars
- Used by: `ResilientMCPProxy.create_proxy()`

**FastMCP Proxy Layer:**
- Purpose: Aggregate all configured MCP servers behind a single HTTP endpoint
- Location: FastMCP library (external) — invoked at `proxy_server.py:564`
- Contains: MCP protocol implementation, HTTP transport (`/mcp/`), OAuth middleware, DCR endpoints
- Depends on: `mcp_config.json`, `GoogleProvider`
- Used by: `ResilientMCPProxy.run_server()` / `run_server_with_reload()`

## Data Flow

### Primary Request Path

1. HTTP client sends MCP request to `https://{MCP_BASE_URL}/mcp/`
2. FastMCP's GoogleProvider middleware validates Bearer JWT token
3. FastMCP routes MCP method call to the appropriate upstream MCP server (stdio/SSE/HTTP)
4. Upstream server responds; FastMCP returns response to client

### OAuth / Authentication Flow

1. Client calls `POST /register` (DCR) — FastMCP's `GoogleProvider` issues client credentials
2. Client redirects user to `GET /auth/login` — initiates Google OAuth consent
3. Google redirects to `GET /auth/callback` — `GoogleProvider` exchanges code for tokens, issues JWT
4. Client uses JWT as Bearer token for all subsequent `/mcp/` requests

### Live Reload Flow

1. Config file saved → watchdog fires `on_modified` / `on_moved` event
2. `ConfigFileHandler._debounced_reload()` cancels any existing timer, starts new 1s timer
3. After 1s debounce, `_trigger_reload()` calls `ResilientMCPProxy._request_reload()`
4. `_request_reload()` sets `reload_event`
5. Background thread `_monitor_for_reload()` detects `reload_event`, sets `restart_event`, sends `SIGINT` to self (`os.kill(os.getpid(), signal.SIGINT)`) at `proxy_server.py:639`
6. Server exits; `run_with_restart()` checks `restart_event`, calls `wait_for_port_available()`, then loops to reload config and recreate proxy

### Crash Recovery Flow

1. Exception escapes `run_server_with_reload()` into `run_with_restart()` exception handler
2. `restart_count` incremented; if >= 10, exits
3. `time.sleep(restart_delay)` with exponential backoff (`restart_delay *= 1.5`, cap 30s) at `proxy_server.py:699`
4. Loop continues: `load_config_with_retry()` → `create_proxy()` → `run_server_with_reload()`

**State Management:**
- All mutable state lives on the `ResilientMCPProxy` instance (no module-level globals except logger)
- Threading primitives: `shutdown_event`, `reload_event`, `restart_event` (all `threading.Event`)
- File observer and config handler stored on instance; torn down cleanly in `stop_file_watcher()`

## Key Abstractions

**ResilientMCPProxy:**
- Purpose: Self-healing process loop — decouples FastMCP lifecycle from crash/reload concerns
- Location: `proxy_server.py:315`
- Pattern: Stateful class with explicit lifecycle methods; not a context manager

**ConfigFileHandler:**
- Purpose: Debounced watchdog adapter — translates filesystem noise into a single reload signal
- Location: `proxy_server.py:226`
- Pattern: Subclass of `watchdog.events.FileSystemEventHandler`

**GoogleProvider (external):**
- Purpose: Encapsulates full Google OAuth + DCR flow for Claude.ai compatibility
- Location: `fastmcp.server.auth.providers.google` (library)
- Pattern: Passed as `auth=` kwarg to `FastMCP.as_proxy()`

**mcp_config.schema.json:**
- Purpose: Contract for valid config structure; enforced on every load via `jsonschema.validate()`
- Location: `mcp_config.schema.json`
- Pattern: JSON Schema draft 2020-12; `anyOf` requires either `{command, args}` or `{url, transport}`

## Entry Points

**`main()` (normal startup):**
- Location: `proxy_server.py:714`
- Triggers: `python proxy_server.py` or Docker `CMD`
- Responsibilities: Read env, construct `ResilientMCPProxy`, call `run_with_restart()`

**`if __name__ == "__main__"` block:**
- Location: `proxy_server.py:757`
- Triggers: Direct script execution
- Responsibilities: Calls `main()`

**`/health` endpoint:**
- Location: `proxy_server.py:571` (registered as `custom_route` on the FastMCP instance)
- Triggers: `GET /health`
- Responsibilities: Returns `{"status": "healthy", "service": "mcp-proxy"}` — used by Docker HEALTHCHECK

## Architectural Constraints

- **Threading:** Main server runs in the calling thread (uvicorn event loop via FastMCP). File watcher runs in a watchdog daemon thread. Reload monitor runs in a `threading.Thread(daemon=True)`. Debounce uses `threading.Timer`.
- **Global state:** `logger` module-level singleton (`proxy_server.py:144`). Library loggers configured at module load time (`proxy_server.py:147–151`).
- **Circular imports:** None — single-file application.
- **Process-level reload:** Live reload sends `SIGINT` to own PID rather than a hot-reload; the entire FastMCP instance is destroyed and recreated. This is the only safe approach given FastMCP does not expose a reload API.
- **Auth is mandatory:** `create_proxy()` returns `False` if `create_google_auth()` returns `None`, aborting startup. There is no unauthenticated mode.
- **Schema co-location required:** `load_config_with_retry()` resolves `mcp_config.schema.json` relative to the script's own directory (`__file__`). Schema must be in the same directory as `proxy_server.py`.

## Anti-Patterns

### Importing `dotenv` twice
**What happens:** `proxy_server.py` imports and calls `load_dotenv()` at lines 51–61 (before logging is configured), then imports it again at lines 154–163 (after logging) just to log whether the file was found.
**Why it's wrong:** Double import, and the second load is a no-op (dotenv skips already-set vars). Adds noise and confusion.
**Do this instead:** Track whether `.env` was loaded in a module-level boolean on the first import block; log it after `setup_logging()` using that boolean.

### `os._exit()` → now resolved, but `os.kill(os.getpid(), signal.SIGINT)` in a thread
**What happens:** `_monitor_for_reload()` spawns yet another daemon thread (`proxy_server.py:638`) to send `SIGINT` to the process.
**Why it's wrong:** Signal delivery to the main thread is not guaranteed when sent from a background thread on all platforms; also creates an extra thread indirection.
**Do this instead:** Use `threading.Event` to signal the main thread, which then performs the shutdown directly.

## Error Handling

**Strategy:** Fail-fast for permanent config errors; exponential backoff retry for transient errors; max 10 crash restarts before giving up.

**Patterns:**
- `FileNotFoundError` and `json.JSONDecodeError` in `load_config_with_retry()` return `False` immediately (no retry)
- `jsonschema.ValidationError` also returns `False` immediately
- All other exceptions in the config load retry loop use `2 ** attempt` backoff (1s, 2s, 4s…)
- Exceptions escaping `run_server_with_reload()` trigger `restart_delay *= 1.5` (starting at 5s, capped at 30s)
- All exceptions logged with `exc_info=True` for full tracebacks

## Cross-Cutting Concerns

**Logging:** `logging` stdlib with dual handlers (stdout for INFO/DEBUG, stderr for WARNING+). Configured via `MCP_LOG_LEVEL` (global) and `MCP_LOG_LEVELS` (per-logger, comma-separated `name:LEVEL` pairs). Logger name field is 15 chars wide for alignment.

**Validation:** JSON Schema validation on every config load via `jsonschema.validate()`. Schema file: `mcp_config.schema.json`.

**Authentication:** Google OAuth 2.0 via FastMCP's `GoogleProvider`. Enforced at the FastMCP HTTP middleware layer. All `/mcp/` requests require a valid Bearer JWT.

---

*Architecture analysis: 2026-05-30*
