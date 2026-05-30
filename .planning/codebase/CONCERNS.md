# Codebase Concerns

**Analysis Date:** 2026-05-30

---

## Security Considerations

### No User Allowlist — Any Google Account Can Authenticate

- **Risk:** Any person with a Google account who completes the OAuth flow gains full access to all proxied MCP tools. There is no per-user access control beyond successful Google OAuth login.
- **Files:** `proxy_server.py:546-568`, `archive/TODO.md`
- **Current mitigation:** None. Access control is 100% delegated to Google — if they have a Google account, they're in.
- **Recommendations:**
  - Implement a `users.json` allowlist (infrastructure already documented in `archive/TODO.md` but never ported to current codebase)
  - Check authenticated email against an allowlist in a FastMCP middleware or post-auth hook
  - Consider domain-restriction using Google Workspace's `hd` (hosted domain) OAuth parameter

### GOOGLE_JWT_KEY Optional in Production

- **Risk:** If `GOOGLE_JWT_KEY` is not set, FastMCP uses a default internal key. Tokens issued across restarts may be invalidated or, worse, use a predictable default key depending on the FastMCP version.
- **Files:** `proxy_server.py:189`, `proxy_server.py:209`
- **Current mitigation:** Warning logged as "not set (dev mode)". No hard failure.
- **Recommendations:** Make `GOOGLE_JWT_KEY` required when `MCP_BASE_URL` is not a localhost URL. Fail fast at startup with a clear error.

### Secrets Visible in Process Environment

- **Risk:** `GOOGLE_CLIENT_SECRET` and `GOOGLE_JWT_KEY` are read directly from `os.getenv()`. In containerized environments, environment variables are visible to anyone with access to `docker inspect` or `/proc/<pid>/environ`.
- **Files:** `proxy_server.py:186-189`
- **Current mitigation:** Values are redacted in log output.
- **Recommendations:** Consider using Docker secrets or a secrets manager; document the risk.

### MCP_CONFIG_PATH Not Validated for Path Traversal

- **Risk:** `MCP_CONFIG_PATH` is used directly as a file path without sanitization. A misconfigured or injected environment variable could cause the server to load a config from an unexpected location.
- **Files:** `proxy_server.py:730`, `proxy_server.py:498`
- **Current mitigation:** JSON schema validation runs after load.
- **Recommendations:** Validate that the resolved path is within an expected directory at startup.

---

## Tech Debt

### Single-File Architecture (759 Lines)

- **Issue:** All logic — signal handling, file watching, config loading, OAuth setup, proxy lifecycle, HTTP server — is co-located in `proxy_server.py`. No module separation.
- **Files:** `proxy_server.py` (entire file)
- **Impact:** Hard to test individual components in isolation. Adding new features increases file size linearly. Difficult to onboard contributors. No separation of concerns at the file level.
- **Fix approach:** Extract into modules: `auth.py`, `config.py`, `watcher.py`, `lifecycle.py`. `proxy_server.py` becomes a thin orchestrator.

### dotenv Imported Twice

- **Issue:** `from dotenv import load_dotenv` is imported and called at lines 51-61, then imported again at lines 154-163 for logging purposes. The `.env` file is effectively loaded twice (harmless but confusing).
- **Files:** `proxy_server.py:51-61`, `proxy_server.py:154-163`
- **Impact:** Code smell, confusing execution order.
- **Fix approach:** Load dotenv once, store a flag, log at the appropriate point.

### `restart_delay` Mutation During Crash Loop

- **Issue:** `self.restart_delay` is mutated in-place during exponential backoff (`proxy_server.py:699`). If a crash loop occurs, the delay grows permanently for the lifetime of the process. A server that crashes repeatedly and then recovers will still wait up to 30s on subsequent crashes — even after a long period of stability.
- **Files:** `proxy_server.py:699`
- **Impact:** Unnecessary slow restarts after recovery.
- **Fix approach:** Use a local variable for the current backoff delay; reset it on successful run.

### Unused `restart_count` Reset Logic

- **Issue:** `restart_count` is reset to 0 after a successful run (`proxy_server.py:672`), but `self.restart_delay` is never reset. These two counters are out of sync.
- **Files:** `proxy_server.py:670-672`, `proxy_server.py:699`

### Hardcoded Max Restart Attempts (10)

- **Issue:** The maximum crash-restart count is hardcoded to `10` at `proxy_server.py:694`. The `MCP_MAX_RETRIES` env var only controls config loading retries, not crash restarts. This is confusing.
- **Files:** `proxy_server.py:694`
- **Fix approach:** Expose `MCP_MAX_CRASH_RETRIES` env var, or clarify in docs that `MCP_MAX_RETRIES` is config-load only.

### Archive Directory Contains Stale Implementation Plans

- **Issue:** `archive/` contains `TODO.md`, `IMPLEMENTATION_PLAN.md`, `AGGREGATOR_CONCEPT.md`, `PERFORMANCE_SOLUTION.md` that reference old code structures (e.g., `HybridAuthProvider`, `load_users()`, Auth0) which no longer exist in the codebase.
- **Files:** `archive/TODO.md`, `archive/IMPLEMENTATION_PLAN.md`
- **Impact:** Misleading to contributors. `archive/TODO.md` describes a user whitelist feature as "not implemented" pointing to non-existent code lines.
- **Fix approach:** Delete or clearly date-stamp archive docs; move active TODO items to GitHub Issues.

### Pre-install MCP Dependencies Commented Out in Dockerfile

- **Issue:** Lines 50-53 of `Dockerfile` show commented-out pre-install steps for MCP server dependencies. Without pre-install, all `npx`/`uvx` packages download on first use, causing startup latency and network dependency at runtime.
- **Files:** `Dockerfile:49-53`
- **Impact:** Cold-start performance degradation; failure if npm/PyPI unreachable at first tool invocation.
- **Fix approach:** Uncomment and populate based on current `mcp_config.json` servers, or document that first-run latency is expected.

### No `.env.example` File

- **Issue:** `.env.example` is referenced in `CLAUDE.md` (`cp .env.example .env`) but does not exist in the repo root.
- **Files:** `CLAUDE.md` (Development Commands section)
- **Impact:** Onboarding friction; new developers get a misleading instruction.
- **Fix approach:** Create `.env.example` with all required and optional variables documented.

---

## Fragile Areas

### Live Reload Uses `os.kill(os.getpid(), signal.SIGINT)`

- **Issue:** When a config reload is triggered, `_monitor_for_reload()` sends `SIGINT` to its own process (`proxy_server.py:639`) to stop the uvicorn server. This relies on `SIGINT` being handled correctly by both FastMCP/uvicorn internals and by the proxy's own signal handler.
- **Files:** `proxy_server.py:628-641`
- **Why fragile:**
  - If uvicorn catches `SIGINT` and re-raises it, the proxy's signal handler sets `shutdown_event`, aborting the restart loop.
  - If the `KeyboardInterrupt` propagates before `restart_event` is checked at `proxy_server.py:679`, the server exits instead of reloading.
  - The handler at line 623 (`except KeyboardInterrupt`) calls `self.shutdown_event.set()`, which would terminate the process rather than reload.
- **Safe modification:** Use a proper asyncio shutdown event or uvicorn's programmatic stop API rather than self-signaling. Alternatively, set `restart_event` *before* sending SIGINT to avoid the race.

### SIGTERM Not Registered

- **Issue:** `setup_signal_handlers()` only registers `signal.SIGINT` (`proxy_server.py:405`). `SIGTERM` — which is the default signal sent by Docker, Kubernetes, and `kill` — is not handled.
- **Files:** `proxy_server.py:391-406`
- **Why fragile:** When the container is stopped (`docker stop`), SIGTERM is sent. With no handler, Python's default behavior terminates the process immediately without calling `shutdown_event.set()`, bypassing graceful shutdown. After the 10-second Docker stop timeout, SIGKILL follows anyway, but file watchers and debounce timers may not be cleaned up.
- **Note:** The docstring at line 396 says "Handles SIGTERM (container stop) and SIGINT (Ctrl+C)" — this is incorrect; SIGTERM is mentioned but not registered.
- **Fix approach:** Add `signal.signal(signal.SIGTERM, signal_handler)` alongside the SIGINT line.

### Port Availability Check Has False Positive Risk

- **Issue:** `wait_for_port_available()` tests by attempting to `bind()` to the port (`proxy_server.py:380`). After the test bind succeeds and the socket is closed, there is a window before the actual server binds where another process could claim the port (TOCTOU race).
- **Files:** `proxy_server.py:374-389`
- **Impact:** Low probability in practice, but on a busy host or with rapid restarts, the server could fail to bind despite the check passing.

### File Watcher Silently Disables Live Reload on Error

- **Issue:** If `setup_file_watcher()` fails (e.g., watchdog observer can't start), it sets `self.enable_live_reload = False` (`proxy_server.py:438`) and logs an error — but execution continues without live reload. The operator may not notice.
- **Files:** `proxy_server.py:435-438`
- **Fix approach:** Emit a prominent warning or add a health-check field that reports live-reload status.

### Config Reload Skips if Port Unavailable After Reload

- **Issue:** If `wait_for_port_available()` times out after a reload, `run_with_restart()` calls `break` (`proxy_server.py:683`), terminating the server entirely rather than retrying or falling back.
- **Files:** `proxy_server.py:679-684`
- **Impact:** A config file save during a period of port pressure could kill the proxy permanently, requiring a manual restart.
- **Fix approach:** Retry the port wait loop or fall back to running with the old config.

---

## Test Coverage Gaps

### No Test Suite

- **What's not tested:** Everything. There are no test files in the repository (`*.test.*`, `*_test.py`, `test_*.py`, `tests/` directory) — confirmed by directory listing.
- **Files:** All of `proxy_server.py`
- **Risk:** Any refactor or dependency update can silently break signal handling, config loading, live reload, OAuth initialization, or health check behavior.
- **Priority:** High
- **Suggested starting points:**
  - Unit test `load_config_with_retry()` with mock file I/O
  - Unit test `wait_for_port_available()` with a mock socket
  - Unit test `_parse_int_env()` (already well-isolated)
  - Integration test: start server, hit `/health`, assert 200

---

## Performance Bottlenecks

### MCP Subprocess Cold Start on First Tool Call

- **Issue:** `stdio`-transport MCP servers (those using `command`/`args` in `mcp_config.json`) are launched as subprocesses by FastMCP when first accessed. With `npx` or `uvx` packages not pre-installed (Dockerfile pre-install is commented out), the first invocation triggers a package download.
- **Files:** `Dockerfile:49-53`, `mcp_config.json`
- **Impact:** First tool call per server can take 10-60+ seconds; timeout errors likely for callers.

---

## Dependencies at Risk

### Unpinned `fastmcp` Dependency

- **Risk:** `requirements.txt` specifies `fastmcp[auth]>=2.13.0.2` with no upper bound. FastMCP is a rapidly evolving library; a breaking change in the `GoogleProvider` API, `as_proxy()` signature, or `custom_route()` behavior could silently break the proxy on next install.
- **Files:** `requirements.txt:1`
- **Impact:** Docker image rebuilds or fresh installs could pick up an incompatible version.
- **Migration plan:** Pin to `fastmcp[auth]>=2.13.0.2,<3.0.0` or use a lockfile (e.g., `pip-compile` generated `requirements.lock`).

### All Other Dependencies Fully Unpinned

- **Risk:** `python-dotenv`, `watchdog`, and `jsonschema` have no version constraints whatsoever in `requirements.txt`.
- **Files:** `requirements.txt`
- **Impact:** Non-reproducible builds; potential for subtle breakage.
- **Fix approach:** Pin all dependencies with `pip freeze > requirements.lock` or adopt `uv lock`.

### Node.js Version in Dockerfile Not Pinned

- **Risk:** `apt-get install nodejs` installs the Debian default Node.js version (currently 18.x in Debian Bookworm), which may not match the version expected by `npx`-based MCP servers.
- **Files:** `Dockerfile:4-9`
- **Fix approach:** Use NodeSource to install a specific Node.js LTS version.

---

## Missing Critical Features

### No Authorization Beyond Authentication

- **Problem:** The proxy authenticates users via Google OAuth but performs no authorization. All authenticated users have access to all tools from all configured MCP servers. There is no per-user, per-tool, or per-server access control.
- **Blocks:** Enterprise or multi-tenant use cases.

### No Config Validation of Server Reachability at Startup

- **Problem:** `load_config_with_retry()` validates JSON schema but does not probe whether configured MCP servers (especially SSE/HTTP `url`-based servers) are actually reachable.
- **Files:** `proxy_server.py:468-531`
- **Blocks:** Early detection of misconfigured upstreams; silent failures surface only at tool-call time.

### Health Check Returns No Upstream Status

- **Problem:** The `/health` endpoint at `proxy_server.py:572-573` always returns `{"status": "healthy"}` regardless of whether any downstream MCP servers are running or reachable.
- **Files:** `proxy_server.py:571-573`
- **Blocks:** Meaningful liveness/readiness probing in Kubernetes or Docker health checks.

---

*Concerns audit: 2026-05-30*
