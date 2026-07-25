# Project State: MCP Proxy

## Current Status

**Phase:** Phase 1 — Production Hardening
**Status:** In Progress (2/4 plans complete)
**Plans:** 4 (waves 1–4)
**Last updated:** 2026-07-25

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-30)

**Core value:** Any MCP client can securely access any combination of MCP servers from anywhere, with per-user access control — without running servers locally.
**Current focus:** Phase 1 — Production Hardening (next: Plan 03 — structlog migration)

## Phase History

- 01-01 complete: proxy_server.py extracted into mcp_proxy/ package (auth, config, watcher modules)
- 01-02 complete: SIGTERM registered; _monitor_for_reload uses direct SIGTERM without thread wrapper
- New scope complete (not tied to a FOUND-NN requirement): static shared-token auth mode (`MCP_AUTH_TOKEN`) added for gateway-fronted deployments (e.g. agentgateway), alongside existing Google OAuth and `MCP_DISABLE_AUTH`. Three-way precedence in `create_proxy()`. See `mcp_proxy/auth.py::create_static_token_auth()` and `docs/AUTH_PROVIDERS.md`.

## Decisions

- Used direct os.kill(os.getpid(), signal.SIGTERM) in _monitor_for_reload — thread wrapper was only needed to avoid SIGINT traceback, no longer needed with SIGTERM registered
- restart_event.set() ordering preserved before os.kill() to avoid race in run_with_restart()
- Static token auth uses FastMCP's built-in `StaticTokenVerifier` rather than custom Starlette middleware. `create_proxy()` already passes a single `auth=` provider to `FastMCP.as_proxy()`, and the server runs via the blocking `proxy.run(transport="http")` (no `http_app()`/ASGI object exposed), so middleware would have required a bigger migration for no real benefit — `StaticTokenVerifier` already accepted the standard `Authorization: Bearer` header.
- Invalid `MCP_AUTH_TOKEN` (too short) is a hard startup failure, not a silent fallthrough to Google OAuth — switching auth modes on a misconfiguration would be a security surprise.
- Accepted trade-offs of static-token mode, documented rather than hidden: `StaticTokenVerifier.verify_token()` does a plain dict lookup, not a constant-time compare (immaterial across a LAN behind a gateway); no per-user identity, expiry, or rotation; the token is not a substitute for network scoping (`MCP_HOST=127.0.0.1` recommended when the gateway is co-located).
- Kept `MCP_DISABLE_AUTH` (added earlier, uncommitted) as a third mode for local debugging, even though static-token mode supersedes it for the actual gateway deployment — user's explicit call.

## Open Questions

(none)

---
*State initialized: 2026-05-30*
