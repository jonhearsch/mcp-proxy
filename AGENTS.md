# AGENTS.md — MCP Proxy

## Project

MCP Proxy is an open-source remote gateway for Model Context Protocol servers. It aggregates multiple MCP servers behind a single Google OAuth-authenticated endpoint, making Claude.ai tools accessible from anywhere.

**Planning docs:** `.planning/` — read `STATE.md` first for current status, `PROJECT.md` for full context.

## GSD Workflow

This project uses the Get Shit Done (GSD) workflow for planning and execution.

**Current milestone:** v1 Production Hardening (1 phase)

**Before starting any work:**
1. Read `.planning/STATE.md` — current phase, open questions
2. Read `.planning/ROADMAP.md` — phase goals and success criteria
3. Read `.planning/REQUIREMENTS.md` — what v1 must deliver

**Commands:**
- `/gsd-plan-phase 1` — plan Phase 1 (Production Hardening)
- `/gsd-progress` — check current status

## Architecture

Single Python application in `proxy_server.py` (759 lines, currently a monolith — Phase 1 refactors this).

Core flow: load `mcp_config.json` → create `GoogleProvider` auth → create `FastMCP.as_proxy()` → run HTTP server on `:8080` → watchdog watches config file → reload or crash triggers restart loop.

Key classes:
- `ResilientMCPProxy` — orchestrates server lifecycle, restart logic, file watching
- `ConfigFileHandler` — watchdog event handler with 1s debounce
- `create_google_auth()` — initializes GoogleProvider from env vars

**Codebase map:** `.planning/codebase/` (mapped 2026-05-30)

## Conventions

- Python 3.10+, FastMCP, watchdog, jsonschema
- Logging: currently standard `logging` module — Phase 1 migrates to structlog JSON
- Tests: none yet — Phase 1 adds pytest + pytest-asyncio
- Docker: `ghcr.io/jonhearsch/mcp-proxy:latest`, multi-arch (amd64/arm64)

## Known Issues (Phase 1 targets)

- `SIGTERM` not registered — only `SIGINT` handled (Docker stop doesn't cleanly shut down)
- Live reload uses `os.kill(os.getpid(), signal.SIGINT)` — fragile
- No tests
- All code in one 759-line file
- `print()`-style logging mixed with `logging` module
