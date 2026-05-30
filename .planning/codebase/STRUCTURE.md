# Codebase Structure

**Analysis Date:** 2026-05-30

## Directory Layout

```
mcp-proxy/                          # Project root
├── proxy_server.py                 # Entire application — single Python file (759 lines)
├── version.py                      # Version constants + get_version() / get_version_info()
├── mcp_config.json                 # Active MCP server definitions (gitignored in production)
├── mcp_config.schema.json          # JSON Schema validator for mcp_config.json
├── mcp_config.example.json         # Example config for reference / docs
├── mcp_config_dev.json             # Dev config (used by docker-compose.yml volume mount)
├── mcp_config_geotab.json          # Alt config preset
├── requirements.txt                # Python dependencies (pip)
├── Dockerfile                      # Production image (python:3.11-slim + nodejs/npm + uv)
├── docker-compose.yml              # Local/dev compose with host networking
├── .env                            # Runtime secrets (gitignored, never read by tools)
├── .env.example                    # Template for required env vars
├── .env.local                      # Local override env (gitignored)
├── CLAUDE.md                       # AI coding guidance for this repo
├── README.md                       # Public documentation
├── LOGGING.md                      # Logging configuration guide
├── LICENSE                         # License file
├── .gitignore
├── .dockerignore
│
├── docs/                           # Extended documentation
│   └── AUTH_PROVIDERS.md           # Auth provider reference
│
├── .github/
│   └── workflows/
│       └── docker-build.yml        # CI/CD: auto-increment patch, multi-arch Docker build
│
├── archive/                        # Historical design docs (not active)
│   ├── AGGREGATOR_CONCEPT.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── PERFORMANCE_SOLUTION.md
│   ├── README.md
│   └── TODO.md
│
├── google_workspace_mcp/           # Bundled sub-project (separate MCP server for Google Workspace)
│   ├── main.py                     # Entry point for google_workspace_mcp server
│   ├── fastmcp_server.py           # FastMCP server definition
│   ├── pyproject.toml              # Its own dependencies (uv)
│   ├── core/                       # Shared core: config, context, storage, tool registry
│   ├── auth/                       # OAuth flow, credential store, middleware
│   ├── gmail/                      # Gmail MCP tools
│   ├── gcalendar/                  # Google Calendar MCP tools
│   ├── gdrive/                     # Google Drive MCP tools
│   ├── gdocs/                      # Google Docs MCP tools
│   ├── gsheets/                    # Google Sheets MCP tools
│   ├── gslides/                    # Google Slides MCP tools
│   ├── gchat/                      # Google Chat MCP tools
│   ├── gcontacts/                  # Google Contacts MCP tools
│   ├── gforms/                     # Google Forms MCP tools
│   ├── gsearch/                    # Google Search MCP tools
│   ├── gtasks/                     # Google Tasks MCP tools
│   ├── gappsscript/                # Google Apps Script MCP tools
│   └── tests/                      # Test suite for google_workspace_mcp
│
└── .venv/                          # Local Python virtualenv (gitignored)
```

## Directory Purposes

**Root (project files):**
- Purpose: All proxy server application code — intentionally flat (single-file architecture)
- Contains: `proxy_server.py`, `version.py`, config files, Docker/compose files
- Key files: `proxy_server.py` (application), `mcp_config.schema.json` (must stay co-located with `proxy_server.py`)

**`docs/`:**
- Purpose: Extended documentation for operators/developers
- Contains: Markdown reference files
- Key files: `docs/AUTH_PROVIDERS.md`

**`.github/workflows/`:**
- Purpose: CI/CD automation
- Contains: `docker-build.yml` — auto-increments patch version in `version.py`, builds multi-arch Docker image (amd64/arm64), pushes to GHCR
- Generated: No
- Committed: Yes

**`archive/`:**
- Purpose: Historical design documents from prior development phases
- Contains: Old plans, concepts, TODOs — not referenced by any code
- Note: Safe to ignore; not imported or loaded at runtime

**`google_workspace_mcp/`:**
- Purpose: A self-contained MCP server for Google Workspace APIs — bundled here as a sub-project for deployment convenience
- Contains: Its own `pyproject.toml`, `auth/`, `core/`, and per-service tool modules
- Note: Operates independently; the proxy can include it via `mcp_config.json` as a stdio/HTTP server

## Key File Locations

**Entry Points:**
- `proxy_server.py:757`: `if __name__ == "__main__": main()` — script execution
- `proxy_server.py:714`: `main()` — reads env vars, constructs proxy, starts loop

**Core Application Logic:**
- `proxy_server.py:315`: `ResilientMCPProxy` class — all lifecycle management
- `proxy_server.py:226`: `ConfigFileHandler` class — watchdog file change handler
- `proxy_server.py:170`: `create_google_auth()` — Google OAuth provider factory
- `proxy_server.py:81`: `setup_logging()` — structured logging setup

**Configuration:**
- `mcp_config.json`: Active runtime config (MCP server definitions)
- `mcp_config.schema.json`: Validation schema — **must be in same directory as `proxy_server.py`**
- `mcp_config.example.json`: Reference example for new deployments
- `.env.example`: Template for required environment variables

**Version:**
- `version.py`: `__version__` and `__build__` constants; `get_version()`, `get_version_info()`

**Container:**
- `Dockerfile`: Production image — copies only `proxy_server.py`, `mcp_config.schema.json`, `version.py`, `requirements.txt`
- `docker-compose.yml`: Dev/local — mounts `mcp_config_dev.json` as `/app/mcp_config.json`

## Naming Conventions

**Files:**
- Application files: `snake_case.py` (e.g., `proxy_server.py`, `version.py`)
- Config files: `snake_case.json` (e.g., `mcp_config.json`, `mcp_config.schema.json`)
- Config variants use suffix: `mcp_config_dev.json`, `mcp_config_geotab.json`
- Documentation: `UPPERCASE.md` for primary docs (`README.md`, `CLAUDE.md`, `LOGGING.md`)

**Python Identifiers (in `proxy_server.py`):**
- Classes: `PascalCase` — `ResilientMCPProxy`, `ConfigFileHandler`
- Functions/methods: `snake_case` — `create_google_auth`, `load_config_with_retry`, `run_with_restart`
- Private methods: leading underscore — `_request_reload`, `_monitor_for_reload`, `_debounced_reload`, `_trigger_reload`
- Constants/module-level: `UPPER_SNAKE` for none currently; env var names follow `MCP_*` and `GOOGLE_*` prefix conventions

## Where to Add New Code

**New proxy-level feature (e.g., rate limiting, request logging middleware):**
- Add to `proxy_server.py` — register as a `custom_route` or middleware on the `self.proxy` FastMCP instance in `create_proxy()` (`proxy_server.py:533`)

**New health/diagnostic endpoint:**
- Add `@self.proxy.custom_route(...)` block inside `create_proxy()` after the existing `/health` route (`proxy_server.py:571`)

**New environment variable:**
- Read in `main()` (`proxy_server.py:714`) using `os.getenv()` or `_parse_int_env()`
- Pass to `ResilientMCPProxy.__init__()` as a constructor argument
- Document in module docstring (`proxy_server.py:1`) and `README.md`

**New MCP server in config:**
- Add entry to `mcp_config.json` following the schema in `mcp_config.schema.json`
- Either `{"command": "...", "args": [...]}` (stdio) or `{"url": "...", "transport": "..."}` (remote)

**Schema changes:**
- Edit `mcp_config.schema.json` — validation runs on every config load; no code changes needed unless new required fields are added

**Version bump:**
- Edit `__version__` in `version.py` for manual major/minor bumps
- Patch is auto-incremented by `.github/workflows/docker-build.yml` on `main` branch push

## Special Directories

**`.venv/`:**
- Purpose: Local Python virtual environment
- Generated: Yes (by `pip` or `uv`)
- Committed: No (gitignored)

**`archive/`:**
- Purpose: Design history — not referenced at runtime
- Generated: No
- Committed: Yes (informational only)

**`google_workspace_mcp/`:**
- Purpose: Bundled sub-project MCP server
- Generated: No
- Committed: Yes
- Note: Has its own `pyproject.toml` and `uv.lock`; managed independently of proxy's `requirements.txt`

---

*Structure analysis: 2026-05-30*
