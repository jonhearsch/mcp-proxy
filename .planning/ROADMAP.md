# Roadmap: MCP Proxy

**Project:** MCP Proxy
**v1 Goal:** Harden the existing proxy for production reliability and maintainability
**Phases:** 1
**Requirements covered:** 5/5

---

## Phases

- [ ] **Phase 1: Production Hardening** - Refactor structure, fix shutdown reliability, add tests and structured logging

---

## Phase Details

### Phase 1: Production Hardening
**Goal:** The proxy shuts down cleanly, is structured for maintainability, has a passing test suite, and emits structured JSON logs
**Depends on:** Nothing
**Requirements:** FOUND-01, FOUND-02, FOUND-03, FOUND-04, FOUND-05
**Success Criteria** (what must be TRUE):
  1. Running `docker stop` sends SIGTERM and the proxy exits cleanly within 5 seconds with no error output
  2. `proxy_server.py` is replaced by a package structure (`auth/`, `proxy/`, `config/`) — server behavior is unchanged after refactor
  3. Triggering a live reload does not produce SIGINT errors or leave zombie processes — the reload completes cleanly
  4. `pytest` passes with coverage of config loading, auth initialization, restart logic, and signal handling
  5. All log output is valid JSON (structlog format) — no bare `print()` statements remain in the codebase
**Plans:** TBD
**UI hint**: no

---

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Production Hardening | 0/0 | Not started | - |

---
*Roadmap created: 2026-05-30*
