# Archive

This folder contains historical documentation from the development of MCP Proxy.

## Completed Implementation Plans

- **IMPLEMENTATION_PLAN.md** - v3.0.0 OAuth simplification plan (completed 2026-01-19)
  - Details the migration from hybrid auth (API keys + Auth0/Keycloak/Okta) to Google OAuth only
  - Documents removed code (~735 lines) and simplified architecture

## Design Documents

- **AGGREGATOR_CONCEPT.md** - Experimental aggregator approach for performance
  - Explored pre-loading tools at startup vs. on-demand proxy
  - Not implemented in favor of simpler proxy pattern

- **PERFORMANCE_SOLUTION.md** - Performance analysis and environment-specific configs
  - Analyzed 8-10 second request times with multiple HTTPS servers
  - Solution: Use separate configs for dev/prod environments

## Historical TODOs

- **TODO.md** - Tracking for removed features
  - User whitelist enforcement (never implemented, removed in v3.0.0)
  - References to HybridAuthProvider and API key auth (removed in v3.0.0)

---

These documents are kept for historical context but are not required for using or deploying MCP Proxy.

For current documentation, see:

- [README.md](../README.md) - Getting started guide
- [CLAUDE.md](../CLAUDE.md) - Developer/AI assistant reference
- [docs/AUTH_PROVIDERS.md](../docs/AUTH_PROVIDERS.md) - Google OAuth setup
- [LOGGING.md](../LOGGING.md) - Logging configuration
