# Feature Landscape — MCP Proxy / API Gateway

**Domain:** MCP aggregation proxy / developer tool gateway
**Researched:** 2026-05-30
**Confidence:** HIGH (cross-referenced MCP spec, Kong enterprise docs, 74-repo GitHub topic scan, mcpproxy-go feature set)

---

## Context

MCP Proxy sits at the intersection of two established patterns:
1. **API gateways** (Kong, AWS API Gateway, Tyk) — decades of battle-tested feature expectations
2. **MCP proxy products** (mcpproxy-go, hyprmcp/jetski, Sentinelgate, anythingmcp) — new but rapidly converging on a feature set

Sources used:
- MCP spec (tools/list, tools/call, security recommendations): https://modelcontextprotocol.io/docs/concepts/tools
- Kong API Gateway and Kong MCP production pages: https://konghq.com
- AWS API Gateway docs: https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html
- GitHub topic `mcp-proxy` (74 repos): top products surveyed — mcpproxy-go (236★), hyprmcp/jetski (210★), Sentinelgate (25★), anythingmcp (108★)
- Vault dynamic credentials pattern for credential vault design

---

## Table Stakes

Features users expect. Missing = product feels incomplete or unsafe to deploy.

### Authentication & Authorization

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| User allowlist / domain restriction | Any OAuth proxy without access control is an open proxy | Low | Email allowlist or Google domain restriction; ALL other MCP proxies have this |
| Per-user tool access (allowlist per user or role) | API gateways have had ACLs since day one; MCP spec explicitly requires access controls | Medium | Map user → allowed tool names; deny others at the proxy layer |
| RBAC roles (admin vs. user) | Admin needs elevated permissions to reconfigure, view all logs | Low | Two roles sufficient: `admin` (full access) and `user` (tool invocation only) |
| Multi-auth provider support (OIDC) | Teams don't all use Google; Auth0, Keycloak, Okta are common enterprise IDPs | Medium | FastMCP's provider model supports this — was removed in v3, should return as option |

### Observability & Audit

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Usage audit trail | MCP spec says "log tool usage for audit purposes" (security consideration); AWS CloudTrail, Kong audit log are standard | Low-Medium | Who called which tool, when, with what args summary; write to append-only log |
| Structured logging | Production deployments need parseable logs for Datadog, Splunk, ELK | Low | JSON log lines with user_id, tool_name, server_name, duration, status |
| Health / status endpoint | Kong, AWS API Gateway, every proxy has `/health` or equivalent | Low | Already partially present; needs proper structured response |

### Admin Dashboard

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Server status view | Admin needs to see which upstream MCP servers are connected/healthy | Low | Table: server name, transport type, status, last seen, tool count |
| Tool inventory browser | Admin needs to know what tools are actually available end-to-end | Low | Flat list of all aggregated tools from all servers, with source server label |
| Active session list | Know who is connected right now | Low | Session ID, user identity, connected at, last activity |
| Audit log viewer | Operational visibility into tool invocations | Medium | Filterable by user, tool, time range; paginated |

### Signal Handling & Reliability

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| SIGTERM handling | Docker `docker stop` sends SIGTERM; ignoring it causes dirty shutdown | Low | Already documented as gap in CONCERNS.md |
| Test coverage | Production readiness; contributors need safety net | Medium | Unit tests for access control, config loading, credential injection |
| Code modularization | 759-line single file is a maintenance hazard; maintainers expect structure | Medium | Already in PROJECT.md as Active requirement |

---

## Differentiators

Features that set the product apart. Not universally expected, but highly valued by the target audience.

### Tool Search & Discovery (HIGH VALUE)

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| BM25 lexical tool search | LLMs hit API limits (Cursor: 40 tools, OpenAI: 128 functions); with 100+ aggregated tools, the LLM can't receive all schemas. mcpproxy-go claims 99% token reduction + 43% accuracy improvement by exposing a single `retrieve_tools` function | High | Use BM25 (rank-bm25 Python lib) over tool names + descriptions; expose `search_tools(query)` as the only tool in `tools/list`; tool schemas are fetched on-demand |
| Tool namespace prefixing | When aggregating 10 servers, tool name collisions are common; `github__create_issue` vs `jira__create_issue` is unambiguous | Low | Prefix tool names with server name; configurable separator |
| Tool enable/disable per server | Admin can disable an entire server's tools without removing it from config | Low | Boolean toggle in config; already partially supported |
| Semantic tool search (vector) | Better than BM25 for vague queries; users searching "send an email" find email tools even if description says "compose message" | High | Requires embedding model (sentence-transformers); higher ops complexity; Kong calls this "semantic intelligence for relevant tool delivery" |

**Tool search is the most important differentiator.** The core problem: aggregate 200+ MCP tools, but LLM context windows and API limits can't receive 200 schemas. The proxy exposes `search_tools(query, k=10)` instead. This is unique to MCP proxies vs. traditional API gateways and is the feature competitors are actively building.

### Per-User Credential Vault (HIGH VALUE)

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| User-scoped API key storage | Users authenticate with Google OAuth, then store their own GitHub token, Notion key, etc. Proxy injects the right credential per user when routing to downstream MCP servers | High | Encrypt at rest (Fernet/AES-GCM keyed per user); store in SQLite or encrypted JSON; inject into MCP server environment at connection time |
| Credential injection at routing time | The MCP server receives the user's actual token without the user or the AI ever seeing it in the MCP session | High | Key design insight: credentials live in the vault, get injected as env vars when the proxy spawns/connects to MCP servers on behalf of the user |
| Credential management UI | Users need a page to add/update/delete their stored credentials | Medium | Simple form: service name, value (write-only display), save; no read-back of stored values |
| Per-user MCP server instances | Different users may need different MCP servers or different credentials for the same server | High | Advanced: spawn separate MCP server processes per user session rather than shared pool |

**Credential vault is the other key differentiator.** Without it, every user needs to configure their own MCP servers locally. With it, the proxy is the single place to manage "my GitHub token goes to the GitHub MCP server." mcpproxy-go has "Secrets & Keyring Integration" for this; anythingmcp has OAuth2 downstream support. This is unique to MCP proxies and doesn't map to traditional API gateways.

### Multi-Auth Provider Support

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Auth0 / Keycloak OIDC | Teams with existing IdPs don't want to force Google accounts | Medium | FastMCP's provider model; was in v2, removed in v3; restore as config option |
| OIDC generic provider | Any OIDC-compliant IdP (Okta, PingFederate, Microsoft Entra) | Medium | Generic OIDC config: discovery URL, client_id, client_secret |
| Local user database | Small teams that don't want external IdP dependency | Medium | Username/password with bcrypt; admin creates accounts; less desirable but often requested for air-gapped deployments |

### Rate Limiting & Quotas

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Per-user tool rate limiting | Prevent one user from hammering expensive downstream services | Medium | Token bucket per user per tool; configurable limits in admin |
| Per-server concurrency limits | Protect fragile stdio-based MCP servers from simultaneous calls | Low-Medium | Max concurrent connections to each upstream |

### Prometheus Metrics

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| `/metrics` endpoint | Grafana/Prometheus integration; enterprises expect this | Medium | Counters: requests_total, errors_total, active_sessions; histograms: tool_call_duration |

---

## Anti-Features

Features to explicitly NOT build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| SaaS hosting / cloud deployment | PROJECT.md: out of scope; changes the business model entirely | Document Docker Compose + Fly.io/Railway deployment guides instead |
| Billing & metering | Kong Konnect-level complexity; not relevant for self-hosted OSS | Leave to Prometheus metrics + user's own aggregation |
| Full policy engine (CEL/OPA) | Sentinelgate's approach; 10x more complexity than needed for target audience (self-hosters) | Simple allowlist config is sufficient: `allowed_tools: ["github_*", "notion_read"]` |
| MCP server development tooling | PROJECT.md: out of scope | This proxies servers, doesn't help build them |
| Real-time collaboration / multiplayer | PROJECT.md: out of scope | Not a team workspace product |
| Mobile app | PROJECT.md: out of scope | |
| Dynamic Client Registration as a feature to configure | DCR is already handled by FastMCP's GoogleProvider; exposing it as configurable adds complexity | Keep as an implementation detail; document that Claude.ai handles it automatically |
| Per-tool argument filtering/transformation | Request transformation is API gateway territory; MCP proxies don't do this | Scope access control to allow/deny tool invocation, not argument mutation |
| Semantic caching of tool results | Kong AI Gateway feature; adds enormous complexity (embedding infra, cache invalidation) | Out of scope for v1 of new features |

---

## Feature Dependencies

```
Google OAuth auth (existing)
  → User allowlist / domain restriction   (blocks: anyone can auth)
  → RBAC roles                            (needs: authenticated users)
    → Per-user tool access (allowlist)    (needs: RBAC roles)
    → Admin dashboard                     (needs: admin role)
    → Usage audit trail                   (needs: user identity)

Multi-server aggregation (existing)
  → Tool namespace prefixing              (prevents collisions)
  → Tool search (BM25)                   (needs: full tool inventory)
    → Semantic tool search               (needs: BM25 working first)

User allowlist / domain restriction
  → Per-user credential vault             (needs: stable user identity)
    → Credential injection at routing    (needs: vault populated)
    → Per-user MCP server instances      (needs: vault + session model)

Structured logging
  → Usage audit trail                     (needs: structured log entries)
  → Prometheus metrics                    (needs: structured events)
  → Audit log viewer in UI               (needs: queryable log store)
```

---

## Feature Comparison: This Project vs. Ecosystem

| Feature | mcp-proxy (this) | mcpproxy-go | hyprmcp/jetski | Sentinelgate | Kong MCP |
|---------|-----------------|-------------|----------------|--------------|----------|
| Google OAuth + DCR | ✅ (only option) | Optional | ✅ | ❌ | ✅ |
| Multi-server aggregation | ✅ | ✅ | ❌ (passthrough) | ✅ | ✅ |
| User allowlist | ❌ (gap) | ✅ | ✅ | ✅ | ✅ |
| Per-user tool access | ❌ (gap) | ✅ | ✅ | ✅ RBAC | ✅ |
| Audit log | ❌ (gap) | ✅ | ✅ analytics | ✅ | ✅ |
| Admin web UI | ❌ (gap) | ✅ embedded | ✅ | ❌ | ✅ |
| Tool search (BM25) | ❌ | ✅ BM25 | ❌ | ❌ | semantic |
| Credential vault | ❌ | keyring only | ❌ | ❌ | ❌ |
| Multi-auth (OIDC) | ❌ (was in v2) | ❌ | ✅ Dex/OIDC | ❌ | ✅ |
| Rate limiting | ❌ | ❌ | ❌ | ❌ | ✅ |
| Docker, single-container | ✅ | ✅ | ✅ | ✅ | complex |
| MIT/OSS | ✅ | ✅ | partial | ✅ | partial |

**Competitive position:** The credential vault is essentially unique in the OSS space. Tool search (BM25) exists in mcpproxy-go but not in the server-side proxy model (mcpproxy-go is local-first; this proxy is remote). Combining server-side deployment (access from anywhere) + Claude.ai DCR compatibility + credential vault is a genuinely differentiated position.

---

## MVP Recommendation

Prioritize for the next milestone (roughly ordered by risk/dependency):

1. **User allowlist** — Must have; current state is an open proxy for all Google accounts
2. **SIGTERM handling** — Must have; production Docker deployments break without it
3. **Per-user tool access (allowlist)** — Core security primitive; unlocks multi-user deployment
4. **Usage audit trail** — Required for production trust; simple append-only log
5. **Admin dashboard (basic)** — Server status + tool inventory + session list; the web UI that makes the product feel finished
6. **Credential vault (v1)** — Biggest differentiator; even a basic implementation separates this from all OSS alternatives

Defer:
- **Tool search (BM25)**: High value but significant implementation; defer until credential vault is done
- **Multi-auth (OIDC)**: Real demand but not blocking core use cases; add after v1 hardens
- **Prometheus metrics**: Nice to have; add after basic observability is solid
- **Semantic tool search**: Requires embedding infrastructure; future phase

---

## Sources

- MCP Spec tools documentation: https://modelcontextprotocol.io/docs/concepts/tools (HIGH confidence)
- Kong API Gateway feature matrix: https://konghq.com/products/kong-gateway (HIGH confidence)
- Kong MCP production solution: https://konghq.com/solutions/mcp-production-and-consumption (HIGH confidence)
- AWS API Gateway features: https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html (HIGH confidence)
- mcpproxy-go README and feature docs: https://github.com/smart-mcp-proxy/mcpproxy-go (HIGH confidence — actively maintained, 236★, 178 releases)
- GitHub topic `mcp-proxy` 74 repos survey: https://github.com/topics/mcp-proxy (HIGH confidence — direct ecosystem scan)
- hyprmcp/jetski: https://github.com/hyprmcp/jetski (MEDIUM — 210★, active)
- Sentinelgate: https://github.com/Sentinel-Gate/Sentinelgate (MEDIUM — 25★, RBAC+CEL)
- anythingmcp: https://github.com/HelpCode-ai/anythingmcp (MEDIUM — 108★, OAuth2 downstream)
- HashiCorp Vault credential patterns via Context7 (HIGH confidence — authoritative)
