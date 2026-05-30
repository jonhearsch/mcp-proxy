# Domain Pitfalls: MCP Proxy — Auth, Credential Vault, Tool Filtering, Admin Dashboard

**Domain:** MCP proxy / API gateway with per-user credential vault and access control  
**Researched:** 2026-05-30  
**Confidence:** HIGH (FastMCP docs via Context7; security patterns from established API gateway literature; codebase concerns from verified CONCERNS.md)

---

## Critical Pitfalls

Mistakes that cause security incidents, data loss, or complete rewrites.

---

### Pitfall C1: Vault Master Key Lives Beside the Data It Protects

**What goes wrong:**  
The encryption key used to encrypt stored user credentials (API keys, tokens) is stored in the same place as the encrypted blobs — the same SQLite file, same `.env`, same container filesystem. An attacker with read access to one has both.

**Why it happens:**  
It's the path of least resistance. You already have `.env` for `GOOGLE_CLIENT_SECRET`, so you add `VAULT_MASTER_KEY` there too, and the vault database is in the same Docker volume.

**Consequences:**  
Encrypted-at-rest credential storage becomes security theater. All per-user API keys are compromised in a single file read.

**Prevention:**  
- The master key must live in a **different trust boundary** from the ciphertext. Options in priority order:
  1. Docker secret (`/run/secrets/vault_master_key`) mounted separately from data volume
  2. External secret (env var injected from a secrets manager, never written to disk)
  3. Derive per-user vault keys from `VAULT_MASTER_KEY` + user ID using HKDF (not PBKDF2 — that's for passwords), so a single key exposure doesn't expose all users' plaintext at once
- Use `cryptography.fernet.Fernet` with a master key loaded only at startup; store only ciphertext in the DB
- Never log, return in API responses, or embed the master key in health check output

**Warning signs:**  
- `VAULT_MASTER_KEY` is in `.env` and the DB is in the same `./data/` volume
- Key is base64-encoded directly in source or config JSON

**Phase:** Credential vault implementation (before any vault storage is written)

---

### Pitfall C2: Tool Call Interception Bypasses the Tool Filter

**What goes wrong:**  
`on_list_tools` correctly hides disallowed tools from the tool listing. But `tools/call` is never filtered — a user who knows a tool's name (from memory, a previous session, or brute force) can call it directly even though it's not listed.

**Why it happens:**  
FastMCP's `on_list_tools` middleware only intercepts list requests. Call-time enforcement requires a **separate** `on_call_tool` hook. Developers test by checking the list and assume filtering is complete.

**Consequences:**  
"Hidden" tools are actually just unlisted, not blocked. A determined user has unrestricted access to every downstream MCP tool.

**Prevention:**  
Always pair filtering hooks — both must be implemented together or neither is security:
```python
class UserToolFilter(Middleware):
    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        return [t for t in tools if self._allowed(user, t.name)]

    async def on_call_tool(self, context, call_next):
        if not self._allowed(user, context.message.name):
            raise ToolError("Tool not found")  # Use "not found" not "forbidden" — avoids name disclosure
        return await call_next(context)
```

**Warning signs:**  
- Only `on_list_tools` is implemented
- Tests only verify tool listing, not direct tool invocation with disallowed tool names

**Phase:** Per-user tool access control implementation

---

### Pitfall C3: Admin Dashboard Has No Separate Auth — It Inherits MCP OAuth

**What goes wrong:**  
The admin dashboard is added as additional routes on the same FastMCP server. It's protected by the same Google OAuth session that protects `/mcp/`. Any authenticated Google user who knows the `/admin/` URL gets admin access.

**Why it happens:**  
Reusing the existing OAuth session is easy. The "auth already works" assumption skips the question of *what the auth grants*.

**Consequences:**  
Every user who can use the proxy can access the admin dashboard — seeing all users' sessions, usage logs, and (if not careful) vault management endpoints.

**Prevention:**  
- Admin routes must check for an explicit admin claim/role from the token, not just authentication:
  ```python
  token = get_access_token()
  if token.claims.get("email") not in ADMIN_EMAILS:
      raise HTTPException(403)
  ```
- Alternatively, serve the admin dashboard on a separate port (`8081`) bound to `127.0.0.1` only — inaccessible outside the container without explicit port forwarding
- Allowlist of admin emails/domain must be configured separately from the general user allowlist

**Warning signs:**  
- Admin routes only check `if token is not None`
- Admin and proxy share the same session cookie or Bearer token without role checks
- No `ADMIN_EMAILS` or `ADMIN_DOMAIN` config variable exists

**Phase:** Admin dashboard implementation

---

### Pitfall C4: Credential Injection Leaks Downstream API Keys Into MCP Logs

**What goes wrong:**  
When injecting per-user credentials into downstream MCP server requests (the core vault feature), the credentials appear in FastMCP's request/response logging, structured log output, or error tracebacks.

**Why it happens:**  
MCP tool arguments are dictionaries. If credentials are injected as tool arguments or environment variables at invocation time and something goes wrong, Python's default exception formatting will dump the full argument dict — including the decrypted API key.

**Consequences:**  
Decrypted user API keys end up in log files, observability platforms (Datadog, CloudWatch), or Docker stdout that operators can read.

**Prevention:**  
- Inject credentials as environment variables into subprocess-based (stdio) MCP servers via a modified config — not as tool arguments
- For SSE/HTTP downstream servers, inject credentials via HTTP headers (not URL params, not request body fields that get logged)
- Mark credential fields as `sensitive=True` in any structured logging wrapper
- Redact patterns matching known API key formats in the log pipeline
- Test: deliberately cause a tool call error and verify the traceback contains no secrets

**Warning signs:**  
- Credentials appear in `args` or `params` of MCP tool call objects
- Log output contains `Bearer sk-`, `api_key=`, or similar patterns
- No credential redaction in logging configuration

**Phase:** Credential vault + injection implementation

---

### Pitfall C5: Open Redirect via Unvalidated OIDC Callback State

**What goes wrong:**  
Adding multiple OIDC providers (Auth0, Keycloak, Google) means multiple callback routes. If the OAuth `state` parameter or `redirect_uri` is not validated against a fixed allowlist, an attacker can craft a login URL that redirects to a malicious domain after auth succeeds.

**Why it happens:**  
FastMCP's built-in `GoogleProvider` handles this internally. When switching to `OIDCProxy` or `OAuthProxy` for additional providers, developers configure `base_url` but forget that `redirect_uri` validation must be strict on the authorization server AND the proxy.

**Consequences:**  
Auth code interception, session fixation, token theft via open redirect.

**Prevention:**  
- Register exact redirect URIs in every OAuth provider console — no wildcards, no patterns
- Validate `state` parameter round-trips cryptographically (FastMCP handles this, but verify with custom providers)
- Use `OIDCProxy` over raw `OAuthProxy` where the provider supports OIDC discovery — it auto-configures correct endpoint URLs, reducing misconfiguration surface
- One callback URL per provider, all registered in that provider's console

**Warning signs:**  
- `redirect_uri` accepts anything with the right hostname prefix
- State parameter is not verified on callback
- Multiple providers sharing a single callback route with provider determined by a query param

**Phase:** Multi-OIDC provider support

---

### Pitfall C6: User Allowlist Checked at Login But Not at Request Time

**What goes wrong:**  
An allowlist is added to block unauthorized Google accounts at the OAuth callback. But the check only runs during the initial login. If an allowlist entry is removed (user offboarded), that user's existing session JWT remains valid for the token's lifetime (hours to days) — they retain full access.

**Why it happens:**  
OAuth sessions work by issuing JWTs that are validated offline. There's no per-request database lookup in the default FastMCP flow.

**Consequences:**  
Offboarded users continue to have access. In a multi-tenant proxy with per-user credential vaults, this means ongoing access to sensitive downstream API keys.

**Prevention:**  
- For any non-trivial deployment: add a FastMCP middleware that checks the token's `email` claim against the allowlist on **every request** (not just at login):
  ```python
  async def on_call_tool(self, context, call_next):
      email = get_access_token().claims.get("email")
      if email not in self.load_allowlist():
          raise ToolError("Access denied")
      return await call_next(context)
  ```
- Keep JWT expiry short (1 hour or less) for the proxy
- Cache the allowlist in memory with a short TTL (30s) — do not read the file on every single request

**Warning signs:**  
- Allowlist is only checked in the OAuth callback handler
- JWT expiry is not configured (may default to provider's default — hours or days)
- No `revocation` or `session invalidation` mechanism

**Phase:** User access control / allowlist

---

### Pitfall C7: Usage Log Contains Full Tool Arguments (PII / Secret Exposure)

**What goes wrong:**  
An audit log records `user_email`, `tool_name`, `arguments`, and `result` for every tool call. This is exactly what you want — until `arguments` contains a user's OAuth token, a credit card number passed to a payment tool, or a `password` field.

**Why it happens:**  
Logging the full argument dict is one line of code and extremely useful for debugging. The sensitivity of arguments is tool-specific and not obvious at logging time.

**Consequences:**  
The audit log itself becomes a sensitive artifact. GDPR/compliance implications. If logs are shipped to an external service, secrets leave the deployment.

**Prevention:**  
- Log **metadata only** by default: `tool_name`, `user_email`, `timestamp`, `duration_ms`, `success/error`
- Never log `arguments` or `result` in production unless explicitly opted in per-tool via a `loggable_args` whitelist
- If arguments must be logged (debugging), apply a redaction pass first — strip keys matching patterns like `*key*`, `*secret*`, `*token*`, `*password*`, `*auth*`
- Separate the debug log level (with arguments) from the audit log level (metadata only)

**Warning signs:**  
- Usage log schema includes `arguments TEXT` or `result TEXT` columns with no redaction
- Log entries contain JSON blobs from tool call results
- No documented policy on what gets logged

**Phase:** Usage logging implementation

---

## Moderate Pitfalls

---

### Pitfall M1: Single-File Architecture Makes Auth Middleware Untestable

**What goes wrong:**  
Adding allowlist checks, vault injection, and tool filtering to `proxy_server.py` (already 759 lines) makes each feature depend on global state, making unit tests require a full server spin-up.

**Prevention:**  
Refactor into modules **before** adding security features. Each module (`auth.py`, `vault.py`, `filters.py`) can be unit-tested in isolation. The refactor is the foundation, not optional polish.

**Phase:** Code structure refactor (must precede security feature implementation)

---

### Pitfall M2: `os.kill(SIGINT)` Reload Race With Vault Writes

**What goes wrong:**  
The existing fragile reload mechanism (`os.kill(os.getpid(), SIGINT)`) has a race condition that's benign now but becomes dangerous with a credential vault. If a reload fires mid-write to the vault database, the write transaction may be incomplete, potentially corrupting the vault.

**Prevention:**  
- Fix the reload mechanism to use a proper `asyncio.Event` shutdown path (already flagged in CONCERNS.md) before implementing the vault
- Vault writes must use SQLite transactions; interrupted transactions roll back cleanly
- Do not implement vault until the reload fragility is resolved

**Phase:** Fix reload before vault work

---

### Pitfall M3: Admin Dashboard CSRF on State-Changing Endpoints

**What goes wrong:**  
The admin dashboard has endpoints like `DELETE /admin/users/{email}`, `POST /admin/vault/rotate-key`. If these are reachable via browser and protected only by a session cookie, they're CSRF-vulnerable — a malicious page can trigger them.

**Prevention:**  
- Use `SameSite=Strict` on session cookies
- Require CSRF token on all mutating admin endpoints (or use Bearer token auth, which is CSRF-safe)
- Prefer the admin-on-separate-port pattern — unreachable from the browser context where CSRF originates

**Phase:** Admin dashboard implementation

---

### Pitfall M4: Tool Filter Evaluated From Stale Config After Live Reload

**What goes wrong:**  
Tool access rules are loaded at startup and cached in the middleware instance. A live config reload (`mcp_config.json` change) creates a new FastMCP proxy instance but the middleware holding the access rules may reference the old config.

**Prevention:**  
- Tool filter config must be re-read on every reload (not cached in instance variables that survive reload)
- Design the filter middleware to load its rules from a file/DB on each request (with a short in-memory TTL cache) rather than once at init
- Integration test: change tool filter config → reload → verify new rules apply immediately

**Phase:** Per-user tool access + live reload interaction

---

### Pitfall M5: Multi-OIDC Breaks DCR If Multiple Providers Expose `/register`

**What goes wrong:**  
Claude.ai uses Dynamic Client Registration (DCR) at `/register`. FastMCP's `GoogleProvider` exposes this automatically. Adding a second OIDC provider (Auth0, Keycloak) via `MultiAuth` may create a routing conflict — two providers trying to register clients, or DCR returning credentials for the wrong provider.

**Why it happens:**  
FastMCP's `MultiAuth` accepts tokens from multiple issuers but DCR is typically tied to one issuer's flow. Naively stacking providers causes ambiguity in which provider handles the initial client registration.

**Prevention:**  
- Use `MultiAuth` with one `server` (the DCR/OAuth flow provider) and additional `verifiers` (JWT-only, no DCR) for other issuers — the FastMCP docs pattern for this is `MultiAuth(server=OAuthProxy(...), verifiers=[JWTVerifier(...)])`
- Keep Google as the single DCR/interactive provider; add other providers as JWT verifiers only
- Test DCR endpoint explicitly after adding each new provider

**Phase:** Multi-OIDC provider support

---

### Pitfall M6: Vault Key Rotation Not Planned From Day One

**What goes wrong:**  
The vault is built with a single master key. A year later, the key needs to be rotated (security policy, suspected exposure). All vault entries must be re-encrypted. There's no migration path because key versioning was never designed in.

**Prevention:**  
- Use `cryptography.fernet.MultiFernet` from the start — it supports multiple keys for decryption (backward compat) with the first key used for new encryptions
- Store a `key_version` column in the vault table
- Even if key rotation isn't implemented in the first version, design the schema to support it (`encrypted_data`, `key_version`, `created_at`)

**Phase:** Credential vault implementation

---

## Minor Pitfalls

---

### Pitfall m1: SQLite Vault Not Appropriate for Multi-Instance Deployments

**What goes wrong:**  
SQLite works for single-container deployments but becomes a write-bottleneck and then a correctness problem if anyone runs multiple proxy instances behind a load balancer.

**Prevention:**  
- Document the single-instance constraint explicitly in README
- Design the vault schema and access layer behind an interface so it could be swapped to PostgreSQL later without rewriting calling code
- Do not use SQLite WAL mode as a substitute for proper multi-instance coordination

---

### Pitfall m2: GOOGLE_JWT_KEY Not Required on Non-Localhost — Tokens Invalidate on Restart

**What goes wrong:**  
Already flagged in CONCERNS.md: if `GOOGLE_JWT_KEY` is not set, FastMCP uses a default or ephemeral key. Every restart invalidates all user sessions. Users must re-authenticate after every deploy.

**Prevention:**  
Add a startup check: if `MCP_BASE_URL` is not `localhost`, fail fast with a clear error if `GOOGLE_JWT_KEY` is not set. This is a one-line fix that prevents confusing user-facing behavior.

**Phase:** Hardening / initial phase

---

### Pitfall m3: Health Endpoint Reveals Admin URLs When Enhanced

**What goes wrong:**  
When the health endpoint is enhanced (as planned) to show upstream server status, it may also inadvertently expose internal URLs, admin route paths, or configured MCP server endpoints to unauthenticated callers.

**Prevention:**  
- Keep `/health` response minimal for unauthenticated access: `{"status": "healthy", "version": "..."}` only
- Return detailed upstream status only on `/health/detail` gated behind authentication
- Never include admin URLs or internal server names in the public health response

---

### Pitfall m4: Argon2 / bcrypt for Credential Encryption — Wrong Tool

**What goes wrong:**  
Developer reaches for `bcrypt` or `argon2` for vault encryption because they're familiar as "secure" crypto. These are password-hashing algorithms — they're one-way and cannot be used for encryption (you cannot recover the original API key).

**Prevention:**  
- **Encryption** (recoverable): use `cryptography.fernet.Fernet` with a master key
- **Password hashing** (irreversible): use `argon2-cffi` or `bcrypt`
- The vault stores API keys that must be retrieved → Fernet only

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|----------------|------------|
| Code structure refactor | Refactoring breaks signal handling or reload logic | Add integration tests for signal/reload behavior *before* refactoring |
| User allowlist | Allowlist only checked at login, not request time | Per-request middleware check with cached allowlist (30s TTL) |
| Per-user tool access | List filtered, call not filtered | Always implement both `on_list_tools` AND `on_call_tool` in the same middleware |
| Credential vault (design) | Master key co-located with ciphertext | Key in Docker secret / separate env; ciphertext only in DB volume |
| Credential vault (injection) | Decrypted credentials leak into logs | Inject via env/headers; never via logged tool arguments |
| Credential vault (schema) | No key versioning → rotation impossible | Add `key_version` column from day one; use MultiFernet |
| Usage logging | Full tool arguments logged (PII/secrets) | Metadata-only log by default; explicit opt-in + redaction for args |
| Admin dashboard (routes) | Any authed user can access admin | Explicit role/email check; consider separate port |
| Admin dashboard (mutating) | CSRF on state-changing endpoints | Bearer token auth (CSRF-safe) or SameSite=Strict + CSRF tokens |
| Multi-OIDC | DCR ambiguity with multiple auth servers | One DCR provider (`server=`), others as JWT `verifiers=` only |
| Multi-OIDC | Open redirect via unvalidated state/redirect_uri | Register exact redirect URIs; validate state round-trip |
| Live reload + vault | Reload race corrupts vault write | Fix reload mechanism before vault; use SQLite transactions |
| Test suite | Integration tests require full server → slow | Extract modules first; unit-test auth/vault/filter in isolation |

---

## Sources

- FastMCP authorization docs (Context7 `/prefecthq/fastmcp`, topic: auth middleware OAuth): HIGH confidence
- FastMCP multi-auth / multi-OIDC docs (Context7, topic: OIDCProxy OAuthProxy MultiAuth): HIGH confidence  
- `cryptography` library Fernet docs (Context7 `/websites/cryptography_io_en`): HIGH confidence
- Codebase CONCERNS.md (`/Users/jon/Documents/_GIT/__claude_code/mcp-proxy/.planning/codebase/CONCERNS.md`): HIGH confidence (first-party audit)
- Project requirements (PROJECT.md): HIGH confidence
- API gateway / credential vault security patterns: MEDIUM confidence (established industry practice, verified against FastMCP's actual auth model)
