# Task: Wire up Google OAuth so claude.ai can connect

## Context

Goal: expose this proxy's MCP tools (context7 + our `common` xmcp server) to
claude.ai's remote MCP connector, publicly at `https://ai.hearsch.xyz/mcp`.

Topology in the `homelab` repo (separate repo,
`/Users/jon/Desktop/dev_ops/homelab`):

```
claude.ai --OAuth--> agentgateway (ai_agentgateway, :3000) --> mcp-proxy (ai_mcp-proxy, :8080) --> tools
```

## What we tried first, and why it failed

We tried terminating OAuth at **agentgateway** (the layer in front of this
proxy) using its built-in `mcpAuthentication` + `provider: auth0 {}` config,
against an Auth0 tenant. That failed for a structural reason: agentgateway
proxies the upstream IdP's discovery metadata verbatim, including its real
`registration_endpoint`. Auth0 doesn't support Dynamic Client Registration
(DCR) outside enterprise plans, so claude.ai's connector — which
unconditionally attempts DCR whenever a `registration_endpoint` is
advertised — failed with "Couldn't register with hearsch's sign-in service."

We then found `docs/AUTH_PROVIDERS.md` in *this* repo, which explains that
**mcp-proxy v3.0 deliberately removed Auth0 support** in favor of Google
OAuth specifically because FastMCP's `GoogleProvider` handles DCR correctly
(it runs its own `/register` endpoint backed by pre-registered credentials,
so claude.ai's DCR attempt succeeds against the proxy instead of failing
against the upstream IdP). This is the exact problem we hit, already solved,
already documented, already implemented in `mcp_proxy/auth.py`'s
`create_google_auth()`.

**Decision: use Google OAuth, not Auth0.** No new code needed in this repo —
this is a configuration + Google Cloud Console task, following
`docs/AUTH_PROVIDERS.md` exactly. Do not re-add Auth0; that goes against
this project's own v3.0 migration decision and duplicates work FastMCP/Google
already solved for us.

## The actual work (all in `docs/AUTH_PROVIDERS.md`, condensed here)

1. **Google Cloud Console** (see AUTH_PROVIDERS.md "Google Cloud Console
   Setup" for full click-path):
   - Create/select a project, configure the OAuth consent screen (External,
     scopes `openid` + `email`).
   - Create an OAuth Client ID, type "Web application".
   - Authorized JavaScript origins: `https://ai.hearsch.xyz`
   - Authorized redirect URIs: `https://ai.hearsch.xyz/auth/callback`
   - Copy the Client ID (`*.apps.googleusercontent.com`) and Client Secret
     (`GOCSPX-...`).

2. **Env vars** — set these wherever mcp-proxy actually runs (see
   "Where this actually needs to land" below):
   ```
   GOOGLE_CLIENT_ID=<from step 1>
   GOOGLE_CLIENT_SECRET=<from step 1>
   MCP_BASE_URL=https://ai.hearsch.xyz
   GOOGLE_JWT_KEY=<openssl rand -hex 32>   # optional but recommended for prod
   ```
   `create_google_auth()` in `mcp_proxy/auth.py` already reads exactly these
   — no code change required. It returns `None` (auth disabled) unless
   `client_id`, `client_secret`, and `base_url` are ALL set, so a partial
   config fails closed, not open.

3. **agentgateway side** (in the `homelab` repo): once mcp-proxy is doing
   its own OAuth, agentgateway must NOT also try to gate `/mcp` with its own
   `mcpAuthentication` block — that would double-auth and conflict. Remove
   the `mcpAuthentication` policy that's currently in
   `agentgateway/config.yaml` (added for the abandoned Auth0-at-the-edge
   attempt) and leave agentgateway as a plain proxy for `/mcp` — this is
   exactly the "Passthrough" mode agentgateway's own docs describe: "When
   the MCP server already implements OAuth authentication, no additional
   configuration is needed. Agentgateway passes requests through without
   modification." Keep the existing `cors` policy in that same block.

4. **Where this actually needs to land**: confirm whether mcp-proxy in
   production is (a) built from this repo as a custom image
   (`ghcr.io/jonhearsch/mcp-proxy`, referenced in `homelab/mcp-proxy.yml`)
   or (b) run some other way. The env vars above need to reach the actual
   running container — check `homelab/mcp-proxy.yml`'s `environment:`
   block and add them there (pulling real values from wherever this repo's
   `.env` / secrets are kept — do not hardcode secrets into the tracked
   yml). Restart both `ai_mcp-proxy` and `ai_agentgateway` after deploying.

## How to verify it worked

Follow `docs/AUTH_PROVIDERS.md`'s "Testing Your Configuration" section:

1. `curl https://ai.hearsch.xyz/.well-known/oauth-authorization-server` —
   confirm this is mcp-proxy's own metadata (not any upstream IdP's raw
   metadata) and includes a `registration_endpoint` pointing back at
   `https://ai.hearsch.xyz`, not `accounts.google.com`.
2. Add the connector in claude.ai pointing at `https://ai.hearsch.xyz/mcp`
   — should NOT require manually entering a client ID/secret, since DCR
   against mcp-proxy's own endpoint should succeed transparently and then
   redirect to Google's real consent screen for the actual login.
3. Watch `docker logs ai_mcp-proxy` for:
   ```
   ✓ GoogleProvider successfully initialized
   ✓ Google OAuth authentication enabled (Claude.ai compatible)
   ```
   and then the OAuth flow / token validation log lines during the actual
   connect attempt.

## Known pitfalls (from AUTH_PROVIDERS.md's troubleshooting section)

- **redirect_uri_mismatch**: `MCP_BASE_URL` must match the Google Cloud
  Console redirect URI *exactly*, including scheme — `{MCP_BASE_URL}/auth/callback`
  must be in Authorized redirect URIs.
- **HTTPS is required** for OAuth in production (fine here — Cloudflare
  Tunnel already terminates TLS in front of this stack).
- If `GoogleProvider` fails to initialize, check the installed `fastmcp`
  version (`pip install 'fastmcp>=3.4.4'`).
