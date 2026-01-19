# MCP Proxy TODO List

## User Whitelist Enforcement

**Status**: Not Implemented
**Priority**: Medium
**Tracking**: See inline TODO comments in code

### Current State
- `load_users()` function exists but is never called
- `/data/users.json` format is defined and documented
- Access control currently happens only at OAuth provider level (Auth0/Keycloak)

### Implementation Plan

1. **Load users.json at startup**
   - Call `load_users()` in `create_proxy()`
   - Store allowed users in `HybridAuthProvider`

2. **Enforce whitelist in token verification**
   - Location: `HybridAuthProvider.verify_token()` (proxy_server.py:598)
   - After successful token verification, check if user is in whitelist
   - Extract user identifier from token claims (email or client_id)
   - Reject tokens for users not in whitelist

3. **Handle OAuth JWT claims**
   - Auth0 tokens include `sub` (subject), `email`, or custom claims
   - Keycloak tokens may use `preferred_username` or `email`
   - Need to support configurable claim field for user matching

4. **Handle API keys**
   - Decide if API keys should also check whitelist
   - Currently API keys have their own client_id mapping

### Code References

- **Function to call**: `load_users()` - proxy_server.py:158
- **Enforcement point**: `HybridAuthProvider.verify_token()` - proxy_server.py:598
- **Example implementation**: See TODO comments in proxy_server.py:614-621

### Configuration

```bash
# Environment variable (already defined)
export MCP_USERS_PATH=/data/users.json
```

```json
// File format (already documented)
{
  "user@example.com": {
    "name": "User Name",
    "roles": ["admin"],
    "allowed_tools": ["*"]
  }
}
```

### Testing Checklist

- [ ] User in whitelist can authenticate (OAuth)
- [ ] User NOT in whitelist is rejected (OAuth)
- [ ] API keys still work after whitelist is enforced
- [ ] Missing users.json file doesn't crash server
- [ ] Invalid JSON in users.json is handled gracefully
- [ ] Empty users.json blocks all users
- [ ] Whitelist updates require server restart (or implement live reload)

### Related Issues

- Documentation currently claims whitelist is enforced (misleading)
- Need to decide on OAuth claim field for user matching
- Consider implementing live reload of users.json (watch for file changes)
