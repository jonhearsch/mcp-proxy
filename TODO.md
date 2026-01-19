# MCP Proxy TODO List

## User Whitelist Enforcement

**Status**: Not Implemented
**Priority**: Medium
**Tracking**: Future enhancement for Google OAuth implementation

### Current State
- Uses FastMCP's GoogleProvider for authentication
- `/data/users.json` format could be used for whitelist (not yet implemented)
- Access control currently happens at Google OAuth level
- User identity tracked via Google email claims

### Implementation Plan

1. **Load users.json at startup**
   - Create whitelist loading function
   - Store allowed users in proxy server state

2. **Enforce whitelist in auth middleware**
   - After successful Google OAuth verification, check user email against whitelist
   - Extract email from Google token claims
   - Reject tokens for users not in whitelist

3. **Handle Google OAuth JWT claims**
   - Google tokens include `email`, `email_verified`, and `sub` claims
   - Use verified email as primary user identifier
   - Consider supporting domain-based whitelisting (e.g., @company.com)

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
