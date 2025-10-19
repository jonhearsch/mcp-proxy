# Configuration Security

⚠️ **IMPORTANT**: Never commit sensitive credentials to git!

## Using Environment Variables

The `mcp_config.json` file supports environment variable substitution using the syntax `${VAR_NAME}` or `${VAR_NAME:-default_value}`.

### Setup Instructions

1. **Copy the example environment file:**

   ```bash
   cp .env.example .env.local
   ```

2. **Edit `.env.local` with your actual credentials:**

   ```bash
   # NocoDB Configuration
   NOCODB_MCP_URL=https://your-nocodb-instance.com/mcp/your-workspace-id
   NOCODB_MCP_TOKEN=your-actual-token-here

   # Other configurations...
   ```

3. **Source the environment file before running:**
   ```bash
   source .env.local
   docker-compose up
   ```

### Example mcp_config.json

```json
{
  "mcpServers": {
    "nocodb": {
      "url": "${NOCODB_MCP_URL}",
      "transport": "http",
      "headers": {
        "xc-mcp-token": "${NOCODB_MCP_TOKEN}"
      }
    }
  }
}
```

### Files to Keep Private

- `.env.local` - Your actual credentials (already in .gitignore)
- Any `.env` file with real values
- Any `mcp_config.json` with hardcoded credentials

### Safe to Commit

- `.env.example` - Template with placeholder values
- `mcp_config.json` - When using environment variables
- `mcp_config.example.json` - Example configuration

## If You Accidentally Commit Credentials

1. **Immediately revoke/rotate the exposed credentials**
2. **Force push a corrected commit** (see git commands below)
3. **Consider the credentials permanently compromised**

```bash
# Remove sensitive data and amend the commit
git add mcp_config.json
git commit --amend --no-edit
git push origin main --force
```
