# Testing Your MCP Proxy Locally

## Prerequisites

1. Make sure your MCP proxy is running:

   ```bash
   docker-compose up
   ```

2. Set your bearer token:
   ```bash
   export MCP_BEARER_TOKEN='your-token-here'
   ```

## Option 1: Quick Test with cURL

### Test Health Endpoint (No Auth Required)

```bash
curl http://localhost:8543/e9415487-f3b9-4186-ade3-da8586ddf96b/health
```

Expected output:

```json
{
  "status": "healthy",
  "version": "1.0.7+...",
  "servers": ["thinking", "time", "web-search", "memory"],
  "path_prefix": "/e9415487-f3b9-4186-ade3-da8586ddf96b"
}
```

### Test with Authentication

```bash
export TOKEN="your-bearer-token"

# Test thinking server
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' \
  http://localhost:8543/e9415487-f3b9-4186-ade3-da8586ddf96b/mcp/thinking/message
```

## Option 2: Python Test Script

### Install Dependencies

```bash
pip install httpx
```

### Run Test Suite

```bash
export MCP_BEARER_TOKEN='your-token-here'
python test_mcp_client.py
```

### Expected Output

```
🔍 MCP Proxy Test Suite
============================================================
🔑 Using token: ********...e123

🏥 Testing Health Endpoint
   URL: http://localhost:8543/e9415487-f3b9-4186-ade3-da8586ddf96b/health
   ✓ Status: healthy
   ✓ Version: 1.0.7+b98ea3e
   ✓ Servers: thinking, time, web-search, memory
   ✓ Path Prefix: /e9415487-f3b9-4186-ade3-da8586ddf96b

📡 Testing server: thinking
   URL: http://localhost:8543/e9415487-f3b9-4186-ade3-da8586ddf96b/mcp/thinking/sse
   ✓ Connected successfully
   ✓ Server: Sequential Thinking Server
   ✓ Version: 1.0.0

...

============================================================
📊 Test Summary:
   ✓ Passed: 4/4
   ❌ Failed: 0/4

✅ All tests passed!
```

## Option 3: Browser Test

Open your browser and navigate to:

```
http://localhost:8543/e9415487-f3b9-4186-ade3-da8586ddf96b/health
```

You should see the health check JSON response.

## Troubleshooting

### "Connection refused"

- Check if the container is running: `docker-compose ps`
- Check logs: `docker-compose logs -f mcp-proxy`

### "Authentication failed" (401)

- Verify your bearer token is correct
- Make sure `MCP_BEARER_TOKEN` is set in docker-compose.yml
- Check the container logs for authentication errors

### "Endpoint not found" (404)

- Verify your path prefix matches what's configured
- Check the health endpoint first to confirm the server is running
- Ensure you're using the correct server name (thinking, time, web-search, memory)

### "Server may be starting up"

- Wait a few seconds for MCP servers to initialize
- Check container logs: `docker-compose logs -f`
- Some servers (especially npm/npx based ones) take time to start

## Advanced Testing

### Test Environment Variable Expansion

```bash
# Check if your API keys are properly expanded
docker-compose exec mcp-proxy env | grep FIRECRAWL
```

### Test Live Reload

```bash
# Enable live reload
export MCP_LIVE_RELOAD=true

# Edit mcp_config.json and watch the logs
docker-compose logs -f mcp-proxy
```

### Test Different Ports

```bash
export MCP_PORT=9090
docker-compose up
curl http://localhost:9090/e9415487-f3b9-4186-ade3-da8586ddf96b/health
```
