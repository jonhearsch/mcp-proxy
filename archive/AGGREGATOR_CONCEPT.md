# MCP Aggregator Concept

## Problem with Current Proxy Approach

**Current (proxy_server.py):**
```
User Request (tools/list)
  ↓
Proxy connects to ALL servers sequentially:
  ├─ data.hearsch.xyz (HTTPS)      ~2s
  ├─ geotab-workspace (HTTP)       ~0.4s
  ├─ mcp.context7.com (HTTPS)      ~1.5s
  └─ nocodb.hearsch.xyz (HTTPS)    ~2s
  ↓
Total: ~8-10 seconds PER REQUEST
```

## Solution: Aggregator Approach

**Proposed (aggregator_server.py):**
```
Startup (once):
  Connect to all servers IN PARALLEL
  ├─ data.hearsch.xyz
  ├─ geotab-workspace
  ├─ mcp.context7.com
  └─ nocodb.hearsch.xyz
  ↓
  Fetch all tools/resources
  ↓
  Cache locally
  ↓
  Keep connections alive

User Request (tools/list):
  ↓
  Return cached list
  ↓
Total: <100ms

User Request (tools/call):
  ↓
  Route to appropriate upstream
  ↓
Total: ~200-500ms (single server)
```

## Implementation Strategy

### Option 1: Pure Python Aggregator (Recommended)

Build a custom aggregator that:

1. **Startup Phase:**
   - Load mcp_config.json
   - Connect to all upstreams in parallel (asyncio.gather)
   - Fetch tools/resources from each
   - Build local tool registry
   - Keep upstream clients alive

2. **Request Phase:**
   - tools/list → Serve from cache (instant)
   - tools/call → Route to appropriate upstream
   - resources/* → Serve from cache or route

**Advantages:**
- 100x faster for metadata requests
- Parallel startup (2-3s vs 8-10s)
- Still get benefits of aggregation
- Can add caching, rate limiting, etc.

**Disadvantages:**
- More complex to implement
- Need to handle upstream failures
- Schema mapping complexity

### Option 2: FastMCP with Dynamic Tool Registration

Use FastMCP's `add_tool()` method to register wrapper tools that proxy to upstreams:

```python
mcp = FastMCP(name="aggregator")

# At startup, for each upstream server:
async with Client(upstream_url) as client:
    tools = await client.list_tools()

    for tool_def in tools.tools:
        # Create wrapper function
        async def tool_wrapper(**kwargs):
            return await client.call_tool(tool_def.name, kwargs)

        # Register locally
        mcp.tool(name=tool_def.name, description=tool_def.description)(tool_wrapper)
```

**Challenges:**
- Need to keep Client instances alive (can't use context manager)
- Schema conversion from MCP format to FastMCP format
- Managing upstream connection lifecycle

### Option 3: Hybrid Approach

Combine both:
- Use FastMCP for the server framework
- Custom connection pooling for upstreams
- Cache tool metadata, proxy tool calls

## Recommended Next Steps

1. **Quick win:** Create separate config files per use case
   - `mcp_config_dev.json` - just geotab-workspace
   - `mcp_config_prod.json` - all servers

2. **Short term:** Build a simple aggregator (Option 1)
   - Faster for your Postman testing
   - Better performance for Claude/Letta

3. **Long term:** File issue with FastMCP
   - Request parallel upstream connections
   - Request session pooling/reuse
   - These are library-level fixes that would benefit everyone

## Performance Comparison

| Scenario | Proxy Mode | Aggregator Mode |
|----------|------------|-----------------|
| Startup | Instant | 2-3s (one-time) |
| tools/list | 8-10s | <100ms (cached) |
| tools/call | 8-10s + tool time | 200-500ms + tool time |
| 10 metadata requests | 80-100s | 1s |

## Implementation Complexity

| Aspect | Proxy (Current) | Aggregator (Proposed) |
|--------|----------------|---------------------|
| Code complexity | Low (uses FastMCP.as_proxy) | Medium (custom logic) |
| Upstream management | Automatic | Manual (connection pool) |
| Error handling | Automatic | Manual (per-upstream) |
| Maintenance | Low | Medium |
| **Performance** | **Poor** | **Excellent** |

## Decision

Given your use case (Postman testing, development), I recommend:

**Immediate:** Use a minimal config with just geotab-workspace
**Next week:** Build the aggregator for production use
**This month:** File FastMCP issue for library improvements
