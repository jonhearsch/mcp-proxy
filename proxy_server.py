from fastmcp import FastMCP
import os
import sys

# Create server
mcp = FastMCP("MCP Proxy Hub")

# Load config from environment variable or default path
config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")

try:
    mcp.load_config(config_path)
    print(f"✓ Loaded configuration from {config_path}", file=sys.stderr)
except Exception as e:
    print(f"✗ Failed to load config: {e}", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    mcp.run()
