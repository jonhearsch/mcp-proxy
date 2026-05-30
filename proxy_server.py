"""proxy_server.py — DEPRECATED. Use `python -m mcp_proxy` instead."""
import sys
print("WARNING: proxy_server.py is deprecated. Use: python -m mcp_proxy", file=sys.stderr)
from mcp_proxy.server import main
if __name__ == "__main__":
    main()
