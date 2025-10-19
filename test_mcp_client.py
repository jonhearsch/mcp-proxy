#!/usr/bin/env python3
"""
Test script for MCP Proxy HTTP endpoints with bearer token authentication.

Usage:
    export MCP_BEARER_TOKEN='your-token-here'
    python test_mcp_client.py
"""

import asyncio
import os
import httpx

async def test_health():
    """Test the health endpoint (no auth required)."""
    base_url = os.getenv("MCP_PROXY_URL", "http://localhost:8543")
    path_prefix = os.getenv("MCP_PATH_PREFIX", "e9415487-f3b9-4186-ade3-da8586ddf96b")
    
    health_url = f"{base_url}/{path_prefix}/health"
    
    print(f"🏥 Testing Health Endpoint")
    print(f"   URL: {health_url}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(health_url)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✓ Status: {data.get('status')}")
                print(f"   ✓ Version: {data.get('version')}")
                print(f"   ✓ Servers: {', '.join(data.get('servers', []))}")
                if data.get('path_prefix'):
                    print(f"   ✓ Path Prefix: {data.get('path_prefix')}")
                return True
            else:
                print(f"   ❌ HTTP {response.status_code}: {response.text}")
                return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

async def test_mcp_server(server_name: str, token: str):
    """Test a single MCP server endpoint."""
    base_url = os.getenv("MCP_PROXY_URL", "http://localhost:8543")
    path_prefix = os.getenv("MCP_PATH_PREFIX", "e9415487-f3b9-4186-ade3-da8586ddf96b")
    
    server_url = f"{base_url}/{path_prefix}/mcp/{server_name}/sse"
    
    print(f"\n📡 Testing server: {server_name}")
    print(f"   URL: {server_url}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Test initialize request
    initialize_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try to initialize
            response = await client.post(
                server_url.replace("/sse", "/message"),
                headers=headers,
                json=initialize_payload
            )
            
            if response.status_code == 401:
                print(f"   ❌ Authentication failed - check your bearer token")
                return False
            elif response.status_code == 404:
                print(f"   ⚠️  Endpoint not found - server may not be running")
                return False
            elif response.status_code == 200:
                print(f"   ✓ Connected successfully")
                result = response.json()
                if "result" in result:
                    server_info = result["result"].get("serverInfo", {})
                    print(f"   ✓ Server: {server_info.get('name', 'Unknown')}")
                    print(f"   ✓ Version: {server_info.get('version', 'Unknown')}")
                return True
            else:
                print(f"   ⚠️  HTTP {response.status_code}: {response.text[:200]}")
                return False
                
    except httpx.TimeoutException:
        print(f"   ⚠️  Connection timeout - server may be starting up")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

async def main():
    """Main test function."""
    print("🔍 MCP Proxy Test Suite")
    print("=" * 60)
    
    # Check for bearer token
    token = os.getenv("MCP_BEARER_TOKEN")
    if not token:
        print("\n❌ Error: MCP_BEARER_TOKEN environment variable not set")
        print("Set it with: export MCP_BEARER_TOKEN='your-token-here'")
        return
    
    print(f"🔑 Using token: {'*' * 8}...{token[-4:]}\n")
    
    # Test health endpoint (no auth required)
    health_ok = await test_health()
    
    if not health_ok:
        print("\n⚠️  Health check failed - is the server running?")
        print("Start with: docker-compose up")
        return
    
    # Test each configured server
    servers = ["thinking", "time", "web-search", "memory"]
    
    results = []
    for server_name in servers:
        result = await test_mcp_server(server_name, token)
        results.append((server_name, result))
        await asyncio.sleep(0.5)  # Small delay between tests
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary:")
    success_count = sum(1 for _, success in results if success)
    print(f"   ✓ Passed: {success_count}/{len(results)}")
    print(f"   ❌ Failed: {len(results) - success_count}/{len(results)}")
    
    if success_count == len(results):
        print("\n✅ All tests passed!")
    else:
        print("\n⚠️  Some tests failed - check the output above")

if __name__ == "__main__":
    asyncio.run(main())

