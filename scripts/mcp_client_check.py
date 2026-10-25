#!/usr/bin/env python3
"""Real MCP client validation for internal/adapter/mcp - the thing the
plan's business review flagged as unverified: the adapter had only ever
been exercised with hand-crafted JSON-RPC (curl/tests), never a real MCP
client. This script uses the OFFICIAL Anthropic `mcp` Python SDK's
Streamable HTTP client - not a simulation of one - to run the real
handshake (initialize -> notifications/initialized -> tools/list ->
tools/call) against a running proxy.

Not a go test on purpose: it depends on the `mcp` PyPI package, a real
dependency this Go module doesn't otherwise have, so it stays a standalone
script run manually (or from CI as a separate step) rather than folded into
`go test ./...`.

Usage:
    pip install mcp
    go run ./cmd/rinwall                 # in another terminal
    go run ./cmd/devtoken --user alex@example.com --role support --ttl 1h
    python scripts/mcp_client_check.py --jwt <token>

--tool/--args point the same real client at any tool in the catalog. Aimed
at an mcp-backed tool (mcp_tool set in the registry) this exercises the
full MCP-to-MCP shape end to end: a real official client speaks MCP to the
proxy, and the proxy speaks MCP onward to the upstream server - both hops
real, neither simulated.

    python scripts/mcp_client_check.py --jwt <token>         --tool mcp_update_customer_tier --args '{"user_id":"42","tier":"gold"}'
"""
import argparse
import asyncio
import json
import sys

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main(base_url: str, jwt: str, tool: str, args: dict) -> int:
    headers = {"Authorization": f"Bearer {jwt}"}
    http_client = httpx2.AsyncClient(headers=headers)

    print(f"connecting to {base_url}/mcp as a real MCP client (official SDK, Streamable HTTP)...")
    async with streamable_http_client(f"{base_url}/mcp", http_client=http_client) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()
            print(f"initialize OK - negotiated protocolVersion={result.protocol_version!r}, "
                  f"serverInfo={result.server_info}")

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print(f"tools/list OK - {len(names)} tools: {names}")
            assert tool in names, f"expected {tool} to be in the real tool catalog"

            print(f"calling {tool}({args})...")
            call = await session.call_tool(tool, args)
            print(f"tools/call OK - isError={call.is_error}, content={call.content}")
            assert not call.is_error, f"expected {tool}({args}) to succeed, not error"

    print("\nPASS - a real official MCP client completed the full handshake and a tool call.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--jwt", required=True, help="a JWT from cmd/devtoken")
    parser.add_argument("--tool", default="get_user", help="which tool to call")
    parser.add_argument("--args", default='{"user_id": "42"}',
                        help="that tool's arguments, as a JSON object")
    parsed = parser.parse_args()
    sys.exit(asyncio.run(main(parsed.base_url, parsed.jwt, parsed.tool, json.loads(parsed.args))))
