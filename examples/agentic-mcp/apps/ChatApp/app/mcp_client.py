"""Minimal hand-rolled MCP streamable-HTTP JSON-RPC client.

The MCP server is a FastMCP streamable-HTTP server with ``stateless_http=True``,
so there is no session header to track: every request is self-contained and
carries its own DPoP proof (``jti`` values are single-use server-side, so a
fresh proof is minted per request).
"""
from __future__ import annotations

import json

import httpx

from .dpop import DPoPKey

PROTOCOL_VERSION = "2025-03-26"
CLIENT_INFO = {"name": "chatapp", "version": "1.0"}
ACCEPT = "application/json, text/event-stream"


class McpError(Exception):
    """Transport- or protocol-level failure talking to the MCP server."""


class McpAuthError(McpError):
    """HTTP 401/403 from the resource server — carries the real challenge."""

    def __init__(self, status: int, www_authenticate: str, body: str):
        super().__init__(f"HTTP {status}: {www_authenticate or body[:200]}")
        self.status = status
        self.www_authenticate = www_authenticate
        self.body = body


class McpToolError(McpError):
    """The tool call itself failed (JSON-RPC error or result.isError)."""


def _parse_rpc_response(resp: httpx.Response) -> dict:
    if resp.status_code == 202 or not resp.content:
        return {}  # notification accepted, no body by design
    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        for line in resp.text.splitlines():
            if not line.startswith("data:"):
                continue
            message = json.loads(line.removeprefix("data:").strip())
            if "result" in message or "error" in message:
                return message
        raise McpError("no JSON-RPC response object found in the SSE stream")
    return resp.json()


async def _rpc(
    client: httpx.AsyncClient,
    dpop_key: DPoPKey,
    mcp_url: str,
    payload: dict,
    token: str | None,
) -> dict:
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token is not None:
        headers["Authorization"] = f"DPoP {token}"
        headers["DPoP"] = dpop_key.proof(htu=mcp_url, access_token=token)
    resp = await client.post(mcp_url, json=payload, headers=headers)
    if resp.status_code in (401, 403):
        raise McpAuthError(
            resp.status_code, resp.headers.get("www-authenticate", ""), resp.text
        )
    resp.raise_for_status()
    return _parse_rpc_response(resp)


async def call_tool(
    name: str,
    arguments: dict,
    token: str,
    *,
    client: httpx.AsyncClient,
    dpop_key: DPoPKey,
    mcp_url: str,
) -> dict:
    """initialize → notifications/initialized → tools/call.

    Returns the parsed tool payload (``result.content[0].text`` decoded as
    JSON, e.g. ``{"orders": [...], "_trace": [...]}``).
    """
    await _rpc(
        client,
        dpop_key,
        mcp_url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        },
        token,
    )
    await _rpc(
        client,
        dpop_key,
        mcp_url,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        token,
    )
    message = await _rpc(
        client,
        dpop_key,
        mcp_url,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        token,
    )
    if "error" in message:
        error = message["error"]
        raise McpToolError(error.get("message") if isinstance(error, dict) else str(error))
    result = message.get("result") or {}
    content = result.get("content") or []
    text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
    if result.get("isError"):
        raise McpToolError(text or "tool call failed")
    return json.loads(text) if text else {}


async def raw_call(
    *,
    client: httpx.AsyncClient,
    dpop_key: DPoPKey,
    mcp_url: str,
    token: str | None = None,
    scheme: str = "DPoP",
    with_dpop: bool = False,
    method: str = "tools/call",
    params: dict | None = None,
) -> tuple[int, dict, str]:
    """Attack-simulation primitive: deliberately malformed auth is the point.

    Sends one JSON-RPC request exactly as told (Bearer instead of DPoP, proof
    header omitted, …) and returns ``(status, headers, body)`` verbatim —
    nothing is raised, the real server answer is the demo output.
    """
    headers = {"Content-Type": "application/json", "Accept": ACCEPT}
    if token is not None:
        headers["Authorization"] = f"{scheme} {token}"
    if with_dpop and token is not None:
        headers["DPoP"] = dpop_key.proof(htu=mcp_url, access_token=token)
    if params is None:
        params = {"name": "get_orders", "arguments": {}}
    resp = await client.post(
        mcp_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=headers,
    )
    return resp.status_code, dict(resp.headers), resp.text
