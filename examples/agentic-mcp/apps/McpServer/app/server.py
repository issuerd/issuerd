"""FastMCP server exposing the two demo tools.

Streamable-HTTP transport at /mcp in stateless mode: no server-side MCP
sessions, so every request is independently authenticated by the auth
middleware (the demo client sends a fresh DPoP proof per request, and proof
jtis are single-use). Responses are plain JSON (json_response=True), which
the stateless client accepts via its ``Accept: application/json`` header.

Both tools return CallToolResult directly: FastMCP passes those through
untouched, so error results carry the exact demo message (e.g.
"order 3 not found") instead of an SDK-generated prefix.
"""

import json

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from app.auth import current_auth, validate_sub_uuid
from app.db import rls_connection

mcp = FastMCP(
    "shop-mcp",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/mcp",
    host="0.0.0.0",
    port=8000,
)

ORDERS_SQL = "SELECT id, item, amount, status FROM orders ORDER BY id"
REFUND_SQL = "UPDATE orders SET status='refunded' WHERE id=$1 RETURNING id, item, amount, status"


def _row_to_order(row) -> dict:
    # numeric(10,2) arrives as Decimal; serialized as float in both tools.
    return {
        "id": row["id"],
        "item": row["item"],
        "amount": float(row["amount"]),
        "status": row["status"],
    }


def _ok(payload: dict) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, indent=2))],
        isError=False,
    )


def _error(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        isError=True,
    )


def _caller_sub() -> str:
    """Validated caller sub, or raise ValueError -> SDK-level isError."""

    auth = current_auth.get()
    if auth is None:
        raise ValueError("no authenticated request context")
    try:
        return validate_sub_uuid(auth.sub)
    except ValueError:
        raise ValueError(f"token sub {auth.sub!r} is not a well-formed UUID") from None


@mcp.tool()
async def get_orders() -> CallToolResult:
    """List the caller's orders. Rows are filtered by PostgreSQL RLS:
    only orders whose owner_sub equals the caller's JWT sub are visible."""

    auth = current_auth.get()
    user_sub = _caller_sub()
    async with rls_connection(user_sub) as conn:
        rows = await conn.fetch(ORDERS_SQL)
    trace = list(auth.trace)
    trace.append(
        f"SQL: {ORDERS_SQL}  (app.user_sub={user_sub} → RLS policy orders_owner)"
    )
    return _ok({"orders": [_row_to_order(r) for r in rows], "_trace": trace})


@mcp.tool()
async def refund_order(order_id: int, amount: float) -> CallToolResult:
    """Mark one of the caller's orders as refunded. RLS hides other users'
    rows, so an order that does not exist or is not owned by the caller
    both surface as 'not found'. The amount is recorded in the audit trace."""

    auth = current_auth.get()
    user_sub = _caller_sub()
    async with rls_connection(user_sub) as conn:
        row = await conn.fetchrow(REFUND_SQL, order_id)
    if row is None:
        return _error(f"order {order_id} not found")
    trace = list(auth.trace)
    trace.append(
        f"SQL: {REFUND_SQL}  (app.user_sub={user_sub} → RLS policy orders_owner)"
    )
    trace.append(f"refund amount {amount} recorded in audit trace")
    return _ok({"order": _row_to_order(row), "_trace": trace})
