"""One-shot post-provision step for the agentic MCP example.

Runs after Issuerd is healthy (compose `service_healthy` dependency) and does
the two things `provision.yaml` cannot express:

1. Sets the `token.exchange.enabled=true` attribute on the `mcp-server`
   client — client attributes are not provisionable, and without it RFC 8693
   exchanges with audience=mcp-server are rejected (token_exchange.rs
   resolve_target_client). Idempotent.
2. Seeds `shop.orders` with the REAL subs of alice/bob — user subs are random
   UUIDs generated at provision time, so rows cannot ship in
   apps/McpServer/db-init/01-shop.sql. Full reseed (DELETE + INSERT).

Exits non-zero on any failure, which aborts `docker compose up` (chatapp
depends on this service completing successfully).
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import asyncpg
import httpx

IDP = os.environ.get("IDP_BASE_URL", "http://issuerd:8080").rstrip("/")
REALM = os.environ.get("REALM", "demo")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
MCP_CLIENT_ID = os.environ.get("MCP_CLIENT_ID", "mcp-server")
SHOP_ADMIN_DSN = os.environ.get(
    "SHOP_ADMIN_DSN", "postgres://issuerd:issuerd_secret@postgres:5432/shop"
)
SHOP_RLS_DSN = os.environ.get(
    "SHOP_RLS_DSN", "postgres://mcp_user@postgres:5432/shop"
)

# Everything below retries until this deadline: on a fresh volume Issuerd must
# run migrations and provisioning before the admin API answers usefully.
DEADLINE_SECS = 120

ORDERS = [
    (123, "alice", "Wireless mouse", 150.00, "paid"),
    (124, "alice", "USB-C cable", 19.90, "paid"),
    (125, "alice", "Laptop stand", 59.99, "shipped"),
    (223, "bob", "Mechanical keyboard", 89.00, "paid"),
    (224, "bob", "Monitor arm", 120.00, "paid"),
]


def admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{IDP}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def enable_token_exchange(client: httpx.Client, token: str) -> None:
    auth = {"Authorization": f"Bearer {token}"}
    clients = client.get(f"{IDP}/admin/realms/{REALM}/clients", params={"max": 100}, headers=auth)
    clients.raise_for_status()
    match = [c for c in clients.json() if c.get("client_id") == MCP_CLIENT_ID]
    if not match:
        raise RuntimeError(f"client {MCP_CLIENT_ID} not found in realm {REALM}")
    client_uuid = match[0]["id"]
    if match[0].get("attributes", {}).get("token.exchange.enabled") == "true":
        print(f"{MCP_CLIENT_ID}: token.exchange.enabled already true — skipped")
        return
    # PUT semantics replace the representation: fetch the full client, merge
    # the attribute, PUT it back untouched otherwise.
    full = client.get(f"{IDP}/admin/realms/{REALM}/clients/{client_uuid}", headers=auth)
    full.raise_for_status()
    body = full.json()
    body.setdefault("attributes", {})["token.exchange.enabled"] = "true"
    put = client.put(
        f"{IDP}/admin/realms/{REALM}/clients/{client_uuid}", json=body, headers=auth
    )
    put.raise_for_status()
    print(f"{MCP_CLIENT_ID}: token.exchange.enabled=true set")


def user_subs(client: httpx.Client, token: str) -> dict[str, str]:
    auth = {"Authorization": f"Bearer {token}"}
    users = client.get(f"{IDP}/admin/realms/{REALM}/users", params={"max": 100}, headers=auth)
    users.raise_for_status()
    subs = {u["username"]: u["id"] for u in users.json() if u.get("username")}
    missing = {"alice", "bob"} - subs.keys()
    if missing:
        raise RuntimeError(f"users not found in realm {REALM}: {sorted(missing)}")
    return subs


async def seed_orders(subs: dict[str, str]) -> None:
    conn = await asyncpg.connect(SHOP_ADMIN_DSN)
    try:
        async with conn.transaction():
            await conn.execute("DELETE FROM orders")
            await conn.executemany(
                "INSERT INTO orders (id, owner_sub, item, amount, status)"
                " VALUES ($1, $2::uuid, $3, $4, $5)",
                [
                    (order_id, subs[owner], item, amount, status)
                    for order_id, owner, item, amount, status in ORDERS
                ],
            )
    finally:
        await conn.close()
    print(f"shop.orders seeded (alice={subs['alice']} bob={subs['bob']})")


async def rls_self_check(alice_sub: str) -> None:
    """Through the RLS path the MCP server uses: as mcp_user, alice's context
    must see exactly her 3 rows; without the context, zero rows.

    The no-context check must run FIRST on a fresh connection: once a custom
    GUC has been SET LOCAL in a session, PostgreSQL keeps a placeholder whose
    post-transaction value is '' (not NULL), and ''::uuid in the policy
    raises instead of matching zero rows.
    """
    conn = await asyncpg.connect(SHOP_RLS_DSN)
    try:
        bare = await conn.fetchval("SELECT count(*) FROM orders")
        if bare != 0:
            raise RuntimeError(f"RLS self-check failed: no context must see 0 rows, got {bare}")
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.user_sub', $1, true)", alice_sub)
            visible = await conn.fetchval("SELECT count(*) FROM orders")
        if visible != 3:
            raise RuntimeError(f"RLS self-check failed: expected 3 rows, got {visible}")
    finally:
        await conn.close()
    print("RLS self-check OK: alice's context sees 3 rows via mcp_user, no context sees 0")


async def main() -> int:
    deadline = time.monotonic() + DEADLINE_SECS
    attempt = 0
    while True:
        attempt += 1
        try:
            with httpx.Client(timeout=10.0) as client:
                token = admin_token(client)
                enable_token_exchange(client, token)
                subs = user_subs(client, token)
            await seed_orders(subs)
            await rls_self_check(subs["alice"])
            print("Done. The demo is ready: http://localhost:5108 (alice/changeme)")
            return 0
        except Exception as exc:
            if time.monotonic() > deadline:
                print(f"ERROR: setup failed after {attempt} attempts: {exc}", file=sys.stderr)
                return 1
            print(f"setup step not ready/failed ({exc}); retrying…")
            await asyncio.sleep(2)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
