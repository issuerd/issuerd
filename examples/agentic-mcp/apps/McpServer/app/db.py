"""PostgreSQL access with Row-Level Security context.

The app connects as the non-owner role ``mcp_user`` so the ``orders_owner``
policy applies. Every tool runs its statements in a transaction that first
sets the transaction-local ``app.user_sub`` GUC from the caller's JWT ``sub``;
the policy compares it against ``orders.owner_sub``.
"""

import asyncio
import os
from contextlib import asynccontextmanager

import asyncpg

from app.auth import validate_sub_uuid

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgres://mcp_user:mcp_pass@localhost:5432/shop"
)

_pool: asyncpg.Pool | None = None
_pool_lock = asyncio.Lock()


async def get_pool() -> asyncpg.Pool:
    """Lazily create the connection pool (no lifespan plumbing needed)."""

    global _pool
    if _pool is None:
        async with _pool_lock:
            if _pool is None:
                _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
    return _pool


@asynccontextmanager
async def rls_connection(sub: str):
    """Yield a connection inside a transaction with the RLS context set.

    Raises ValueError if ``sub`` is not a well-formed UUID — the policy casts
    the GUC to uuid, and failing early yields a clean tool error instead of a
    database error.
    """

    user_sub = validate_sub_uuid(sub)
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Parameterized: the value never touches the SQL text.
            await conn.execute("SELECT set_config('app.user_sub', $1, true)", user_sub)
            yield conn
