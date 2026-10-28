"""ASGI entrypoint: auth middleware wrapped around the MCPServer app.

``mcp.streamable_http_app()`` returns a Starlette app whose route matches
/mcp and whose lifespan runs the MCP session manager; the middleware passes
the lifespan scope straight through and guards only HTTP requests to /mcp.
"""

import os

from app.auth import DPoPAuthMiddleware
from app.server import mcp

app = DPoPAuthMiddleware(
    mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host="0.0.0.0",
    )
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
