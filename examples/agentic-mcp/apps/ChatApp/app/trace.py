"""Security trace: the right-hand panel narrating every protocol step.

Entries accumulate on the session; ``new_entries`` returns the ones not yet
rendered so HTMX out-of-band swaps can append them to the panel.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

KINDS = ("exchange", "mcp", "ciba", "sql", "attack", "info")


@dataclass
class TraceEntry:
    kind: str  # one of KINDS
    title: str
    detail: str  # pretty JSON / command+response
    ok: bool = True
    ts: float = field(default_factory=time.time)


def add_trace(session: dict, kind: str, title: str, detail: str = "", ok: bool = True) -> None:
    session["trace"].append(TraceEntry(kind=kind, title=title, detail=detail, ok=ok))


def new_entries(session: dict) -> list[TraceEntry]:
    start = session.get("trace_rendered", 0)
    session["trace_rendered"] = len(session["trace"])
    return session["trace"][start:]


def merge_server_trace(session: dict, server_trace: object) -> None:
    """Merge the MCP server's own validation steps, tolerating shape drift."""
    if not isinstance(server_trace, list):
        return
    for item in server_trace:
        if not isinstance(item, dict):
            # Plain string step (the MCP server's usual shape): the step text
            # IS the title — it is what the panel shows on camera.
            add_trace(session, "mcp", str(item), "")
            continue
        detail = item.get("detail")
        add_trace(
            session,
            item.get("kind") or "mcp",
            item.get("title") or item.get("step") or "mcp-server validation",
            detail if isinstance(detail, str) else json.dumps(detail, indent=2),
            bool(item.get("ok", True)),
        )
