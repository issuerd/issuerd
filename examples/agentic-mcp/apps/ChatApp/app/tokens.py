"""OAuth plumbing beyond login: RFC 8693 token exchange, the CIBA client,
and the two tool-execution paths (orders / refund) that power the agent.

Every token-endpoint request carries a DPoP proof whose ``htu`` is the PUBLIC
issuer spelling — Issuerd compares ``htu`` against the public URL even when
the request itself goes to the internal docker address.
"""
from __future__ import annotations

import json
import time

import httpx
import jwt

from . import mcp_client
from .config import Settings
from .dpop import DPoPKey
from .oidc import fresh_login_token
from .trace import add_trace, merge_server_trace

EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
MCP_AUDIENCE = "mcp-server"
CIBA_SCOPE = "openid refunds:execute"
CIBA_REQUESTED_EXPIRY = 120
CIBA_POLL_INTERVAL = 5  # server enforces slow_down below this
REFUND_STEPUP_LIMIT = 100.0  # refunds above this always need human approval


class TokenExchangeError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"token exchange failed: HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


class CibaError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"CIBA request failed: HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


def decode_payload(token: str) -> dict:
    """Display-only decode of a JWT payload (signatures are verified server-side)."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


def _token_view(claims: dict) -> str:
    """The claims worth showing in the trace panel."""
    keys = ("iss", "aud", "azp", "scope", "exp", "iat", "jti", "cnf")
    return json.dumps({k: claims[k] for k in keys if k in claims}, indent=2)


async def token_exchange(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    *,
    subject_token: str,
    scope: str,
) -> dict:
    """RFC 8693: narrow ``subject_token`` to aud=mcp-server and ``scope``.

    If the subject token is DPoP-bound (cnf.jkt), the proof must come from the
    same key — and the exchanged token inherits the binding to this app's key.
    """
    resp = await http.post(
        settings.token_url_internal,
        data={
            "grant_type": EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "audience": MCP_AUDIENCE,
            "scope": scope,
        },
        auth=(settings.client_id, settings.client_secret),
        headers={"DPoP": dpop_key.proof(htu=settings.token_url_public)},
    )
    if resp.status_code != 200:
        raise TokenExchangeError(resp.status_code, resp.text)
    return resp.json()


async def ciba_authorize(
    settings: Settings,
    http: httpx.AsyncClient,
    *,
    login_hint: str,
    binding_message: str,
) -> dict:
    """CIBA bc-authorize. Issuerd authenticates this endpoint via the body
    only (client_id + client_secret) — Basic auth is not supported here."""
    resp = await http.post(
        settings.ciba_auth_url_internal,
        data={
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "login_hint": login_hint,
            "binding_message": binding_message[:100],
            "scope": CIBA_SCOPE,
            "requested_expiry": str(CIBA_REQUESTED_EXPIRY),
        },
    )
    if resp.status_code != 200:
        raise CibaError(resp.status_code, resp.text)
    return resp.json()


async def ciba_poll_once(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    *,
    auth_req_id: str,
) -> tuple[int, dict]:
    """One CIBA poll at the token endpoint. The DPoP proof header makes the
    resulting step-up token sender-constrained (Issuerd threads dpop_jkt)."""
    resp = await http.post(
        settings.token_url_internal,
        data={"grant_type": CIBA_GRANT, "auth_req_id": auth_req_id},
        auth=(settings.client_id, settings.client_secret),
        headers={"DPoP": dpop_key.proof(htu=settings.token_url_public)},
    )
    try:
        return resp.status_code, resp.json()
    except json.JSONDecodeError:
        return resp.status_code, {}


async def start_ciba_stepup(
    settings: Settings,
    http: httpx.AsyncClient,
    session: dict,
    *,
    order_id: int,
    amount: float,
) -> dict:
    binding_message = f"Refund ${amount:g} for order #{order_id}"
    issued = await ciba_authorize(
        settings,
        http,
        login_hint=session["username"],
        binding_message=binding_message,
    )
    pending = {
        "auth_req_id": issued["auth_req_id"],
        "order_id": order_id,
        "amount": amount,
        "binding_message": binding_message,
        "expires_at": time.time() + int(issued.get("expires_in") or CIBA_REQUESTED_EXPIRY),
        "last_poll": 0.0,
    }
    session["pending_ciba"] = pending
    add_trace(
        session,
        "ciba",
        "CIBA authentication request issued (human step-up)",
        json.dumps(
            {
                "auth_req_id": pending["auth_req_id"],
                "login_hint": session["username"],
                "binding_message": binding_message,
                "scope": CIBA_SCOPE,
                "expires_in": issued.get("expires_in"),
                "interval": issued.get("interval"),
            },
            indent=2,
        ),
    )
    return pending


async def poll_pending_ciba(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    session: dict,
    *,
    auth_req_id: str,
) -> tuple[str, dict | None]:
    """One poll, respecting the server-side interval. Returns
    ``(outcome, pending)`` with outcome in
    pending | approved | denied | expired | missing | error."""
    pending = session.get("pending_ciba")
    if not pending or pending["auth_req_id"] != auth_req_id:
        return "missing", pending
    now = time.time()
    if now > pending["expires_at"]:
        session["pending_ciba"] = None
        return "expired", pending
    if now - pending["last_poll"] < CIBA_POLL_INTERVAL:
        return "pending", pending  # do not poke the endpoint — it answers slow_down
    pending["last_poll"] = now
    status, body = await ciba_poll_once(settings, http, dpop_key, auth_req_id=auth_req_id)
    if status == 200:
        session["pending_ciba"] = None
        session["stepup_token"] = body["access_token"]
        add_trace(
            session,
            "ciba",
            "User approval observed — CIBA step-up token issued "
            "(scope refunds:execute, DPoP-bound, 120 s TTL)",
            _token_view(decode_payload(body["access_token"])),
        )
        return "approved", pending
    error = (body or {}).get("error", "")
    if error in ("authorization_pending", "slow_down"):
        return "pending", pending
    session["pending_ciba"] = None
    if error == "access_denied":
        add_trace(session, "ciba", "User denied the approval request", json.dumps(body, indent=2))
        return "denied", pending
    if error == "expired_token":
        add_trace(session, "ciba", "Approval request expired", json.dumps(body, indent=2))
        return "expired", pending
    add_trace(
        session,
        "ciba",
        f"CIBA poll failed: {error or f'HTTP {status}'}",
        json.dumps(body, indent=2),
        ok=False,
    )
    return "error", pending


async def call_get_orders(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    session: dict,
) -> list[dict]:
    """login token → RFC 8693 exchange (orders:read) → MCP get_orders."""
    subject = await fresh_login_token(settings, http, dpop_key, session)
    exchanged = await token_exchange(
        settings, http, dpop_key, subject_token=subject, scope="orders:read"
    )
    token = exchanged["access_token"]
    session["last_exchange_token"] = token
    session["last_exchange_exp"] = decode_payload(token).get("exp", 0)
    add_trace(
        session,
        "exchange",
        "RFC 8693 token exchange — aud narrowed to mcp-server, scope narrowed "
        "to orders:read, bound to this app's DPoP key (cnf.jkt)",
        _token_view(decode_payload(token)),
    )
    data = await mcp_client.call_tool(
        "get_orders", {}, token, client=http, dpop_key=dpop_key, mcp_url=settings.mcp_url
    )
    merge_server_trace(session, data.get("_trace"))
    return data.get("orders", [])


async def call_refund(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    session: dict,
    *,
    stepup_token: str,
    order_id: int,
    amount: float,
) -> dict:
    """CIBA step-up token → RFC 8693 exchange (refunds:execute) → MCP refund_order."""
    exchanged = await token_exchange(
        settings, http, dpop_key, subject_token=stepup_token, scope="refunds:execute"
    )
    token = exchanged["access_token"]
    session["last_exchange_token"] = token
    session["last_exchange_exp"] = decode_payload(token).get("exp", 0)
    add_trace(
        session,
        "exchange",
        "RFC 8693 token exchange — step-up token narrowed to aud=mcp-server, "
        "scope refunds:execute",
        _token_view(decode_payload(token)),
    )
    data = await mcp_client.call_tool(
        "refund_order",
        {"order_id": order_id, "amount": amount},
        token,
        client=http,
        dpop_key=dpop_key,
        mcp_url=settings.mcp_url,
    )
    merge_server_trace(session, data.get("_trace"))
    return data.get("order", {})
