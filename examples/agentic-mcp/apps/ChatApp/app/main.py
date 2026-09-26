"""ChatApp — FastAPI app factory and HTTP routes.

A server-rendered chat page where a logged-in user talks to an AI support
agent. Every MCP tool call carries an RFC 8693-exchanged, scope-narrowed,
DPoP-bound token; refunds additionally require a CIBA human step-up.
Part of the runnable `examples/agentic-mcp` stack — the security trace
panel exists so the demo can show every protocol step for real.
"""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer

from . import agent, oidc, tokens
from .config import STATIC_DIR, TEMPLATES_DIR, Settings
from .dpop import DPoPKey
from .mcp_client import raw_call
from .trace import add_trace, new_entries

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

UNAUTHENTICATED = Response(status_code=401, headers={"HX-Redirect": "/login"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await app.state.http.aclose()


def create_app() -> FastAPI:
    settings = Settings.from_env()
    app = FastAPI(title="Shop Support — Issuerd agentic demo", lifespan=lifespan)
    app.state.settings = settings
    app.state.dpop_key = DPoPKey.load_or_create(settings.dpop_key_path)
    app.state.sessions = {}
    app.state.pkce_states = {}
    app.state.signer = URLSafeSerializer(settings.session_secret, salt="chat-session-v1")
    # Created eagerly (not in the lifespan) so ASGI-level tests work without
    # running lifespan events; closed on shutdown.
    app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(oidc.router)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        session = oidc.get_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=302)
        session["trace_rendered"] = len(session["trace"])
        return templates.TemplateResponse(
            request,
            "chat.html",
            {"settings": settings, "session": session, "entries": session["trace"]},
        )

    @app.post("/chat/message", response_class=HTMLResponse)
    async def chat_message(request: Request, message: str = Form(...)):
        session = oidc.get_session(request)
        if session is None:
            return UNAUTHENTICATED
        message = message.strip()[:500]
        try:
            events = await agent.handle_message(
                settings, request.app.state.http, request.app.state.dpop_key, session, message
            )
        except oidc.NeedsLoginError:
            return UNAUTHENTICATED
        except Exception as exc:  # recorded demo: render, never stack-trace
            add_trace(session, "info", f"Unexpected error handling the message: {exc}", ok=False)
            events = [agent.AgentEvent("text", text=f"Something went wrong: {exc}")]
        return templates.TemplateResponse(
            request,
            "partials/messages.html",
            {
                "settings": settings,
                "message": message,
                "events": events,
                "entries": new_entries(session),
            },
        )

    @app.get("/chat/ciba-status", response_class=HTMLResponse)
    async def ciba_status(request: Request, auth_req_id: str = ""):
        session = oidc.get_session(request)
        if session is None:
            return UNAUTHENTICATED
        outcome, pending = await tokens.poll_pending_ciba(
            settings,
            request.app.state.http,
            request.app.state.dpop_key,
            session,
            auth_req_id=auth_req_id,
        )
        context = {
            "settings": settings,
            "pending": pending,
            "resolved": None if outcome == "pending" else outcome,
            "order": None,
            "order_json": "",
            "error": "",
        }
        if outcome == "approved":
            stepup_token = session.pop("stepup_token", None)
            try:
                order = await tokens.call_refund(
                    settings,
                    request.app.state.http,
                    request.app.state.dpop_key,
                    session,
                    stepup_token=stepup_token,
                    order_id=pending["order_id"],
                    amount=pending["amount"],
                )
                context["order"] = order
                context["order_json"] = json.dumps(order, indent=2)
            except Exception as exc:  # surface on the card — recording safety
                add_trace(
                    session, "mcp", f"refund_order failed after approval: {exc}", ok=False
                )
                context["resolved"] = "error"
                context["error"] = f"approval was granted but the refund failed: {exc}"
        context["entries"] = new_entries(session)
        return templates.TemplateResponse(request, "partials/approval_card.html", context)

    @app.post("/demo/replay-stolen-token", response_class=HTMLResponse)
    async def demo_replay_stolen_token(request: Request):
        return await _attack_html(request, _attack_replay)

    @app.post("/demo/no-scope-call", response_class=HTMLResponse)
    async def demo_no_scope_call(request: Request):
        return await _attack_html(request, _attack_no_scope)

    @app.post("/demo/refund-no-stepup", response_class=HTMLResponse)
    async def demo_refund_no_stepup(request: Request):
        return await _attack_html(request, _attack_refund_no_stepup)

    @app.get("/demo/attack-json")
    async def demo_attack_json(request: Request, kind: str = ""):
        """Same attacks as JSON — the recorder's stylized terminal fetches this
        via page.evaluate(fetch) from the logged-in page to print real answers."""
        session = oidc.get_session(request)
        if session is None:
            return JSONResponse({"error": "not_authenticated"}, status_code=401)
        handlers = {
            "replay": _attack_replay,
            "no-scope": _attack_no_scope,
            "refund-no-stepup": _attack_refund_no_stepup,
        }
        handler = handlers.get(kind)
        if handler is None:
            return JSONResponse(
                {"error": "unknown kind", "kinds": sorted(handlers)}, status_code=400
            )
        try:
            attack = await handler(request)
        except oidc.NeedsLoginError:
            return JSONResponse({"error": "not_authenticated"}, status_code=401)
        _trace_attack(session, attack)
        return JSONResponse(
            {
                "command": attack["command"],
                "status": attack["status"],
                "www_authenticate": attack["www_authenticate"],
                "body": attack["body"],
            }
        )

    return app


async def _attack_html(request: Request, handler):
    session = oidc.get_session(request)
    if session is None:
        return UNAUTHENTICATED
    try:
        attack = await handler(request)
    except oidc.NeedsLoginError:
        return UNAUTHENTICATED
    _trace_attack(session, attack)
    return templates.TemplateResponse(
        request,
        "partials/attack_result.html",
        {"attack": attack, "entries": new_entries(session)},
    )


def _trace_attack(session: dict, attack: dict) -> None:
    add_trace(
        session,
        "attack",
        attack["title"],
        f"$ {attack['command']}\n\nHTTP {attack['status']}\n"
        f"WWW-Authenticate: {attack['www_authenticate']}\n\n{attack['body']}",
    )


def _short(token: str, head: int = 28, tail: int = 14) -> str:
    """Truncated for display — the full token never renders into the page."""
    if len(token) <= head + tail + 1:
        return token
    return f"{token[:head]}…{token[-tail:]}"


def _tools_call_command(settings: Settings, authorization: str, dpop: str | None, params: str) -> str:
    lines = [
        f"curl -i -X POST {settings.mcp_url} \\",
        f'  -H "Authorization: {authorization}" \\',
    ]
    if dpop is not None:
        lines.append(f'  -H "DPoP: {dpop}" \\')
    lines += [
        '  -H "Content-Type: application/json" \\',
        f"  -d '{params}'",
    ]
    return "\n".join(lines)


async def _fresh_exchange_token(request: Request, session: dict) -> str:
    """An exchanged (aud=mcp-server, orders:read) token for the attack scenes.

    Reuses the session's most recent exchanged token when it is still valid;
    otherwise runs a fresh exchange so the scene works even when clicked cold.
    """
    settings: Settings = request.app.state.settings
    token = session.get("last_exchange_token")
    if token and session.get("last_exchange_exp", 0) - time.time() > 30:
        # Reuse only an ordinary orders:read exchange. After a CIBA approval
        # the cached token carries refunds:execute — replaying THAT in the
        # refund-no-stepup scene would succeed and defeat its whole point.
        if "orders:read" in tokens.decode_payload(token).get("scope", "").split():
            return token
    subject = await oidc.fresh_login_token(
        settings, request.app.state.http, request.app.state.dpop_key, session
    )
    exchanged = await tokens.token_exchange(
        settings,
        request.app.state.http,
        request.app.state.dpop_key,
        subject_token=subject,
        scope="orders:read",
    )
    session["last_exchange_token"] = exchanged["access_token"]
    session["last_exchange_exp"] = tokens.decode_payload(exchanged["access_token"]).get("exp", 0)
    return exchanged["access_token"]


async def _attack_replay(request: Request) -> dict:
    settings: Settings = request.app.state.settings
    session = oidc.get_session(request)
    token = await _fresh_exchange_token(request, session)
    command = _tools_call_command(
        settings,
        f"DPoP {_short(token)}",
        None,  # the theft: the attacker has the token but not the private key
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_orders","arguments":{}}}',
    )
    status, headers, body = await raw_call(
        client=request.app.state.http,
        dpop_key=request.app.state.dpop_key,
        mcp_url=settings.mcp_url,
        token=token,
        scheme="DPoP",
        with_dpop=False,
    )
    return {
        "title": "Stolen-token replay rejected — a sender-constrained token is useless without the key",
        "command": command,
        "status": status,
        "www_authenticate": headers.get("www-authenticate", ""),
        "body": body,
        "explanation": "An attacker who steals the exchanged token cannot use it: the token's "
        "cnf.jkt binds it to this app's DPoP key, and the MCP server demands a fresh, "
        "correctly-signed DPoP proof on every request. No key, no data.",
    }


async def _attack_no_scope(request: Request) -> dict:
    settings: Settings = request.app.state.settings
    session = oidc.get_session(request)
    token = await oidc.fresh_login_token(
        settings, request.app.state.http, request.app.state.dpop_key, session
    )
    command = _tools_call_command(
        settings,
        f"Bearer {_short(token)}",
        None,
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_orders","arguments":{}}}',
    )
    status, headers, body = await raw_call(
        client=request.app.state.http,
        dpop_key=request.app.state.dpop_key,
        mcp_url=settings.mcp_url,
        token=token,
        scheme="Bearer",
        with_dpop=False,
    )
    return {
        "title": "Plain login token rejected — the MCP server is a real resource server",
        "command": command,
        "status": status,
        "www_authenticate": headers.get("www-authenticate", ""),
        "body": body,
        "explanation": f"The login token is meant for this app (aud={settings.client_id}), not for the MCP "
        "server — wrong audience, no orders:read scope for mcp-server, and not DPoP-bound. "
        "Only an RFC 8693-exchanged token gets in.",
    }


async def _attack_refund_no_stepup(request: Request) -> dict:
    settings: Settings = request.app.state.settings
    session = oidc.get_session(request)
    token = await _fresh_exchange_token(request, session)
    params = (
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"refund_order","arguments":{"order_id":1,"amount":25}}}'
    )
    command = _tools_call_command(
        settings, f"DPoP {_short(token)}", _short(request.app.state.dpop_key.proof(htu=settings.mcp_url, access_token=token)), params
    )
    status, headers, body = await raw_call(
        client=request.app.state.http,
        dpop_key=request.app.state.dpop_key,
        mcp_url=settings.mcp_url,
        token=token,
        scheme="DPoP",
        with_dpop=True,  # a fully valid DPoP call — the missing piece is the scope
        method="tools/call",
        params={"name": "refund_order", "arguments": {"order_id": 1, "amount": 25}},
    )
    return {
        "title": "Refund without step-up rejected — refunds:execute exists only after a human approves",
        "command": command,
        "status": status,
        "www_authenticate": headers.get("www-authenticate", ""),
        "body": body,
        "explanation": "This call is perfectly authenticated — valid exchanged token, valid DPoP "
        "proof — but the token only carries orders:read. The refunds:execute scope enters the "
        "system only through the CIBA step-up, when a human approves, and dies within 120 seconds.",
    }


app = create_app()
