"""OIDC login (Auth Code + PKCE S256), callback, logout, token refresh,
and the server-side session store.

Sessions live in an in-memory dict keyed by a random sid; the browser cookie
carries only the sid, signed with SESSION_SECRET (itsdangerous HMAC).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature

from .config import TEMPLATES_DIR, Settings
from .dpop import DPoPKey
from .trace import add_trace

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

COOKIE_NAME = "chat_session"
LOGIN_SCOPE = "openid profile orders:read"
REFRESH_LEEWAY_SECONDS = 15
PKCE_STATE_TTL_SECONDS = 600


class NeedsLoginError(Exception):
    """The login token could not be renewed — the user must log in again."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_claims(token: str) -> dict:
    """Display-only decode of a JWT payload (the IdP issued it over TLS)."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


def get_session(request: Request) -> dict | None:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return None
    try:
        sid = request.app.state.signer.loads(raw)
    except BadSignature:
        return None
    session = request.app.state.sessions.get(sid)
    if session is None:
        return None
    session["sid"] = sid
    return session


def _set_session_cookie(request: Request, response, sid: str) -> None:
    settings: Settings = request.app.state.settings
    response.set_cookie(
        COOKIE_NAME,
        request.app.state.signer.dumps(sid),
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )


def _new_session(request: Request, tokens: dict) -> tuple[str, dict]:
    sid = secrets.token_urlsafe(24)
    claims = _decode_claims(tokens.get("access_token") or "")
    id_claims = _decode_claims(tokens.get("id_token") or "")
    username = (
        id_claims.get("preferred_username") or claims.get("preferred_username") or "user"
    )
    session = {
        "username": username,
        "sub": claims.get("sub") or id_claims.get("sub") or "",
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "id_token": tokens.get("id_token"),
        "token_exp": time.time() + int(tokens.get("expires_in") or 300),
        "trace": [],
        "trace_rendered": 0,
        "pending_ciba": None,
        "stepup_token": None,
        "last_exchange_token": None,
        "last_exchange_exp": 0,
        "llm_history": [],
    }
    request.app.state.sessions[sid] = session
    bound = str(tokens.get("token_type", "")).lower() == "dpop" and "cnf" in claims
    add_trace(
        session,
        "info",
        f"OIDC login complete — access token issued to {username}"
        + (", DPoP-bound to this app's key (cnf.jkt)" if bound else ""),
        json.dumps(
            {k: claims[k] for k in ("iss", "aud", "azp", "scope", "exp", "cnf") if k in claims},
            indent=2,
        ),
    )
    return sid, session


@router.get("/login")
async def login(request: Request):
    settings: Settings = request.app.state.settings
    # Purge expired PKCE states so the dict does not grow unbounded.
    now = time.time()
    stale = [s for s, v in request.app.state.pkce_states.items() if v["exp"] < now]
    for s in stale:
        request.app.state.pkce_states.pop(s, None)
    verifier = _b64url(secrets.token_bytes(32))
    state = secrets.token_urlsafe(24)
    request.app.state.pkce_states[state] = {
        "verifier": verifier,
        "exp": now + PKCE_STATE_TTL_SECONDS,
    }
    query = urlencode(
        {
            "client_id": settings.client_id,
            "response_type": "code",
            "scope": LOGIN_SCOPE,
            "redirect_uri": settings.redirect_uri,
            "state": state,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
            "code_challenge_method": "S256",
        }
    )
    return RedirectResponse(f"{settings.authorize_url}?{query}", status_code=302)


def _login_error(request: Request, message: str, status_code: int = 502):
    return templates.TemplateResponse(
        request, "error.html", {"message": message}, status_code=status_code
    )


@router.get("/auth/callback")
async def auth_callback(
    request: Request, code: str = "", state: str = "", error: str = ""
):
    settings: Settings = request.app.state.settings
    if error:
        return _login_error(
            request, f"The identity provider returned an error: {error}", status_code=400
        )
    stash = request.app.state.pkce_states.pop(state, None)
    if not code or stash is None or stash["exp"] < time.time():
        return _login_error(
            request,
            "Invalid or expired login state. Please start the sign-in again.",
            status_code=400,
        )
    try:
        tokens = await _redeem_code(
            settings,
            request.app.state.http,
            request.app.state.dpop_key,
            code=code,
            verifier=stash["verifier"],
        )
    except Exception as exc:  # IdP unreachable or rejected — never a stack trace
        return _login_error(
            request, f"Could not finish sign-in at the identity provider: {exc}"
        )
    sid, _session = _new_session(request, tokens)
    response = RedirectResponse("/", status_code=302)
    _set_session_cookie(request, response, sid)
    return response


async def _redeem_code(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    *,
    code: str,
    verifier: str,
) -> dict:
    """Redeem the authorization code. The DPoP proof header makes the issued
    access token sender-constrained (Issuerd threads dpop_jkt on this grant)."""
    resp = await http.post(
        settings.token_url_internal,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.redirect_uri,
            "code_verifier": verifier,
        },
        auth=(settings.client_id, settings.client_secret),
        headers={"DPoP": dpop_key.proof(htu=settings.token_url_public)},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"token endpoint answered HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


@router.get("/logout")
async def logout(request: Request):
    settings: Settings = request.app.state.settings
    session = get_session(request)
    id_token = session.get("id_token") if session else None
    if session:
        request.app.state.sessions.pop(session["sid"], None)
    if id_token:
        query = urlencode(
            {
                "id_token_hint": id_token,
                "post_logout_redirect_uri": f"{settings.public_base}/",
            }
        )
        target = f"{settings.logout_url}?{query}"
    else:
        target = "/"
    response = RedirectResponse(target, status_code=302)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


async def fresh_login_token(
    settings: Settings,
    http: httpx.AsyncClient,
    dpop_key: DPoPKey,
    session: dict,
) -> str:
    """The session's access token, refreshed via the refresh_token grant when
    it expires within REFRESH_LEEWAY_SECONDS. Raises NeedsLoginError otherwise."""
    if time.time() < session["token_exp"] - REFRESH_LEEWAY_SECONDS:
        return session["access_token"]
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise NeedsLoginError()
    resp = await http.post(
        settings.token_url_internal,
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        auth=(settings.client_id, settings.client_secret),
        headers={"DPoP": dpop_key.proof(htu=settings.token_url_public)},
    )
    if resp.status_code != 200:
        raise NeedsLoginError()
    tokens = resp.json()
    session["access_token"] = tokens.get("access_token")
    if tokens.get("refresh_token"):
        session["refresh_token"] = tokens["refresh_token"]
    if tokens.get("id_token"):
        session["id_token"] = tokens["id_token"]
    session["token_exp"] = time.time() + int(tokens.get("expires_in") or 300)
    add_trace(
        session,
        "info",
        "Access token renewed (refresh_token grant, DPoP proof on the request)",
        "",
    )
    return session["access_token"]
