"""JWT (JWKS) + DPoP validation for the MCP endpoint.

Implements the resource-server side of the MCP authorization spec against
Issuerd-issued tokens: every POST to /mcp must carry a DPoP-bound access
token (Authorization: DPoP <jwt>) plus a fresh single-use DPoP proof
(RFC 9449) whose key thumbprint matches the token's cnf.jkt. Plain Bearer
is not accepted at all, and a valid proof never rescues an unbound token
(no cnf.jkt) — sender-constraining is enforced here, at the resource
server, instead of depending on how tokens happen to be issued. Failure
responses follow RFC 9449 section 7.1 / RFC 6750 — the exact
WWW-Authenticate headers are part of the recorded demo.
"""

import hashlib
import json
import os
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field

import jwt
from jwt.exceptions import PyJWTError

from app.jwks import EXPECTED_ISSUER, get_signing_key

AUDIENCE = os.environ.get("AUDIENCE", "mcp-server")
MCP_PATH = os.environ.get("MCP_PATH", "/mcp")

# Per-request validated identity, consumed by the tool implementations.
current_auth: ContextVar["RequestAuth | None"] = ContextVar("mcp_auth", default=None)

# RFC 9449 section 4.2: acceptable proof signature algorithms (asymmetric only).
DPOP_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA")
_DPOP_ALG_KTY = {"RS": "RSA", "ES": "EC", "EdDSA": "OKP"}
_DPOP_ALG_CRV = {"ES256": "P-256", "ES384": "P-384"}
# Members that would turn the embedded proof key into a private key.
_JWK_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

# DPoP iat acceptance window: [now - 300s, now + 60s].
_DPOP_MAX_AGE_S = 300
_DPOP_MAX_SKEW_S = 60
# jti replay cache retention: must outlive the iat window.
_JTI_TTL_S = _DPOP_MAX_AGE_S + _DPOP_MAX_SKEW_S + 60

# Tool name -> required scope, enforced on JSON-RPC tools/call.
TOOL_SCOPES = {
    "get_orders": "orders:read",
    "refund_order": "refunds:execute",
}


@dataclass
class RequestAuth:
    """Validated caller identity plus the demo security-trace lines.

    ``jkt`` is the DPoP key thumbprint the caller proved possession of —
    always present: unbound tokens never get past the middleware.
    """

    sub: str
    scopes: set[str]
    jkt: str
    trace: list[str] = field(default_factory=list)


class AuthFailure(Exception):
    """Carries the RFC 6750/9449 error code, HTTP status and description."""

    def __init__(self, status: int, error: str, description: str, scope: str | None = None):
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.scope = scope

    def challenge(self) -> str:
        parts = [f'DPoP realm="{AUDIENCE}"', f'error="{self.error}"']
        if self.scope:
            parts.append(f'scope="{self.scope}"')
        parts.append(f'error_description="{self.description}"')
        return ", ".join(parts)


def _invalid_token(reason: str) -> AuthFailure:
    return AuthFailure(401, "invalid_token", reason)


def _invalid_proof(reason: str) -> AuthFailure:
    return AuthFailure(401, "invalid_dpop_proof", reason)


def _b64url_no_pad(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_thumbprint(jwk_dict: dict) -> str:
    """RFC 7638 thumbprint: sha256 over the canonical JSON of required members."""

    kty = jwk_dict.get("kty")
    if kty == "RSA":
        members = {"e": jwk_dict["e"], "kty": "RSA", "n": jwk_dict["n"]}
    elif kty == "EC":
        members = {
            "crv": jwk_dict["crv"],
            "kty": "EC",
            "x": jwk_dict["x"],
            "y": jwk_dict["y"],
        }
    elif kty == "OKP":
        members = {"crv": jwk_dict["crv"], "kty": "OKP", "x": jwk_dict["x"]}
    else:
        raise _invalid_proof(f"unsupported jwk kty {kty!r} in DPoP proof")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _b64url_no_pad(hashlib.sha256(canonical).digest())


class _JtiCache:
    """Single-use jti registry (in-memory; the demo runs one replica)."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def check_and_store(self, jti: str) -> bool:
        now = time.time()
        # Lazy expiry sweep.
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            del self._seen[k]
        if jti in self._seen:
            return False
        self._seen[jti] = now + _JTI_TTL_S
        return True


_jti_cache = _JtiCache()


async def _validate_access_token(token: str, trace: list[str]) -> dict:
    """Verify the JWT via the realm JWKS; return claims on success."""

    try:
        jwk = await get_signing_key(token)
    except Exception:
        raise _invalid_token("token signing key not found in JWKS")
    alg = jwk.algorithm_name
    if not alg or not (alg.startswith(("RS", "ES")) or alg == "EdDSA"):
        raise _invalid_token(f"unsupported token alg {alg!r} in JWKS")
    try:
        claims = jwt.decode(
            token,
            key=jwk.key,
            algorithms=[alg],
            audience=AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise _invalid_token("token expired")
    except jwt.InvalidAudienceError:
        raise _invalid_token(f"audience mismatch, expected {AUDIENCE!r}")
    except jwt.InvalidIssuerError:
        raise _invalid_token(f"issuer mismatch, expected {EXPECTED_ISSUER!r}")
    except jwt.ImmatureSignatureError:
        raise _invalid_token("token not yet valid (nbf)")
    except PyJWTError as exc:
        raise _invalid_token(f"token validation failed: {exc}")

    kid = jwt.get_unverified_header(token).get("kid", "?")
    trace.append(f"JWT signature verified via JWKS (kid {kid}, alg {alg})")
    trace.append(f"iss = {claims['iss']} ✓")
    trace.append(f"aud = {AUDIENCE} ✓")
    return claims


def _validate_dpop_proof(
    proof: str, method: str, htu: str, access_token: str, token_cnf_jkt: str
) -> tuple[str, list[str]]:
    """Validate an RFC 9449 proof; return (jkt, trace lines)."""

    try:
        header = jwt.get_unverified_header(proof)
    except PyJWTError:
        raise _invalid_proof("malformed DPoP proof JWT")

    if header.get("typ") != "dpop+jwt":
        raise _invalid_proof('proof typ must be "dpop+jwt"')
    alg = header.get("alg", "")
    if alg not in DPOP_ALGS:
        raise _invalid_proof(f"proof alg {alg!r} not allowed")
    jwk_dict = header.get("jwk")
    if not isinstance(jwk_dict, dict):
        raise _invalid_proof("proof header must embed a public jwk")
    if _JWK_PRIVATE_MEMBERS & jwk_dict.keys():
        raise _invalid_proof("proof jwk must not contain private key material")
    kty = jwk_dict.get("kty", "")
    expected_kty = "OKP" if alg == "EdDSA" else _DPOP_ALG_KTY[alg[:2]]
    if kty != expected_kty:
        raise _invalid_proof(f"proof alg {alg} does not match jwk kty {kty!r}")
    if alg in _DPOP_ALG_CRV and jwk_dict.get("crv") != _DPOP_ALG_CRV[alg]:
        raise _invalid_proof(f"proof alg {alg} requires curve {_DPOP_ALG_CRV[alg]}")

    try:
        key = jwt.PyJWK.from_dict(jwk_dict).key
        claims = jwt.decode(
            proof,
            key=key,
            algorithms=[alg],
            options={"verify_aud": False, "verify_iss": False, "verify_exp": False},
        )
    except PyJWTError as exc:
        raise _invalid_proof(f"proof signature verification failed: {exc}")

    if claims.get("htm", "").upper() != method.upper():
        raise _invalid_proof(f"htm mismatch: proof {claims.get('htm')!r} != request {method}")
    if claims.get("htu") != htu:
        raise _invalid_proof(f"htu mismatch: proof {claims.get('htu')!r} != request {htu!r}")

    now = time.time()
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        raise _invalid_proof("proof missing numeric iat")
    if iat < now - _DPOP_MAX_AGE_S or iat > now + _DPOP_MAX_SKEW_S:
        raise _invalid_proof("proof iat outside acceptance window")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise _invalid_proof("proof missing jti")
    if not _jti_cache.check_and_store(jti):
        raise _invalid_proof("proof jti already used (replay)")

    ath = claims.get("ath")
    expected_ath = _b64url_no_pad(hashlib.sha256(access_token.encode("ascii")).digest())
    if ath != expected_ath:
        raise _invalid_proof("ath does not match the presented access token")

    jkt = _jwk_thumbprint(jwk_dict)
    if jkt != token_cnf_jkt:
        raise _invalid_proof("proof key thumbprint does not match token cnf.jkt")

    lines = [
        "DPoP proof: typ/htm/htu/iat/jti fresh ✓, ath matches access token ✓",
        "proof jkt == token cnf.jkt — sender-constrained ✓",
    ]
    return jkt, lines


def _request_htu(scope: dict, headers: dict[bytes, bytes]) -> str:
    """Exact request URL (scheme://host[:port]/path, no query) as seen here."""

    proto = headers.get(b"x-forwarded-proto")
    scheme = proto.decode("latin-1").split(",")[0].strip() if proto else scope["scheme"]
    host = headers.get(b"host", b"").decode("latin-1")
    return f"{scheme}://{host}{scope['path']}"


def _tool_names_from_body(body: bytes) -> list[str]:
    """Tool names requested by JSON-RPC tools/call messages in the body."""

    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return []
    messages = payload if isinstance(payload, list) else [payload]
    names = []
    for msg in messages:
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if isinstance(name, str):
                names.append(name)
    return names


async def _read_body(receive) -> bytes:
    body = b""
    more = True
    while more:
        message = await receive()
        if message["type"] != "http.request":
            continue
        body += message.get("body", b"")
        more = message.get("more_body", False)
    return body


def _replay_receive(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def _send_error(send, failure: AuthFailure):
    payload = {"error": failure.error, "error_description": failure.description}
    if failure.scope:
        payload["scope"] = failure.scope
    data = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": failure.status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", failure.challenge().encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": data})


class DPoPAuthMiddleware:
    """ASGI middleware enforcing JWT + DPoP on every request to MCP_PATH."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != MCP_PATH:
            await self.app(scope, receive, send)
            return

        try:
            auth, body = await self._authenticate(scope, receive)
        except AuthFailure as failure:
            await _send_error(send, failure)
            return

        token = current_auth.set(auth)
        try:
            await self.app(scope, _replay_receive(body), send)
        finally:
            current_auth.reset(token)

    async def _authenticate(self, scope, receive) -> tuple[RequestAuth, bytes]:
        headers = {k.lower(): v for k, v in scope["headers"]}
        method = scope["method"]

        authz = headers.get(b"authorization", b"").decode("latin-1")
        if not authz:
            raise _invalid_token("missing Authorization header")
        scheme, _, token = authz.partition(" ")
        if scheme.lower() not in ("dpop", "bearer") or not token:
            raise _invalid_token("Authorization scheme must be DPoP")

        token_trace: list[str] = []
        claims = await _validate_access_token(token, token_trace)
        scopes = set(claims.get("scope", "").split())
        cnf_jkt = (claims.get("cnf") or {}).get("jkt")

        # DPoP-only policy: no Bearer fallback. A bound token as Bearer is
        # rejected per RFC 9449 section 6.1; an unbound token is rejected
        # regardless of scheme because sender-constraining is mandatory here.
        if scheme.lower() == "bearer":
            if cnf_jkt is not None:
                raise _invalid_token(
                    "token is DPoP-bound (cnf.jkt present) but presented as Bearer; "
                    "DPoP scheme with a proof is required"
                )
            raise _invalid_token(
                "Bearer tokens are not accepted; a DPoP-bound access token "
                "and a DPoP proof are required"
            )
        if cnf_jkt is None:
            raise _invalid_token(
                "access token is not DPoP-bound (no cnf.jkt); "
                "sender-constrained tokens are required"
            )

        proof = headers.get(b"dpop", b"").decode("latin-1")
        if not proof:
            raise _invalid_proof("missing DPoP proof header")
        jkt, dpop_trace = _validate_dpop_proof(
            proof, method, _request_htu(scope, headers), token, cnf_jkt
        )

        # Scope enforcement needs the tool name: peek at the JSON-RPC body.
        body = await _read_body(receive)
        scope_trace: list[str] = []
        for tool in _tool_names_from_body(body):
            required = TOOL_SCOPES.get(tool)
            if required is None:
                continue  # unknown tools are rejected downstream by the MCP layer
            if required not in scopes:
                raise AuthFailure(
                    403,
                    "insufficient_scope",
                    f"tool {tool!r} requires scope {required!r}",
                    scope=required,
                )
            scope_trace.append(f"scope contains {required} ✓")

        sub = claims["sub"]
        auth = RequestAuth(
            sub=sub,
            scopes=scopes,
            jkt=jkt,
            trace=token_trace + scope_trace + dpop_trace,
        )
        return auth, body


def validate_sub_uuid(sub: str) -> str:
    """Guard for the RLS context value; raises ValueError on malformed subs."""

    return str(uuid.UUID(sub))
