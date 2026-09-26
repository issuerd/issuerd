"""JWKS fetch and cache for Issuerd realm signing keys.

The realm's public keys live at JWKS_URL (in the compose rig this is the
internal address of the IdP; the keys are identical to the public spelling).
PyJWKClient keeps an in-memory cache and refetches on unknown ``kid``, which
covers rare key rotations without extra code.
"""

import asyncio
import os

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

ISSUER = os.environ.get("ISSUER", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("REALM", "demo")

# Expected ``iss`` claim: exact string match, per Issuerd token contract.
EXPECTED_ISSUER = f"{ISSUER}/realms/{REALM}"

JWKS_URL = os.environ.get(
    "JWKS_URL", f"{EXPECTED_ISSUER}/protocol/openid-connect/certs"
)

_client: PyJWKClient | None = None


def get_client() -> PyJWKClient:
    global _client
    if _client is None:
        _client = PyJWKClient(JWKS_URL, cache_keys=True, max_cached_keys=8)
    return _client


async def get_signing_key(token: str):
    """Resolve the JWK matching the token's ``kid``.

    Returns a ``jwt.PyJWK`` (``.key`` is the verifier key, ``.algorithm_name``
    the JWK's declared alg). Raises PyJWKClientError on fetch/match failures.
    PyJWKClient is synchronous, so the (cached) lookup runs off the event loop.
    """

    def _lookup():
        return get_client().get_signing_key_from_jwt(token)

    try:
        return await asyncio.to_thread(_lookup)
    except PyJWKClientError:
        raise
    except Exception as exc:  # malformed header, unknown kid after refetch, ...
        raise PyJWKClientError(str(exc)) from exc
