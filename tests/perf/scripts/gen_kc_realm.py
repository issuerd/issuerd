#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
"""Generate keycloak/realm-perf.json — the Keycloak 26.7 realm import that mirrors
tests/perf/provision.perf.yaml (same clients, same password, N bulk users).

Bulk users carry one password credential each; hashing happens inside Keycloak
at import time. Since KC 25 the default hash algorithm is Argon2id (KC 24 used
PBKDF2), which is deliberately memory-hard — the first boot with the default
of 1000 users takes noticeably longer than it did on KC 24.

perf-service additionally enables the CIBA grant (confidential-only in
Keycloak) in poll delivery mode; DPoP needs no client attribute — Keycloak
binds the token whenever a valid proof is presented, and forcing
`dpop.bound.access.tokens` would reject the proof-less client_credentials /
password_grant scenarios sharing this client.

Usage: python scripts/gen_kc_realm.py [num_users]   (default 1000)
"""
import json
import sys
from pathlib import Path

PASSWORD = "Perf-Pass-123!"


def user(name: str) -> dict:
    return {
        "username": name,
        "enabled": True,
        "emailVerified": True,
        "email": f"{name}@example.com",
        "firstName": "Perf",
        "lastName": "User",
        "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
        "realmRoles": ["user"],
    }


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    realm = {
        "realm": "perf",
        "enabled": True,
        "sslRequired": "none",
        "registrationAllowed": False,
        "roles": {"realm": [{"name": "user"}]},
        "clients": [
            {
                "clientId": "perf-service",
                "enabled": True,
                "publicClient": False,
                "secret": "perf-secret-9f8e7d6c5b4a",
                "serviceAccountsEnabled": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": True,
                "protocol": "openid-connect",
                "attributes": {
                    # CIBA grant is confidential-only in Keycloak and must be
                    # switched on per client; delivery mode matches issuerd
                    # (poll). Interval/expires stay at KC defaults (5s/120s),
                    # identical to issuerd's.
                    "oidc.ciba.grant.enabled": "true",
                    "ciba.backchannel.token.delivery.mode": "poll",
                },
                # KC 25+ requires the introspecting client to be in the
                # token's `aud` (KC 24 allowed issuedFor self-introspection).
                # Add perf-service to its own access-token audience.
                "protocolMappers": [
                    {
                        "name": "audience-self",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": "perf-service",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                        },
                    }
                ],
                "defaultClientScopes": ["profile"],
                "optionalClientScopes": ["email"],
            },
            {
                "clientId": "perf-public",
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": True,
                "redirectUris": [
                    "http://app.local/callback",
                    "http://localhost:4000/callback",
                    "http://localhost:8080/cb",
                ],
                "attributes": {"pkce.code.challenge.method": "S256"},
                "protocol": "openid-connect",
                "defaultClientScopes": ["profile"],
                "optionalClientScopes": [],
            },
        ],
        "users": [user("perfuser")] + [user(f"user{i:04d}") for i in range(1, n + 1)],
    }
    out = Path(__file__).resolve().parent.parent / "keycloak" / "realm-perf.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(realm, indent=1), encoding="utf-8")
    print(f"wrote {out} with {n} bulk users")


if __name__ == "__main__":
    main()
