#!/usr/bin/env python3
"""Standalone evidence run for oidcc-server-rotate-keys.

The module is a manual-step module (`autoStart=false`, TellUserToRotateOpKeys):
it snapshots the OP JWKS at configure time, waits in CONFIGURED, and when
started re-fetches the JWKS requiring a NEW kid (FAILURE) while the OLD kid
remains (WARNING). The pristine run-test-plan.py force-starts it without
rotating, so in-plan it is an expected failure; this script produces the real
evidence by interposing an actual admin-API key rotation between configure
and start.

Runs INSIDE the hermetic network (docker compose exec test-runner). Exits 0
only when the module finishes PASSED.
"""

import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

SUITE = os.environ.get("CONFORMANCE_SERVER", "https://suite.conformance.test:8443")
OP = os.environ.get("ISSUERD_URL", "https://op.conformance.test:8443")
CACERT = os.environ.get("ISSUERD_CACERT", "/pki/ca.crt")


def http(method, url, body=None, bearer=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context(cafile=CACERT)
    with urllib.request.urlopen(req, context=ctx) as resp:
        raw = resp.read()
        return resp.status, json.loads(raw) if raw else {}


def wait_status(module_id, want, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, info = http("GET", f"{SUITE}/api/info/{module_id}")
        if info.get("status") == want:
            return info
        time.sleep(1)
    raise SystemExit(f"module {module_id} never reached {want}")


def main():
    # 1. Create the module standalone (discovery variant).
    config = {"server": {"discoveryUrl": f"{OP}/realms/conformance/.well-known/openid-configuration"}}
    status, created = http(
        "POST",
        f"{SUITE}/api/runner?test=oidcc-server-rotate-keys&variant="
        + urllib.parse.quote(json.dumps({"server_metadata": "discovery"})),
        body=config,
    )
    assert status == 201, created
    module_id = created["id"]
    print(f"created oidcc-server-rotate-keys module {module_id}")

    # 2. Wait for CONFIGURED: the module has now snapshotted the original JWKS.
    wait_status(module_id, "CONFIGURED")
    print("module CONFIGURED (original JWKS snapshot taken)")

    # 3. Rotate the OP signing keys through the admin API. The new key is
    # RS256: the suite's VerifyNewJwksHasNewSigningKey condition cannot parse
    # Ed25519 (OKP) keys, and rotation keeps one active key per algorithm, so
    # the realm's EdDSA default stays active alongside.
    _, token_resp = http(
        "POST",
        f"{OP}/api/v1/auth/admin-token",
        body={"realm": "master", "username": "admin", "password": "admin"},
    )
    admin = token_resp["access_token"]
    status, _ = http(
        "POST",
        f"{OP}/admin/realms/conformance/keys/rotate",
        body={"algorithm": "RS256"},
        bearer=admin,
    )
    assert status in (200, 201, 204), f"rotate failed: {status}"
    print("OP keys rotated via admin API (old key remains published)")

    # 4. Start the module: it re-fetches the JWKS and validates the rotation.
    http("POST", f"{SUITE}/api/runner/{module_id}")
    info = wait_status(module_id, "FINISHED")
    result = info.get("result", "UNKNOWN")
    print(f"module FINISHED with result {result}")
    if result != "PASSED":
        print(json.dumps(info, indent=2)[:2000])
        raise SystemExit(f"rotation evidence run failed: {result}")
    print("oidcc-server-rotate-keys: PASSED with a real key rotation")


if __name__ == "__main__":
    main()
