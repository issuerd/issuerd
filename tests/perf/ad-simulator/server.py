#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Authentication-device (AD) simulator for Keycloak CIBA in the perf rig.

Keycloak's built-in `ciba-http-auth-channel` provider POSTs every backchannel
authentication request to this service (and fails the bc-auth request with
503 unless we answer 201). The POST carries an `Authorization: Bearer` token
identifying the pending auth session; approving means POSTing
`{"status": "SUCCEED"}` with that token to Keycloak's CIBA callback endpoint.

Timing: the auth session is not visible to the callback endpoint until the
bc-auth request has completed (callback attempts before that get 403), so we
answer 201 immediately and approve from a background thread with a zero-delay
first attempt plus tight retries. Keycloak fires the channel POST mid-bc-auth,
so the approval typically lands before the client's first token poll — the
KC analogue of issuerd's synchronous ext/ciba/approve call.

Endpoints:
  POST /ciba    — Keycloak auth-channel webhook (202-then-approve)
  GET  /health  — liveness + approval counters
"""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALLBACK_URL = "http://keycloak:8080/realms/perf/protocol/openid-connect/ext/ciba/auth/callback"
RETRY_BUDGET_S = 10.0  # total budget for one approval (bc-auth expires_in is 120s)

_approvals = 0
_failures = 0
_lock = threading.Lock()


def _approve(token: str) -> None:
    """POST {"status": "SUCCEED"} to Keycloak's CIBA callback. The first
    attempts usually 403 (auth session not yet committed by the in-flight
    bc-auth request); retry with a short backoff until it sticks."""
    global _approvals, _failures
    body = json.dumps({"status": "SUCCEED"}).encode()
    deadline = time.monotonic() + RETRY_BUDGET_S
    attempt = 0
    while True:
        req = urllib.request.Request(
            CALLBACK_URL,
            data=body,
            headers={"Authorization": token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as res:
                if 200 <= res.status < 300:
                    with _lock:
                        _approvals += 1
                    return
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            pass
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            with _lock:
                _failures += 1
            print("ciba approve: gave up — poll will see authorization_pending/expired", flush=True)
            return
        time.sleep(min(0.05 + 0.025 * attempt, remaining))


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/ciba":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)  # body unused — the bearer token identifies the session
        token = self.headers.get("Authorization", "")
        if token:
            threading.Thread(target=_approve, args=(token,), daemon=True).start()
        else:
            print("ciba webhook without Authorization header", flush=True)
        self.send_response(201)
        self.end_headers()

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps({"status": "ok", "approvals": _approvals, "failures": _failures}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"ad-simulator: {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"ad-simulator listening on :8080, approving via {CALLBACK_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
