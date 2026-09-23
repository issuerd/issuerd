# Plan: Runnable DPoP & CIBA examples under `examples/`

Status: **plan only — no implementation in this change.** This document is the
specification for the work; delete it (or move it under `docs/`) once the
examples land.

## 1. Goal

Give a first-time evaluator two **small, self-contained, runnable demonstrations**
of the two agentic-IAM technologies Issuerd implements and most IdPs don't:

- **DPoP (RFC 9449)** — sender-constrained tokens: mint a key, get a DPoP-bound
  token, use it, and watch theft/replay/downgrade attempts fail with real 401s.
- **CIBA (poll mode)** — decoupled user approval: an agent starts a backchannel
  authentication, the user approves under their SSO session (with a binding
  message), the agent polls and receives a token — optionally a **DPoP-bound
  step-up token**, tying both demos together.

Each example must be: runnable in under 5 minutes, fully scriptable end-to-end
(assertions included, non-zero exit on failure), documented line-by-line, and
honest about what is issuerd-specific vs spec-mandated.

## 2. Current state and the gap

| What exists today | Why it isn't enough |
|---|---|
| `docs/agentic-iam-mcp.md`, `docs/ciba-step-up.md` — narrative guides with recorded GIF demos | The demos run against the heavy `rig/` lab (FastAPI chat agent + FastMCP + PostgreSQL RLS + frpc tunnel). Great for storytelling, far too heavy to reproduce locally. |
| `tests/perf/k6/scenarios/dpop.js`, `ciba.js` — working programmatic flows | Benchmark harness: needs the whole isolated perf stack, uses k6 idioms, zero explanatory prose. |
| `examples/` | Config/provision files only (`*.demo.*`, `*.example.*`, `*.agent-test.*`, `*.federation.*`) — nothing runnable. |

Gap: **no minimal, copy-paste-runnable example** that shows these flows working
against Issuerd on localhost.

## 3. Decisions (with rationale)

1. **Demo vehicle: Node.js ≥ 18 single-file scripts, zero npm dependencies.**
   `crypto.webcrypto` provides ES256 keygen/signing/JWK export and
   `fetch` is global, so each demo is one `.mjs` file that runs with
   `node demo.mjs` — no `npm install`, no pip venv. (Rejected: Python — needs
   `pip install cryptography`; bash+curl+openssl — ECDSA JWK-thumbprint work in
   shell is unreadable, which defeats the teaching purpose; k6 — wrong tool for
   a tutorial.) READMEs additionally show the **raw curl shapes** for every
   request so the HTTP contract is visible without running anything.
2. **Infrastructure: one issuerd container per example, in-memory storage +
   in-memory cache, plain HTTP.** DPoP's `jti` replay cache and CIBA's pending
   requests live in the `DistributedCache` (`dpop_jti:{realm}:{jti}`,
   `ciba_auth_req:{id}`), which falls back to `InMemoryCache` when no `redis=`
   is configured — perfect for a single-node demo, no PostgreSQL/Redis needed.
   Each example ships its own `docker-compose.yml` with
   `build: { context: ../.., dockerfile: Dockerfile }`, so
   `docker compose up --build` works from a fresh clone. A **localhost variant**
   (`cargo run --bin issuerd -- daemon -c examples/<name>/issuerd.toml`) is
   documented for people who already build the repo.
3. **Port: host `8080`**, matching every existing doc and the root demo stack,
   with an explicit "only one issuerd stack on :8080 at a time" note in each
   README (`issuer_url` is baked into `iss`, so port discipline matters).
4. **Two independent directories** (`examples/dpop/`, `examples/ciba/`), each
   fully self-contained. The ~50-line DPoP proof helper is **duplicated** into
   the CIBA example rather than shared — teaching examples optimize for
   "read one directory, understand everything", not DRY. The CIBA README
   cross-links the DPoP example for the deep explanation.
5. **CIBA approval is scripted by default, with a `--browser` flag.** The
   approve endpoint requires the user's SSO session cookie, so the script first
   performs a programmatic browser-flow login (GET `/authorize` → POST login
   form → harvest session cookie — the same pattern as
   `tests/perf/k6/scenarios/ciba.js`) and then POSTs the approval. `--browser`
   instead pauses, prints the login URL, and lets a human approve by hand — the
   mode you'd use when demoing to an audience.
6. **No new issuerd features.** These examples consume the shipped surface only:
   DPoP binding at the token endpoint, `cnf.jkt`, replay/downgrade rejection,
   DPoP-bound refresh; CIBA `ext/ciba/auth` + `ext/ciba/approve` + polling.
   If a step turns out to need a product change, that is a plan deviation to
   surface — not something to silently fix in the example PR.

## 4. Target layout

```
examples/
├── README.md                       # NEW — index of everything in examples/
├── dpop-ciba-examples-plan.md      # this file (removed when done)
├── dpop/
│   ├── README.md                   # the teaching document (see §6)
│   ├── docker-compose.yml          # single issuerd service, build: repo root
│   ├── issuerd.toml                # in-memory storage+cache, HTTP :8080, pretty logs
│   ├── provision.yaml              # realm `demo`, user alice, client `dpop-app`
│   └── demo.mjs                    # the scripted demo, exits non-zero on failure
└── ciba/
    ├── README.md                   # the teaching document (see §7)
    ├── docker-compose.yml
    ├── issuerd.toml
    ├── provision.yaml              # realm `demo`, user alice, client `ciba-agent`
    └── demo.mjs                    # [--browser]
```

`issuerd.toml` per example (≈15 lines): `bind`, `port`, `issuer_url =
"http://localhost:8080"`, `provision`, `[logging] pretty/info` — deliberately
no `[storage]` (in-memory) and no `redis` (in-memory cache), mirroring the
root `issuerd.toml` dev rig pattern.

## 5. Provisioning content

Both `provision.yaml` files create the same minimal realm so the two examples
feel like siblings (name it `demo`, not `myrealm`, to stay independent of the
root demo stack):

- Realm `demo`: `ssl_required: external` (localhost HTTP), defaults otherwise.
- User `alice` / `changeme`, `email_verified` — the approval identity.
- DPoP example client `dpop-app` (public, PKCE, redirect
  `http://localhost:8080/callback` unused-but-valid) **or** a confidential
  `dpop-agent` using `client_credentials` — decide during implementation;
  client_credentials keeps the DPoP demo free of browser login entirely and is
  the honest shape for an agent. Prefer the confidential-client shape.
- CIBA example client `ciba-agent` (confidential, secret documented in the
  README; CIBA rejects public clients — verified by
  `ciba_auth_handler_public_client_rejected`). A second confidential client
  `wrong-client` is created too, for the §7.1 wrong-client-polls rejection
  step.

## 6. Example A — `examples/dpop/`

### Story arc (each step asserts and prints what it taught)

1. **Mint a key.** ES256 (P-256) keypair via WebCrypto; show the public JWK and
   its RFC 7638 SHA-256 thumbprint (`jkt`) in the output.
2. **Get a bound token.** `POST /realms/demo/protocol/openid-connect/token`
   `grant_type=client_credentials` with a fresh `DPoP` proof header
   (`htm=POST`, `htu=<token URL>`, random `jti`, `iat`). Assert the response;
   decode the JWT payload and show `cnf.jkt` + `token_type: "DPoP"`.
3. **Use it correctly.** `GET userinfo` with `Authorization: DPoP <token>` and
   a fresh proof carrying `ath` (base64url-SHA256 of the access token).
   Assert 200.
4. **Replay dies.** Repeat step 3 with the **same proof** (same `jti`) → assert
   `401 invalid_dpop_proof`. Teaching point: single-use `jti` replay cache
   (`dpop_jti:{realm}:{jti}`).
5. **Downgrade dies.** Present the bound token as plain `Bearer` → assert 401.
   Teaching point: a `cnf`-carrying token can never be used proof-less.
6. **Theft dies.** Replay the token from a **different key's** proof → assert
   401. Teaching point: stolen token ≠ stolen key.
7. **Introspection agrees.** Confidential-client introspect → assert
   `token_type: DPoP` and the same `cnf.jkt` (RFC 9449 §6.1).
8. **Refresh binding.** If step 2 used a grant that issues a refresh token
   (password grant against alice): refresh **without** a proof → 401; refresh
   with a proof from the same key → 200. (Optional step, gated on grant choice
   in §5.)

### README requirements

- What DPoP is in 3 sentences + link to RFC 9449.
- ASCII sequence diagram of steps 2–6.
- Run instructions: container path (`docker compose up --build`, then
  `node demo.mjs`) and localhost path (`cargo run … daemon -c issuerd.toml`).
- **Full expected-output transcript** (with secrets/elided fields marked) so a
  reader can verify without running.
- curl equivalent of every request (proof JWT shown as `<computed>` with the
  claims documented).
- "What Issuerd does / doesn't": opportunistic binding, no per-client
  require-DPoP switch (Keycloak parity note), proof age window (300 s / 60 s
  leeway), no DPoP nonces (OPTIONAL in RFC), mTLS sender-constraining deferred.
- Source map: `crates/issuerd-server/src/dpop.rs`,
  `crates/issuerd-token/src/dpop.rs`, `docs/agentic-iam-mcp.md`.

## 7. Example B — `examples/ciba/`

### Story arc

1. **Discovery.** GET the discovery document; show
   `backchannel_authentication_endpoint` and the CIBA grant type. Teaching
   point: the capability is advertised truthfully.
2. **Start backchannel auth.** As `ciba-agent`:
   `POST .../ext/ciba/auth` with `scope="openid refunds:execute"`,
   `login_hint=alice`, `binding_message="Refund $150 for order #123"`.
   Assert `auth_req_id`, `expires_in` (default 120 s), `interval` (default 5 s).
3. **Poll too early / too fast.** Token endpoint with
   `grant_type=urn:openid:params:grant-type:ciba` → assert
   `authorization_pending`; immediate second poll → assert `slow_down`.
4. **Approve as the user.** Scripted: complete the browser login flow
   programmatically as alice (capture SSO cookie), then
   `POST .../ext/ciba/approve` with `auth_req_id` + `action=approve`.
   With `--browser`: print the login URL, wait for the human, then approve via
   the harvested cookie is skipped — the human's browser session does it
   through a documented curl/form POST… (implementation detail: the script
   still needs to submit the approve POST; browser mode means the script
   reuses the human's cookie is impossible cross-process — so `--browser` mode
   instead has the human run one printed curl command with their own cookie, or
   the script exposes the exact form fields for a copy-paste. Final UX decided
   at implementation time; the README must show both paths.)
5. **Poll succeeds.** Assert `access_token` (and `id_token` since scope
   includes `openid`), decode and show `scope` contains `refunds:execute`.
6. **Step-up variant (the tie-in).** Re-run bc-auth, poll **with a DPoP proof**
   → assert the issued token carries `cnf.jkt`. One paragraph linking to
   `examples/dpop/` and `docs/ciba-step-up.md`.
7. **Denial path.** New bc-auth → approve with `action=deny` → next poll
   asserts `access_denied`.
8. **Wrong client path.** New bc-auth by `ciba-agent`, poll attempted by
   `wrong-client` → assert rejection (CIBA §7.1).
9. **Expiry path (optional, cheap).** bc-auth with `requested_expiry: 3`,
   never approve, poll after 4 s → assert `expired_token`.

### README requirements

Same shape as the DPoP README, plus: consumption-device vs authorization-device
explanation in 3 sentences; why approval rides the SSO session (and the audit
event when a session tries to approve another user's request); poll-only
scope (ping/push out of scope); the issuerd-specific endpoint paths called out
explicitly as **extensions** (`ext/ciba/approve` is not part of the CIBA spec —
the spec leaves user approval to the deployment); source map:
`crates/issuerd-protocol/src/ciba.rs`,
`crates/issuerd-server/src/routes/oidc.rs` (`ciba_auth_handler`,
`ciba_approve_handler`), `docs/ciba-step-up.md`.

## 8. Cross-cutting requirements

- **Idempotent + self-verifying.** Every demo script asserts each expected
  status/body and exits non-zero with a clear message on mismatch; re-running
  against the same container must work (in-memory restart makes this free, but
  scripts must not depend on it).
- **Timeouts everywhere.** All fetch calls carry explicit timeouts; the CIBA
  poll loop honors the server-advertised `interval` and has an overall deadline.
- **Configurability.** `ISSUERD_URL` env var (default `http://localhost:8080`);
  realm/user/client names overridable but defaulting to the provisioned values.
- **Teardown.** Each README ends with `docker compose down` (and notes `-v` is
  unnecessary — no volumes).
- **`examples/README.md`** gains a table indexing all files: existing
  config/provision files (with one-line purpose each) + the two new runnable
  examples.
- **Docs integration.** Add a "Runnable examples" pointer to
  `docs/client-integration.md` and the `docs/README.md` index; update the
  `examples/` line in `AGENTS.md` (workspace-structure section) to mention the
  runnable demos.
- **No CI wiring in v1** (the demos need a built image / running daemon);
  instead a manual checklist in each README. A follow-up may add a
  `scripts/test-examples.sh` smoke that builds the image and runs both demos —
  listed as stretch, not required.

## 9. Work breakdown (implementation phases, when picked up)

1. **Scaffold + provision** — both directories' `issuerd.toml`,
   `provision.yaml`, `docker-compose.yml`; verify boot and discovery manually.
   Acceptance: `docker compose up --build` healthy; `curl` discovery shows
   expected endpoints.
2. **DPoP demo script** — `examples/dpop/demo.mjs` steps 1–7 (+8 if refresh is
   in scope), green against the container.
3. **CIBA demo script** — `examples/ciba/demo.mjs` steps 1–8, incl. scripted
   SSO login + approve; green against the container.
4. **READMEs** — both teaching documents with transcripts recorded from real
   runs (never hand-written outputs), plus `examples/README.md` index.
5. **Docs/AGENTS links** — §8 pointers.
6. **Fresh-clone verification** — clean checkout (or `git clean`-style stash),
   follow both READMEs verbatim, confirm exit 0 and matching transcripts;
   `docker compose down` leaves nothing behind.

## 10. Definition of done

- Both demos run green on the container path and the localhost path.
- Every printed claim in the READMEs is backed by a real captured transcript.
- Every rejection step asserts the exact error code (`invalid_dpop_proof`,
  `authorization_pending`, `slow_down`, `access_denied`, `expired_token`).
- A reader who knows neither DPoP nor CIBA can explain both after reading the
  two READMEs and running the two scripts.
- `AGENTS.md`, `docs/README.md`, `docs/client-integration.md` and
  `examples/README.md` are in sync with the new layout.
