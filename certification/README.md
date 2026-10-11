# OIDC Certification Surface Expansion — Master Plan

> Status: **implementation complete; review fixes applied** — full matrix green (gate v10, 612 executed modules, exit 0). M6 (certification-grade dynamic re-runs + OIDF submissions) remains.
> Branch: `feat/oidc-certification-expansion`. Suite pinned at `release-v5.3.2`.
> Companion documents:
> [`execution-matrix.md`](./execution-matrix.md) — exact plan/variant run matrix;
> [`JOURNAL.md`](./JOURNAL.md) — living handoff journal (**read it first** when
> picking up this work; see §6 Working rules).

## 1. Objective

Extend Issuerd's OpenID Foundation certification surface from the 3 profiles
that pass today (**Config OP**, **Basic OP**, **Form Post OP – basic**) to the
full published OP certification set: **11 profiles, 634 test-module
executions**.

### Target matrix (published OIDF certification profiles)

Regular profiles — total **532** module executions:

| OIDC Profile | Response types | Tests | Status today |
|---|---|---|---|
| Basic OP | `code` | 36 | **PASSING** (static_client) |
| Implicit OP | `id_token` | 58 | not run — needs M2 |
| Hybrid OP | `code id_token` | 102 | not run — needs M2 |
| Config OP | — | 1 | **PASSING** |
| Dynamic OP | all six | 127 | not run — needs M1+M4+M5 |
| Form Post OP | basic / implicit / hybrid | 196 | 36 PASSING (basic); implicit/hybrid need M2 |
| 3rd Party-Init OP | all six | 12 | not run — needs M1 |

Logout profiles — total **102** module executions:

| OIDC Profile | Response types | Tests | Status today |
|---|---|---|---|
| RP-Initiated OP | all six | 66 | feature ~implemented; needs M2 (+M1) |
| Session OP | all six | 12 | not run — `check_session_iframe`/`session_state` MISSING (M3) |
| Front-Channel OP | all six | 12 | feature implemented; needs M2 (+M1) |
| Back-Channel OP | all six | 12 | feature implemented; needs M2 (+M1) |

Net-new executions to make green: **459 regular + 102 logout = 561**.

"All six" response types = `code`, `code id_token`, `code id_token token`,
`code token`, `id_token`, `id_token token`. The suite runs the Dynamic,
3rd-Party-Init, and all four logout/session plans **once per response type**
(the `response_type` variant is a menu selection in those plans) — that
multiplication is how the published totals arise (e.g. RP-Initiated: 11
modules × 6 = 66; Session: 2 × 6 = 12; Dynamic: 23+22+22+22+19+19 = 127).

## 2. Starting point

Harness (all reusable, hermetic, pristine-suite): `tests/conformance/` —
isolated network (`internal: true`), bind9-only DNS + CDN shim, local root CA,
pristine suite JAR built in-docker from `conformance-suite/`
(`release-v5.3.2`), one-shot `conformance-run` service driving the pristine
`run-test-plan.py`, plans + expected-skips under `configs/`, results under
`results/`, single-module debugging via `run-focus.sh`. CI: `heavy.yml`
conformance job; evidence tarball attached to releases.

Passing today (0 failures / 0 warnings, see `tests/conformance/COVERAGE.md`):

- `oidcc-config-certification-test-plan` — 1 module
- `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` — 36 modules
- `oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` — 36 modules

Relevant implemented features (verified against source): `form_post`
response mode; RP-initiated logout with real `id_token_hint` validation and
state echo; front-channel logout iframes (`iss`+`sid` always appended);
back-channel logout dispatcher with spec-correct logout tokens; `sid` claim in
all token types; pairwise subjects (`subject_types_supported:
["public","pairwise"]`); private_key_jwt client auth with inline **and**
URL-fetched client JWKS (kid-miss refetch retry); admin-driven key rotation
(`POST /admin/realms/{realm}/keys/rotate`); SSO cookie is already
`SameSite=None; Secure` under TLS (`crates/issuerd-server/src/routes/oidc.rs:207-229`).

## 3. Suite mechanics that shape this plan

Established by reading the pinned suite source (`tests/conformance/conformance-suite/` @ `release-v5.3.2`):

- **Plan names & module counts** (per `@PublishTestPlan` /
  `testModulesWithVariants()`): see `execution-matrix.md`. Implicit = one run
  covering `id_token` **and** `id_token token`; Hybrid = one run covering all
  three hybrid types; Dynamic/3rd-Party-Init/logout plans = one run **per**
  response type.
- **Published-count reconciliation**: the OIDF pages count 58/102 for
  Implicit/Hybrid — the **dynamic_client** numbers. Under `static_client` the
  `oidcc-id-token-signature` modules are `@VariantNotApplicable`
  (`OIDCCIdTokenSignature.java:18`), giving 56/99. Internal gating uses static
  runs (parity with today's Basic runs); the **certification submission runs
  for Implicit/Hybrid/Form-Post must use
  `client_registration=dynamic_client`** to reach the published counts — which
  makes M1 (DCR) a prerequisite for final submission of those profiles too.
- **Dynamic and 3rd-Party-Init plans pin `client_registration=dynamic_client`**
  and `client_auth_type=private_key_jwt` (Dynamic). The suite registers a
  client with RFC 7591 metadata (`client_name`, `grant_types`,
  `response_types`, `jwks`, `token_endpoint_auth_method`, per-module extras)
  and requires HTTP 201 + `registration_client_uri` + management credentials,
  RFC 7592 read, and (warning-only) DELETE.
- **`oidcc-server-rotate-keys` is a manual-step module** (`autoStart=false`,
  `TellUserToRotateOpKeys`): it snapshots the JWKS at configure time, waits in
  `CONFIGURED`, and on start requires a **new** kid (FAILURE) while the old
  kid **remains** (WARNING). The pristine `run-test-plan.py` starts it
  immediately without rotating ("we can't actually do that"), so a pristine
  unattended run fails this module. Resolution in §7.3 — expected-failure
  entry + standalone suite-API-driven run, no suite patching.
- **Logout negative modules use screenshot placeholders**
  (`ExpectInvalidIdTokenHintErrorPage`, etc.) — the browser must land on a
  human-readable error/confirmation page; results come back REVIEW-flagged
  (like today's `oidcc-ensure-registered-redirect-uri`). Our JSON 400 bodies
  render in the browser and satisfy the placeholder mechanism.
- **No variant has a server-side default** — every unpinned variant must be
  spelled out in the plan-name variant string (as today's runs already do for
  `server_metadata`/`client_registration`).
- Session Management plan's main module iframes the OP's
  `check_session_iframe` from the suite origin and speaks the postMessage
  protocol (`client_id + " " + session_state` → `"changed"|"unchanged"|"error"`);
  the suite's HtmlUnit executes plain JS — **do not rely on WebCrypto**
  (`crypto.subtle`) inside the iframe page.

## 4. Feature work inventory (workstreams)

Detailed per-workstream task lists live in this section; **execution order is
defined by the milestones in §5, not by workstream** — milestones pull tasks
from several workstreams in convergence order. File references are the current
implementation points; tests follow the repo convention (unit in-file,
integration under `tests/integration/`).

### WS-A — Response types & nonce rules

- **A1. Accept the missing response types at the authorization endpoint.**
  `crates/issuerd-server/src/routes/oidc.rs:889-921` currently rejects
  `token`, `code token`, `id_token token`, `code id_token token` with
  `unsupported_response_type`. Parsing and per-client allowlists already
  handle all seven combinations
  (`crates/issuerd-protocol/src/authorization.rs:439-516`, `:163-183`).
  Certification needs `id_token token`, `code token`, `code id_token token`
  (bare `token` is OAuth2-only and never exercised by the suite — keep
  rejecting it). Registration-time `response_types` validation (M1) must
  accept all syntactically valid OIDC response types as metadata even before
  the endpoint supports them — endpoint enforcement stays the authority.
- **A2. Mint access tokens at the authorization endpoint.** Token-bearing
  response types need `access_token` + `token_type=Bearer` + `expires_in` in
  the fragment (or form_post body). Reuse the existing issuance machinery
  (`issue_access_token_with_roles`) in `finish_sso_login`
  (`oidc.rs:1472-1723`), which today has branches only for `id_token`
  (`:1581-1632`) and `code id_token` (`:1633-1690`). Claims assembly for
  implicit-issued access tokens must match the documented overlay rules
  (`src/claims.rs`: token-endpoint ID tokens get no overlay; implicit ID
  tokens do).
- **A3. `at_hash` / `c_hash` completeness.** Already computed alg-aware
  (`crates/issuerd-token/src/hash.rs:22-28`, wired at
  `crates/issuerd-token/src/token_manager.rs:375-401`). Wire `at_hash` into
  every implicit/hybrid ID token that accompanies an access token and verify
  the hybrid `sub`-consistency expectations
  (`VerifyIdTokenSubConsistentHybridFlow`).
- **A4. Enforce `nonce` for implicit/hybrid.** OIDC Core §3.2.2.1/§3.3.2.1:
  nonce REQUIRED for any response type containing `id_token`; the suite
  asserts nonce-less requests fail (`OIDCCEnsureRequestWithoutNonceFails`)
  and — for `code token` — succeed (no id_token in that response). Pure `code`
  must stay nonce-optional (`oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
  stays green). **Backward-compat decision (CHANGELOG):** today nonce-less
  `code id_token` is accepted; tightening is a spec-MUST remediation. Ship a
  realm-attribute escape hatch (`compat.nonceless_hybrid=true`, default off)
  so existing deployments can opt back in during a deprecation window.
- **A5. Discovery truthfulness.** `response_types_supported` gains the newly
  supported types and `grant_types_supported` gains `implicit`
  (`crates/issuerd-protocol/src/discovery.rs:252-275`). The Dynamic plan's
  discovery check requires `code`, `id_token`, and `token id_token` all
  advertised — only advertise what A1/A2 actually implement.
- **A6. Tests.** Unit: response-type acceptance matrix, nonce rules, hash
  presence. Integration: fragment-flow happy paths, form_post packaging of
  multi-value responses, `at_hash`/`c_hash` validation, nonce failure cases.

### WS-B — Session Management 1.0

Currently nothing exists (`session_state` never computed;
`AccessTokenClaims.session_state` exists but is always `None`;
`IdTokenClaims` lacks the field; discovery deliberately omits
`check_session_iframe`).

- **B1. `session_state` issuance.** Return `session_state` in every
  authorization response (code, implicit, hybrid; query/fragment/form_post),
  bound to the SSO `UserSession` so the iframe can compare later. Design
  choice (mirrors Keycloak): `session_state` carries the SSO session id in a
  JS-comparable form — the `sid` claim already exposes the same id to the RP,
  so no new identifier leaks. Spec scope: `session_state` is an authorization-RESPONSE parameter
  (OIDC Session Management §2/§3) — the as-built implementation carries it
  there and in the SPA `LoginResponse`; it is deliberately NOT embedded in
  access/id tokens (Keycloak includes it in both; one line in
  tests/KEYCLOAK_DIFFS.md records the parity note).
- **B2. Session-state cookie.** The SSO cookie is `HttpOnly`
  (`login_api.rs:982`) — iframe JS cannot read it. Set a companion,
  JS-readable, non-HttpOnly cookie (e.g. `issuerd_session_state`) carrying the
  current `session_state`, scoped `Path=/realms/{realm}`,
  `SameSite=None; Secure` under TLS (the conformance stack is TLS
  end-to-end), written at login, refreshed on re-auth, **cleared at logout**
  (all logout paths: RP-initiated, SPA logout API, account console, admin
  session delete, SSO idle cleanup) and on session expiry.
- **B3. `check_session_iframe` endpoint.**
  `GET /realms/{realm}/protocol/openid-connect/check_session_iframe` serves a
  self-contained HTML page (no external assets — the hermetic network refuses
  them) whose JS implements the spec's OP-iframe receiver: on `message` of
  `<client_id> + " " + <session_state>` from any origin, compare against the
  companion cookie and `postMessage` back `"unchanged"` / `"changed"`
  (mismatch or no cookie) / `"error"` (malformed), targeting `e.origin`.
  Plain-string comparison only — **no WebCrypto** (HtmlUnit compatibility).
- **B4. Security-header carve-out.** The iframe page must be framable by RP
  origins — it must NOT get `X-Frame-Options: DENY` / restrictive
  `frame-ancestors`. Carve out this one route (`frame-ancestors https:`
  posture), keep the rest of the surface locked. The page is stateless and
  performs no writes — framing it is safe.
- **B5. Logout propagation (as built).** Browser-present teardown paths
  clear the companion cookie in the logout response (RP-initiated all exits,
  SPA logout API, account-console self-delete), so the next poll answers
  `"changed"`. Out-of-band teardowns (admin delete, SSO idle cleanup) cannot
  clear a browser cookie; the iframe keeps answering `"unchanged"` until the
  next browser-present login/logout — the same limitation Keycloak's
  static-JS iframe has (the suite's Session plan only exercises
  browser-present logout). Recorded as an accepted deviation.
- **B6. Discovery.** Advertise `check_session_iframe` (`discovery.rs` —
  remove the deliberate-omission assertion at `:501`).
- **B7. Tests.** Unit: session_state stability/change semantics, cookie
  lifecycle. Integration: end-to-end iframe protocol against an in-process
  server, incl. logout → `"changed"`.

### WS-C — RFC 7591/7592 dynamic client registration

Current state: Keycloak-shaped DCR behind a per-realm attribute,
initial-access-token-gated advertised endpoint, RFC metadata silently dropped
(`client_registration.rs`), Keycloak-flavored response (`secret`,
`registrationAccessToken`, no `registration_client_uri`).

- **C1. Accept RFC 7591 request metadata** (alongside the Keycloak shape —
  additive): `client_name`, `grant_types`, `response_types`,
  `token_endpoint_auth_method`, `scope`, `id_token_signed_response_alg`,
  `userinfo_signed_response_alg`, `jwks` / `jwks_uri` (map onto the existing
  `use.jwks.string`+`jwks.string` / `use.jwks.url`+`jwks.url` client
  attributes — `crates/issuerd-server/src/client_assertion.rs:46-69`),
  `subject_type`, `initiate_login_uri`, `post_logout_redirect_uris`,
  `frontchannel_logout_uri` + `frontchannel_logout_session_required`,
  `backchannel_logout_uri` + `backchannel_logout_session_required`. Validate
  per RFC: https-only `initiate_login_uri` (else **HTTP 400
  `invalid_client_metadata`** — required by
  `oidcc-3rd_party-init-login-nohttps`), URI syntax,
  `token_endpoint_auth_method` support, `grant_types`/`response_types`
  coherence. Map registered `response_types` into the client's
  response-type allowlist that A1 consults.
- **C2. RFC 7591 response shape.** Return `client_id`, `client_secret`,
  `registration_access_token`, `registration_client_uri`,
  `client_id_issued_at`, `client_secret_expires_at` plus echoed metadata.
  Keep serving the Keycloak shape where the admin console depends on it —
  never break existing `registrationAccessToken` consumers.
- **C3. RFC 7592 management read** — `GET registration_client_uri` with the
  registration access token returns full current metadata incl.
  `initiate_login_uri` (`ValidateInitiateLoginUriInConfigurationResponse`).
  PUT/DELETE exist (`client_registration.rs:649/:669/:833`); verify DELETE is
  warning-free.
- **C4. ~~Advertised open registration~~ — RESOLVED BY DECISION (2026-10-11,
  see JOURNAL.md):** no open-registration changes. The suite's dynamic_client
  variant supports `client.initial_access_token`, and issuerd's initial access
  tokens are cache-backed with unlimited-count/no-expiry options — so the
  conformance bootstrap mints one and the token-gated endpoint (already the
  advertised `registration_endpoint`) serves all dynamic registrations. The
  open endpoint and its 50/h rate limit stay exactly as they are.
- **C5. `sector_identifier_uri` fetch + validation.** Pairwise is advertised,
  so `OIDCCRegistrationSectorUri` / `OIDCCRegistrationSectorBad` run: fetch
  the sector document (reuse the SSRF-guarded outbound fetch from the
  client-JWKS path), require registered `redirect_uris` to be covered, reject
  mismatches with 400 `invalid_client_metadata`, and use the fetched sector
  for pairwise subject computation. At registration and on update.
- **C6. Signed userinfo responses.** `OIDCCUserInfoRS256` registers
  `userinfo_signed_response_alg=RS256` and requires a JWT userinfo response
  (discovery must then advertise `userinfo_signing_alg_values_supported`).
  Net-new: userinfo-as-JWT in the userinfo endpoint (signing machinery exists
  in `issuerd-token`), per-client metadata, discovery field.
- **C7. RP key rotation via `jwks_uri`.** `OIDCCRefreshTokenRPKeyRotation`
  rotates the suite-hosted client JWKS and expects the OP to pick it up.
  Existing kid-miss refetch + cooldown (`client_assertion.rs:26`) should
  satisfy this — verify cooldown < the suite's 60 s `jwks_refresh_delay`;
  add an integration test.
- **C8. `alg=none` request objects.** Suite self-skips when `none` is not
  advertised — keep it that way.
- **C9. Tests.** Unit: metadata validation matrix (incl. 400 cases).
  Integration: register→read→update→delete lifecycle, sector accept/reject,
  signed userinfo, private_key_jwt with registered `jwks`/`jwks_uri`.

### WS-D — Logout-profile hardening

Feature core exists (`routes/oidc.rs:5608-5875`, `routes/logout.rs`); this is
spec-fidelity work.

- **D1. First-class `post_logout_redirect_uris`.** Today the post-logout
  target is validated against `redirect_uris` (`oidc.rs:5832-5860`). Add the
  spec'd per-client list (namespaced attribute — no migration needed), Admin
  API DTO + SPA display, provision YAML, DCR metadata (C1); logout validation
  prefers it, falling back to `redirect_uris` for existing clients (compat).
  `QueryAddedToLogoutRedirectUri`/`BadLogoutRedirectUri` must hit the
  no-redirect error path.
- **D2. Honor the per-client logout metadata** from C1
  (`frontchannel_logout_session_required`, `backchannel_logout_session_required`):
  when `false`, omit `iss`/`sid` (we always send them today — harmless for the
  suite, which registers `true`, but truthful).
- **D3. Negative-path review.** Walk the ten RP-initiated modules against
  current behavior: invalid/modified/absent `id_token_hint`, missing params,
  unregistered `post_logout_redirect_uri` → never redirect, render a
  browser-presentable error page. Confirm post-logout `prompt=none` fails and
  `NoState` redirects without state (both already true).
- **D4. Optional:** dispatch back-channel notifications from SSO idle-timeout
  cleanup (`oidc.rs:646-650` — currently silent); decide on `exp` in logout
  tokens (not spec-required).
- **D5. Tests.** Extend `tests/integration/logout_channels.rs`: dedicated
  post-logout list validation, metadata-`false` behavior, per-response-type
  logout smoke.

### WS-E — 3rd-Party-Initiated Login

The certification plan (2 modules × 6 response types) exercises **only DCR
handling**: register `initiate_login_uri`, echo it in the RFC 7592 read,
reject non-https with 400 `invalid_client_metadata` — fully covered by
C1+C3. The runtime flow (an RP's `initiate_login_uri` consuming
`iss`/`login_hint`/`target_link_uri`) is an RP concern; **no issuerd endpoint
is required for certification**.

## 5. Implementation order — milestones

Ordering principle: **convergence-first**. Each milestone is a coherent
implementation unit whose completion immediately turns profiles green, and
which later milestones build on. Workstreams (§4) are pulled apart and
re-gathered into this order — the anti-pattern being avoided is touching the
same surface (Client model, DCR, authorization endpoint, discovery) four
separate times.

### M1 — Client metadata & registration foundation

**Pulls in:** C1, C2, C3, D1, D2, WS-E (C4 dropped — initial-access-token
decision, see WS-C note).

One pass over the whole client-metadata surface: `Client` model attributes →
admin DTO (`crates/issuerd-admin-api/src/dto.rs`) → DCR accept/validate/echo →
RFC 7592 read → provision YAML → SPA display. Doing this first means every
later milestone registers clients through a finished surface (dynamic runs)
or pre-registers finished fields (static logout bootstrap), and M2's
response-type enforcement can consult a properly populated per-client
allowlist from day one.

**Converges into:** 3rd-Party-Init OP green ×6 immediately (12/634);
unblocks all dynamic_client runs.

**Exit criteria:** DCR lifecycle integration tests green (register → RFC 7592
read echoing every field → update → delete); https-validation 400s;
`oidcc-3rdparty-init-login-certification-test-plan` green for all six
response-type variants; per-realm registration posture attribute documented;
CHANGELOG entry.

### M2 — Authorization response types & nonce

**Pulls in:** A1–A6.

**Converges into:** Implicit OP (58), Hybrid OP (102), Form Post
implicit+hybrid (160) green under static_client; RP-Initiated (66),
Front-Channel (12), Back-Channel (12) green ×6 (logout core already exists;
bootstrap uses M1's `post_logout_redirect_uris`).

**Exit criteria:** the four regular-profile plans and the three logout plans
green in the hermetic run; nonce-tightening compat attribute + CHANGELOG
note; discovery advertises exactly what is implemented; no regression in
Basic/FormPost-basic/Config.

### M3 — Session management

**Pulls in:** B1–B7.

**Converges into:** Session OP green ×6 (12/634) — the last missing feature
area.

**Exit criteria:** session plan green for all six response types;
header carve-out reviewed; cookie lifecycle covered by integration tests;
no regression elsewhere.

### M4 — Registration-backed deep features

**Pulls in:** C5 (sector fetch/validate), C6 (signed userinfo), C7
(`jwks_uri` verification test).

**Converges into:** Dynamic OP green ×6 (127/634, with
`oidcc-server-rotate-keys` handled per §7.3 — sidecar script is M5.1 and is
the first thing built in M5); certification-grade **dynamic_client re-runs**
of Implicit/Hybrid/Form-Post at the published counts (58/102/160).

**Exit criteria:** six dynamic runs green + standalone rotation evidence;
sector/signed-userinfo/jwks_uri integration tests green.

### M5 — Harness & rotation automation

**Pulls in:** §7 (harness) — in full-matrix form. Note: per-profile configs
and bootstrap extensions **ride along with the milestone that unblocks each
profile** (M1 ships the 3rd-party config, M2 ships implicit/hybrid/logout
configs, …). What remains here:

- **M5.1** `tests/conformance/run-rotation-check.sh` (§7.3) — needed for M4 sign-off.
- **M5.2** `run-conformance.sh` full matrix assembly (all invocations from
  `execution-matrix.md`).
- **M5.3** `run-focus.sh` generalization (any `plan[variants]:module`).

### M6 — Full-matrix gate + submission prep

Single `run.sh` (or CI shard set if wall-clock demands — §7.2) executes
**634/634** green; `tests/conformance/COVERAGE.md` gains a per-profile
section per run; the Known-Gaps table loses the session-management row;
`AGENTS.md` conformance bullet updated; submission packages assembled per §9.

### Convergence summary

| After milestone | Newly green | Cumulative (of 634) |
|---|---|---|
| (today) | Config 1 + Basic 36 + FormPost-basic 36 | 73 |
| M1 | 3rd-Party-Init 12 | 85 |
| M2 | Implicit 58, Hybrid 102, FormPost-i/h 160, RP-Initiated 66, Front 12, Back 12 | 495 |
| M3 | Session 12 | 507 |
| M4 (+M5.1) | Dynamic 127 | 634 |
| M5.2–M6 | full-matrix gate, certification-grade dynamic reruns | 634 sustained |

## 6. Working rules — commit often, journal always

These rules are **binding for all work under this plan** (they exist because
this is a long, multi-session effort and context loss is the biggest risk):

1. **Commit often.** Every completed task — or coherent half-task — is its
   own commit on `feat/oidc-certification-expansion`. A working session must
   never end with uncommitted changes. Small commits beat comprehensive ones:
   they bisect, revert, and hand off cleanly.
2. **Journal before you stop.** `certification/JOURNAL.md` is the handoff
   contract. Before ending any working session — and after any commit that
   changes plan state — update it: milestone/profile status tables, the
   "Next action" line, and a dated log entry (what landed, commit hash,
   decisions made, blockers hit). Write it for a reader with **zero** prior
   context: verbatim commands, full repo-relative paths, reasons not just
   facts.
3. **Everything lives in `./certification/`.** Plan, matrix, journal, and any
   still-relevant analysis. If a decision or state isn't recorded here, it
   does not survive handoff. (Suite evidence stays in
   `tests/conformance/results/` — reference it, don't copy it.)
4. **Standard repo gates apply to every commit:** `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
   `cargo test --workspace --lib` (plus `scripts/dylint.sh --workspace` when
   logging/`#[instrument]` sites were touched). CHANGELOG entry per
   user-visible change (the `changelog.yml` PR gate).
5. **Suite tag changes are journal-worthy events**: record the tag, the run
   result, and any module-count deltas, and update `execution-matrix.md` in
   the same commit.

## 7. Harness & automation work (`tests/conformance/`)

### 7.1 Plan configs & bootstrap

- New configs under `configs/` (naming mirrors today):
  `issuerd-implicit-op.json`, `issuerd-hybrid-op.json`,
  `issuerd-formpost-implicit-op.json`, `issuerd-formpost-hybrid-op.json`,
  `issuerd-dynamic-op.json`, `issuerd-3rdparty-init-op.json`,
  `issuerd-rpinitiated-logout-op.json`, `issuerd-session-op.json`,
  `issuerd-frontchannel-logout-op.json`,
  `issuerd-backchannel-logout-op.json`. Browser task blocks (login, consent,
  placeholder fills) copy from `issuerd-basic-op.json`; logout configs add the
  error/confirmation-page placeholder tasks the logout modules use.
- `bootstrap-issuerd.sh`: enable `dynamic_client_registration_enabled` (+ open
  registration per C4) on the conformance realm; for the static logout runs,
  pre-register on both clients: `post_logout_redirect_uris` =
  `{suite}/test/a/issuerd/post_logout_redirect`, `frontchannel_logout_uri` =
  `{suite}/test/a/issuerd/frontchannel_logout` (+ `_session_required=true`),
  `backchannel_logout_uri` = `{suite}/test/a/issuerd/backchannel_logout`
  (+ `_session_required=true`).
- Expected-skips/failures: one file per plan where they diverge
  (`issuerd-expected-skips-dynamic.json`, …). Carry forward the two
  unsigned-request-object skips (signed-only OP posture unchanged).

### 7.2 Runner

- Extend `scripts/run-conformance.sh`'s `run_plan` list with the full matrix
  from `execution-matrix.md`.
- Generalize `run-focus.sh` to take `plan[variants]:module` + config (today it
  hardcodes the Basic plan/config).
- Watch total wall-clock: today's 73 modules ≈ 3.5 min suite time; 634
  modules will be ~25–40 min. Acceptable for nightly `heavy.yml`; if it
  outgrows the window, shard by profile across parallel jobs (the stack is
  per-job hermetic, so sharding is trivial) rather than trimming scope.

### 7.3 `oidcc-server-rotate-keys` automation (Dynamic plan)

Pristine-suite constraint forbids patching the runner, and the pristine
runner starts the module without rotating. Approach:

1. In the six Dynamic-plan runs, list `oidcc-server-rotate-keys` in
   `issuerd-expected-failures-dynamic.json` with a comment explaining why
   (manual-step module; covered separately).
2. `tests/conformance/run-rotation-check.sh` drives the module standalone through the
   suite's REST API (the same public API `export-html.py` already uses):
   create module → poll until `CONFIGURED` (original JWKS snapshotted) →
   call `POST /admin/realms/conformance/keys/rotate` on the OP → start the
   module via the API → require green. Real, repeatable evidence of
   OIDCC-10.1.1 (new kid present, old kid retained — issuerd keeps rotated
   keys published until disabled, so both conditions hold).
3. Document in the certification submission that rotation evidence comes from
   the standalone run (the OIDF explicitly allows an attestation fallback for
   this module; our standalone green run is stronger than an attestation).

### 7.4 Coverage documentation

Extend `tests/conformance/COVERAGE.md` with a per-profile section per run
(same table format as today), update the "Known Gaps" table (session
management row disappears once M3 lands), and keep the header totals in sync.
Update the conformance bullet in `AGENTS.md` and the CI section as profiles
land.

## 8. Risks & open decisions

- **Nonce tightening (A4)** changes existing hybrid behavior. Mitigation:
  realm-attribute escape hatch + CHANGELOG breaking-change note with
  migration path (per the backward-compat policy).
- **Open registration endpoint — REMOVED FROM SCOPE (decision 2026-10-11).**
  The original plan considered advertising the unauthenticated registration
  path per realm; the suite's `client.initial_access_token` support plus
  issuerd's unlimited initial access tokens make that unnecessary, so no
  security-posture change happens at all. (Kept in this list for the record.)
- **`session_state` = session id (B1)** mirrors Keycloak but bakes the
  session id into another RP-visible value. Acceptable (already exposed as
  `sid`); revisit if we ever randomize `sid` per token.
- **Iframe JS compatibility (B3)**: HtmlUnit executes the page; use ES5-grade
  JS and string comparison only (no `crypto.subtle`, no modules, no fetch).
  Verify early with a focused run before building B5/B6 on top.
- **Suite runtime growth** (§7.2): if a full matrix exceeds the nightly
  window, shard by profile in `heavy.yml`; never trim modules.
- **Published-count reconciliation** (§3): Implicit/Hybrid/FormPost published
  counts assume dynamic_client. Static runs (56/99) are the M2 gate;
  certification-grade runs happen in M4.
- **`oidcc-server-rotate-keys`** can never pass inside the pristine unattended
  runner (upstream acknowledges this). The standalone-run evidence path (§7.3)
  is the resolution; flag it in the submission narrative.
- **Upstream suite drift**: plans/counts are pinned to `release-v5.3.2`.
  Re-validate the matrix on any further tag bump (working rule 5).

## 9. Certification submission checklist (per profile, at M6)

1. Full green run of the profile's plan(s) in the hermetic environment,
   `release-v5.3.2`, exported JSON + HTML reports archived under
   `results/` (and attached to the release as the `conformance-evidence`
   artifact — the release pipeline already does this).
2. REVIEW-flagged modules (logout error pages, `prompt=login`, `max-age=1`,
   unregistered-redirect) visually verified; screenshots retained.
3. Known-deviation disclosure for the submission narrative: the
   `check_session_iframe` OP page answers postMessage from any origin without
   an expected-origin allowlist (OIDC Session Management §3.2/§6 is
   MUST-level) — matching Keycloak's reference behavior. Impact is
   negligible-by-design (session ids are 122-bit UUIDs; absent-cookie and
   mismatch both answer `changed`, so even login state is not
   distinguishable); tightening it requires a per-client server round-trip
   the static-page design avoids. (If a future suite version tests it, the
   page gains a per-client origin check via a server lookup.)
4. (renumbered) Profile submission on openid.net/certification: plan export + logs +
   deployment description; rotation evidence per §7.3 for Dynamic OP.
5. (renumbered) Update public docs (`docs/`, README badge list) only after the OIDF lists
   the profile.

## 10. References

- Suite source (pinned): `tests/conformance/conformance-suite/` @ `release-v5.3.2`
- Current results: `tests/conformance/COVERAGE.md`
- Harness guide: `tests/conformance/README.md`
- Run matrix produced by this plan: [`execution-matrix.md`](./execution-matrix.md)
- Handoff journal: [`JOURNAL.md`](./JOURNAL.md)
- OIDF profiles & published counts: <https://openid.net/certification/openid-connect/>
- OIDCC plan sources: `conformance-suite/src/main/java/net/openid/conformance/openid/OIDCC*TestPlan.java`
