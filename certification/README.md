# OIDC Certification Surface Expansion — Master Plan

> Status: **plan** (not started). Branch: `feat/oidc-certification-expansion`.
> Companion document: [`execution-matrix.md`](./execution-matrix.md) — the exact
> plan/variant/config run matrix this plan produces.

## 1. Objective

Extend Issuerd's OpenID Foundation certification surface from the 3 profiles
that pass today (**Config OP**, **Basic OP**, **Form Post OP – basic**) to the
full published OP certification set: **11 profiles, 634 test-module
executions**.

### Target matrix (published OIDF certification profiles)

Regular profiles — total **532** module executions:

| OIDC Profile | Response types | Tests | Status today |
|---|---|---|---|
| Basic OP | `code` | 36 | **PASSING** (static_client run, suite `release-v5.2.4`) |
| Implicit OP | `id_token` | 58 | not run — blocked on response types (WS-A) |
| Hybrid OP | `code id_token` | 102 | not run — blocked on response types (WS-A) |
| Config OP | — | 1 | **PASSING** |
| Dynamic OP | all six | 127 | not run — blocked on RFC 7591/7592 DCR (WS-C) |
| Form Post OP | basic / implicit / hybrid | 196 | 36 PASSING (basic); implicit/hybrid blocked on WS-A |
| 3rd Party-Init OP | all six | 12 | not run — blocked on DCR metadata (WS-C) |

Logout profiles — total **102** module executions:

| OIDC Profile | Response types | Tests | Status today |
|---|---|---|---|
| RP-Initiated OP | all six | 66 | feature ~implemented; not run — blocked on WS-A + WS-D |
| Session OP | all six | 12 | not run — `check_session_iframe`/`session_state` MISSING (WS-B) |
| Front-Channel OP | all six | 12 | feature implemented; not run — blocked on WS-A + WS-D |
| Back-Channel OP | all six | 12 | feature implemented; not run — blocked on WS-A + WS-D |

Net-new executions to make green: **459 regular + 102 logout = 561**.

"All six" response types = `code`, `code id_token`, `code id_token token`,
`code token`, `id_token`, `id_token token`. The suite runs the Dynamic,
3rd-Party-Init, and all four logout/session plans **once per response type**
(the `response_type` variant is a menu selection in those plans) — that
multiplication is how the published totals arise (e.g. RP-Initiated: 11
modules × 6 = 66; Session: 2 × 6 = 12; Dynamic: 23+22+22+22+19+19 = 127).
Consequence: **the response-type work (WS-A) gates 9 of the 11 profiles** and
is therefore Phase 1.

## 2. Starting point

Harness (all reusable, hermetic, pristine-suite): `tests/conformance/` —
isolated network (`internal: true`), bind9-only DNS + CDN shim, local root CA,
pristine suite JAR built in-docker from `conformance-suite/`
(`release-v5.2.4`), one-shot `conformance-run` service driving the pristine
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

Established by reading the pinned suite source (`tests/conformance/conformance-suite/`):

- **Plan names & module counts** (per `@PublishTestPlan` /
  `testModulesWithVariants()`): see `execution-matrix.md`. Implicit = one run
  covering `id_token` **and** `id_token token`; Hybrid = one run covering all
  three hybrid types; Dynamic/3rd-Party-Init/logout plans = one run **per**
  response type.
- **Published-count reconciliation**: the OIDF pages count 58/102 for
  Implicit/Hybrid — the **dynamic_client** numbers. Under `static_client` the
  `oidcc-id-token-signature` modules are `@VariantNotApplicable`
  (`OIDCCIdTokenSignature.java:18`), giving 56/99. Internal Phase-1 gating
  uses static runs (parity with today's Basic runs); the **certification
  submission runs for Implicit/Hybrid/Form-Post must use
  `client_registration=dynamic_client`** to reach the published counts — which
  makes WS-C (DCR) a prerequisite for final submission of those profiles too.
- **Dynamic and 3rd-Party-Init plans pin `client_registration=dynamic_client`**
  and `client_auth_type=private_key_jwt` (Dynamic). The suite registers a
  client with RFC 7591 metadata (`client_name`, `grant_types`,
  `response_types`, `jwks`, `token_endpoint_auth_method`, per-module extras)
  and requires HTTP 201 + `registration_client_uri` + management credentials,
  RFC 7592 read, and (warning-only) DELETE.
- **`oidcc-server-rotate-keys` is a manual-step module** (`autoStart=false`,
  `TellUserToRotateOpKeys`): it snapshots the JWKS at configure time, waits in
  `CONFIGURED`, and on start requires a **new** kid (FAILURE) while the old
  kid **remains** (WARNING). The pristine `run-test-plan.py:279-284` starts it
  immediately without rotating ("we can't actually do that"), so a pristine
  unattended run fails this module. Resolution in §5.3 — a sidecar watcher +
  expected-failure entry + standalone rerun, no suite patching.
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

## 4. Feature work (issuerd code)

Workstreams are ordered by dependency. File references are the current
implementation points; tests follow the repo convention (unit in-file,
integration under `tests/integration/`).

### WS-A — Full response-type support + nonce rules (Phase 1)

Gates: Implicit OP, Hybrid OP, Form Post implicit/hybrid, and every
six-response-type run of the logout/session/3rd-party profiles.

- **A1. Accept the missing response types at the authorization endpoint.**
  `crates/issuerd-server/src/routes/oidc.rs:889-921` currently rejects
  `token`, `code token`, `id_token token`, `code id_token token` with
  `unsupported_response_type`. Parsing and per-client allowlists already
  handle all seven combinations
  (`crates/issuerd-protocol/src/authorization.rs:439-516`, `:163-183`).
  Certification needs `id_token token`, `code token`, `code id_token token`
  (bare `token` is OAuth2-only and never exercised by the suite — keep
  rejecting it unless we deliberately widen).
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
  and — for `code token` — succeed (`code token` has no id_token). Pure `code`
  must stay nonce-optional (`oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
  stays green). **Backward-compat decision (called out in CHANGELOG):**
  today nonce-less `code id_token` is accepted; tightening is a spec-MUST
  remediation. Ship a realm attribute escape hatch
  (`compat.nonceless_hybrid=true`, default off) so existing deployments can
  opt back in during a deprecation window.
- **A5. Discovery truthfulness.** `response_types_supported` gains the newly
  supported types and `grant_types_supported` gains `implicit`
  (`crates/issuerd-protocol/src/discovery.rs:252-275`). The Dynamic plan's
  discovery check requires `code`, `id_token`, and `token id_token` all
  advertised — only advertise what A1/A2 actually implement.
- **A6. Tests.** Unit: response-type acceptance matrix, nonce rules, hash
  presence. Integration: fragment-flow happy paths, form_post packaging of
  multi-value responses, `at_hash`/`c_hash` validation, nonce failure cases.
  Keycloak-parity check via the dual-target harness where applicable.

### WS-B — Session Management 1.0 (Phase 2)

Gates: Session OP. Largest net-new feature. Currently nothing exists
(`session_state` never computed; `AccessTokenClaims.session_state` exists but
is always `None`; `IdTokenClaims` lacks the field; discovery deliberately
omits `check_session_iframe`).

- **B1. `session_state` issuance.** Return `session_state` in every
  authorization response (code, implicit, hybrid; query/fragment/form_post).
  Value: bound to the SSO `UserSession` so the iframe can compare later.
  Design choice (mirrors Keycloak): `session_state` carries the SSO session
  id in a JS-comparable form — the `sid` claim already exposes the same id to
  the RP, so no new identifier leaks. Add `session_state` to
  `AccessTokenClaims` wiring and as an optional `IdTokenClaims` field
  (serde-defaulted — additive for JSON snapshots per the compatibility
  policy).
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
  them) whose JS implements the spec's OP-iframe receiver: on
  `message` of `<client_id> + " " + <session_state>` from any origin, compare
  against the companion cookie and `postMessage` back `"unchanged"` /
  `"changed"` (mismatch or no cookie) / `"error"` (malformed), targeting
  `e.origin`. Plain-string comparison only — **no WebCrypto** (HtmlUnit
  compatibility). i18n not needed (no visible UI).
- **B4. Security-header carve-out.** Audit the middleware stack: the iframe
  page must be framable by RP origins — it must NOT get `X-Frame-Options:
  DENY` / restrictive `frame-ancestors`. Carve out this one route
  (`frame-ancestors https:` posture), keep the rest of the surface locked.
  The page itself is stateless and performs no writes — framing it is safe.
- **B5. Logout propagation.** Every session-destruction path must flip the
  iframe verdict to `"changed"`: delete the companion cookie server-side
  responses and, for back-channel-only teardowns (admin delete, idle
  cleanup), the cookie naturally resolves to a destroyed session → next poll
  reports `"changed"` (comparison is against live storage, not just cookie
  presence).
- **B6. Discovery.** Advertise `check_session_iframe`
  (`discovery.rs` — remove the deliberate-omission assertion at `:501`).
- **B7. Tests.** Unit: session_state stability/change semantics, cookie
  lifecycle. Integration (`tests/integration/`): end-to-end iframe protocol
  against an in-process server using a tiny HTML driver, incl. logout →
  `"changed"`.

### WS-C — RFC 7591/7592 dynamic client registration (Phase 3)

Gates: Dynamic OP, 3rd-Party-Init OP, and the dynamic_client certification
runs of Implicit/Hybrid/Form-Post. Current state: Keycloak-shaped DCR behind
a per-realm attribute, initial-access-token-gated advertised endpoint, RFC
metadata silently dropped (`client_registration.rs`), Keycloak-flavored
response (`secret`, `registrationAccessToken`, no `registration_client_uri`).

- **C1. Accept RFC 7591 request metadata** (alongside the Keycloak shape —
  additive, existing clients unchanged): `client_name`, `grant_types`,
  `response_types`, `token_endpoint_auth_method`, `scope`,
  `id_token_signed_response_alg`, `userinfo_signed_response_alg`, `jwks` /
  `jwks_uri` (map onto the existing `use.jwks.string`+`jwks.string` /
  `use.jwks.url`+`jwks.url` client attributes — see
  `crates/issuerd-server/src/client_assertion.rs:46-69`), `subject_type`,
  `initiate_login_uri`, `post_logout_redirect_uris`,
  `frontchannel_logout_uri` + `frontchannel_logout_session_required`,
  `backchannel_logout_uri` + `backchannel_logout_session_required`.
  Validate per RFC: https-only `initiate_login_uri` (else **HTTP 400
  `invalid_client_metadata`** — the 3rd-Party-Init plan's
  `OIDCC3rdPartyInitLoginNonHttps` module requires exactly this), URI syntax,
  `token_endpoint_auth_method` support, `grant_types`/`response_types`
  coherence.
- **C2. RFC 7591 response shape.** Return `client_id`, `client_secret`,
  `registration_access_token`, `registration_client_uri`,
  `client_id_issued_at`, `client_secret_expires_at` plus the echoed metadata.
  Keep serving the Keycloak shape where the admin console depends on it —
  dual-shape by endpoint or content negotiation; never break the existing
  `registrationAccessToken` consumers (backward-compat policy).
- **C3. RFC 7592 management read** — `GET registration_client_uri` with the
  registration access token must return the full current metadata including
  `initiate_login_uri` (3rd-Party-Init plan,
  `ValidateInitiateLoginUriInConfigurationResponse`). PUT/DELETE exist
  (`client_registration.rs:649/:669/:833`); verify DELETE is 204 and warning-free.
- **C4. Advertised open registration.** Discovery currently advertises the
  initial-access-token-gated path only (`oidc.rs:130-138`). The suite has no
  token → certification needs the **open** (unauthenticated, per-IP
  rate-limited — `client_registration.rs:556`) path advertised for the
  conformance realm. Make the advertised path per-realm configurable
  (`registration` realm attribute: `open` | `token-gated`), default unchanged
  (token-gated) — existing deployments unaffected.
- **C5. `sector_identifier_uri` fetch + validation.** Pairwise is advertised,
  so `OIDCCRegistrationSectorUri` / `OIDCCRegistrationSectorBad` run: fetch
  the sector document (reuse the SSRF-guarded outbound fetch from the
  client-JWKS path), require the registered `redirect_uris` to be covered,
  reject mismatches with 400 `invalid_client_metadata`, and use the fetched
  sector for pairwise subject computation. Performed at registration and on
  update.
- **C6. Signed userinfo responses.** `OIDCCUserInfoRS256` registers
  `userinfo_signed_response_alg=RS256` and requires a JWT userinfo response
  (discovery must then advertise `userinfo_signing_alg_values_supported`).
  Net-new: userinfo-as-JWT in the userinfo endpoint (signing machinery exists
  in `issuerd-token`), per-client metadata, discovery field. Userinfo content
  itself is unchanged (claims overlay already correct).
- **C7. RP key rotation via `jwks_uri`.** `OIDCCRefreshTokenRPKeyRotation`
  rotates the suite-hosted client JWKS and expects the OP to pick it up.
  Existing kid-miss refetch + cooldown (`client_assertion.rs:26`) should
  satisfy this — verify the cooldown < the suite's 60 s `jwks_refresh_delay`
  and add an integration test.
- **C8. `alg=none` request objects.** Suite self-skips when `none` is not
  advertised (today's expected skips) — keep it that way; do not advertise
  `none`.
- **C9. Tests.** Unit: metadata validation matrix (incl. the 400 cases).
  Integration: full register→read→update→delete lifecycle, sector accept/reject,
  signed userinfo, private_key_jwt with registered `jwks`/`jwks_uri`.

### WS-D — Logout-profile hardening (Phase 4)

Gates: RP-Initiated / Front-Channel / Back-Channel OP certification runs.
Feature core exists (`routes/oidc.rs:5608-5875`, `routes/logout.rs`); this is
spec-fidelity work.

- **D1. First-class `post_logout_redirect_uris`.** Today the post-logout
  target is validated against `redirect_uris` (`oidc.rs:5832-5860`). Add the
  spec'd per-client list: client model field or namespaced attribute (no
  migration needed if attribute), Admin API DTO + SPA display, provision
  YAML, DCR metadata (C1), and logout validation prefers it, falling back to
  `redirect_uris` for existing clients (compat). Suite's
  `QueryAddedToLogoutRedirectUri`/`BadLogoutRedirectUri` must hit the
  no-redirect error path.
- **D2. Parse the per-client logout metadata** introduced in C1
  (`frontchannel_logout_session_required`, `backchannel_logout_session_required`)
  and honor `false` by omitting `iss`/`sid` (we always send them today —
  harmless for the suite, which registers `true`, but truthful).
- **D3. Negative-path review.** Walk the ten RP-initiated modules against
  current behavior: invalid/modified/absent `id_token_hint`, missing params,
  unregistered `post_logout_redirect_uri` → never redirect, render a
  browser-presentable error page (JSON 400 already satisfies the placeholder
  mechanism — confirm per module). Confirm post-logout `prompt=none` fails
  (SSO genuinely destroyed — already true) and `NoState` redirects back
  without state (already true).
- **D4. Optional-but-listed:** dispatch back-channel notifications from the
  SSO idle-timeout cleanup (`oidc.rs:646-650` — currently silent). Not
  required by the suite; decide on merit (spec says OPs *should* notify on
  OP-initiated logout). Also decide whether `LogoutTokenClaims` gains `exp`
  (not spec-required; suite doesn't check).
- **D5. Tests.** Extend `tests/integration/logout_channels.rs`: dedicated
  post-logout list validation, metadata `false` behavior, per-response-type
  logout smoke.

### WS-E — 3rd-Party-Initiated Login (Phase 3, rides on WS-C)

The certification plan (`oidcc-3rdparty-init-login-certification-test-plan`,
2 modules × 6 response types) exercises **only DCR handling**: register
`initiate_login_uri`, echo it in the RFC 7592 read, reject non-https with 400
`invalid_client_metadata`. Fully covered by C1+C3. OP-side runtime behavior
(the RP's `initiate_login_uri` consuming `iss`/`login_hint`/`target_link_uri`)
is an RP concern — **no issuerd endpoint is required for certification**.
Optional follow-up (out of scope here): account-console "sign in via..."
deep-link support.

## 5. Harness & automation work (`tests/conformance/`)

### 5.1 Plan configs & bootstrap

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

### 5.2 Runner

- Extend `scripts/run-conformance.sh`'s `run_plan` list with the full matrix
  from `execution-matrix.md` (13 plan invocations: implicit, hybrid,
  formpost-implicit, formpost-hybrid, dynamic ×6 response types,
  3rdparty ×6, rpinitiated-logout ×6, session ×6, frontchannel ×6,
  backchannel ×6 — 34 invocations total, or grouped where the suite allows
  comma/multi-variant selection).
- Generalize `run-focus.sh` to take `plan[variants]:module` + config (today it
  hardcodes the Basic plan/config).
- Watch total wall-clock: today's 73 modules ≈ 3.5 min suite time; 634
  modules will be ~25–40 min. Acceptable for nightly `heavy.yml`; if it
  outgrows the window, shard by profile across parallel jobs (the stack is
  per-job hermetic, so sharding is trivial) rather than trimming scope.

### 5.3 `oidcc-server-rotate-keys` automation (Dynamic plan)

Pristine-suite constraint forbids patching the runner, and the pristine
runner starts the module without rotating. Approach:

1. In the six Dynamic-plan runs, list `oidcc-server-rotate-keys` in
   `issuerd-expected-failures-dynamic.json` with a comment explaining why
   (manual-step module; covered separately).
2. New `scripts/run-rotation-check.sh` drives the module standalone through
   the suite's REST API (the same public API `export-html.py` already uses):
   create module → poll until `CONFIGURED` (original JWKS snapshotted) →
   call `POST /admin/realms/conformance/keys/rotate` on the OP → start the
   module via the API → require green. This yields real, repeatable evidence
   of OIDCC-10.1.1 (new kid present, old kid retained — issuerd keeps
   rotated keys published until disabled, so both conditions hold).
3. Document in the certification submission that rotation evidence comes from
   the standalone run (the OIDF explicitly allows an attestation fallback for
   this module; our standalone green run is stronger than an attestation).

### 5.4 Coverage documentation

Extend `tests/conformance/COVERAGE.md` with a per-profile section per run
(same table format as today), update the "Known Gaps" table (session
management row disappears once WS-B lands), and keep the header totals in
sync. Update the conformance bullet in `AGENTS.md` and the CI section as
profiles land.

## 6. Phases & exit criteria

| Phase | Workstreams | Profiles unlocked | Exit criteria |
|---|---|---|---|
| **1. Response types** | WS-A | Implicit OP (58), Hybrid OP (102), Form Post implicit+hybrid (160) | 4 new plans green in the hermetic run (static_client); unit+integration tests green; discovery truthful; CHANGELOG entry (nonce tightening + compat attribute) |
| **2. Session management** | WS-B | Session OP (12) | session plan green ×6 response types; no regression in Basic/FormPost; header carve-out reviewed |
| **3. DCR & 3rd-party-init** | WS-C, WS-E | Dynamic OP (127), 3rd-Party-Init OP (12); dynamic_client re-runs of Implicit/Hybrid/FormPost at published counts | 6 dynamic runs green incl. standalone rotation evidence; 3rdparty green ×6; sector + signed-userinfo + jwks_uri integration tests green |
| **4. Logout profiles** | WS-D | RP-Initiated (66), Front-Channel (12), Back-Channel (12) | 18 logout runs green (REVIEW-flagged screenshot modules documented as such in COVERAGE.md) |
| **5. Full-matrix gate + submission prep** | harness §5 | all 11 profiles | single `run.sh` (or CI shard set) executes 634/634 green; COVERAGE.md + AGENTS.md updated; submission package assembled per §8 |

Phases 1→2→3→4 are dependency-ordered (2 technically independent of 1's
token-minting for the `code` runs only — the session plan still runs ×6
response types, so it waits). Phase 5 is continuous integration work once all
profiles are green.

## 7. Risks & open decisions

- **Nonce tightening (A4)** changes existing hybrid behavior. Mitigation:
  realm-attribute escape hatch + CHANGELOG breaking-change note with
  migration path (per the backward-compat policy).
- **Open registration endpoint (C4)** is a deliberate security-posture
  change: unauthenticated client creation, even rate-limited, must stay
  opt-in per realm (default: today's token-gated behavior). Document in
  `docs/`.
- **`session_state` = session id (B1)** mirrors Keycloak but bakes the
  session id into another RP-visible value. Acceptable (already exposed as
  `sid`); revisit if we ever randomize `sid` per token.
- **Iframe JS compatibility (B3)**: HtmlUnit executes the page; use ES5-grade
  JS and string comparison only (no `crypto.subtle`, no modules, no fetch).
  Verify early with a focused run before building B5/B6 on top.
- **Suite runtime growth** (§5.2): if a full matrix exceeds the nightly
  window, shard by profile in `heavy.yml`; never trim modules.
- **Published-count reconciliation** (§3): Implicit/Hybrid/FormPost published
  counts assume dynamic_client. Static runs (56/99) are the Phase-1 gate;
  certification-grade runs happen after Phase 3.
- **`oidcc-server-rotate-keys`** can never pass inside the pristine unattended
  runner (upstream acknowledges this). The standalone-run evidence path (§5.3)
  is the resolution; flag it in the submission narrative.
- **Upstream suite drift**: plans/counts above are pinned to
  `release-v5.2.4`. Re-validate the matrix when bumping the suite tag.

## 8. Certification submission checklist (per profile, at Phase 5)

1. Full green run of the profile's plan(s) in the hermetic environment,
   `release-v5.2.4`, exported JSON + HTML reports archived under
   `results/` (and attached to the release as the `conformance-evidence`
   artifact — the release pipeline already does this).
2. REVIEW-flagged modules (logout error pages, `prompt=login`, `max-age=1`,
   unregistered-redirect) visually verified; screenshots retained.
3. Profile submission on openid.net/certification: plan export + logs +
   deployment description; rotation evidence per §5.3 for Dynamic OP.
4. Update public docs (`docs/`, README badge list) only after the OIDF lists
   the profile.

## 9. References

- Suite source (pinned): `tests/conformance/conformance-suite/` @ `release-v5.2.4`
- Current results: `tests/conformance/COVERAGE.md`
- Harness guide: `tests/conformance/README.md`
- Run matrix produced by this plan: [`execution-matrix.md`](./execution-matrix.md)
- OIDF profiles & published counts: <https://openid.net/certification/openid-connect/>
- OIDCC plan sources: `conformance-suite/src/main/java/net/openid/conformance/openid/OIDCC*TestPlan.java`
