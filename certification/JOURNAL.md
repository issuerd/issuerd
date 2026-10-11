# Certification Expansion — Handoff Journal

> **Purpose:** this journal is the single source of truth for work-in-progress
> on the certification expansion. It exists so that **any agent or human can
> pick the work up cold** after a break, context loss, or handoff — without
> re-reading chat history or re-deriving state.
>
> **Rules (binding, see `README.md` §6 "Working rules"):**
> 1. **Commit often.** Every completed task (or coherent half-task) is its own
>    commit on `feat/oidc-certification-expansion`. Never end a working session
>    with uncommitted changes.
> 2. **Journal before you stop.** Before ending any working session — and after
>    every commit that changes state — update this file: the status tables, the
>    "Next action" line, and a dated log entry with the commit hash.
> 3. **Everything lives in `./certification/`.** Plans, matrices, this journal,
>    scratch analyses that are still decision-relevant. If it's not here, it
>    doesn't survive handoff. (Test evidence still lands in
>    `tests/conformance/results/` as before — reference it, don't copy it.)
> 4. **Write for a reader with zero context.** State commands verbatim, name
>    files with full repo-relative paths, record *why* decisions were made.

---

## Where we are (read this first)

- **Branch:** `feat/oidc-certification-expansion` (from `main` @ plan baseline).
- **Suite tag:** `release-v5.3.2`.
- **🎉 FULL MATRIX GREEN — gate v10 (2026-10-11, `run.sh` exit 0):** all 43
  plan invocations pass with 0 failures / 0 unexpected warnings. Evidence:
  `tests/conformance/results/html-reports-20261011-193753`. Rotation evidence:
  `run-rotation-check.sh` PASSED with a real admin-API rotation.
- **Milestones M1–M5 all DONE.** M6 (submission prep) remains: the
  certification-grade dynamic_client re-runs of Implicit/Hybrid/FormPost
  (published counts 58/102/196 assume that variant) and the OIDF submissions
  themselves.
- **Cumulative internal gate: 612/612 executed profile module executions
  green** (43 invocations, exit 0). The published 634 counts the suite's
  listing+1 reporting convention plus the dynamic_client-only modules
  (`oidcc-id-token-signature`, `oidcc-idtoken-unsigned`) that static runs mark
  N/A — the M6 certification-grade dynamic re-runs cover them.

## Status by milestone

Milestones are defined in `certification/README.md` §5 (implementation order).
Legend: ⬜ not started · 🔶 in progress · ✅ done.

| Milestone | Scope | Status | Evidence |
|---|---|---|---|
| M1 | Client metadata & registration foundation (DCR RFC 7591/7592 plumbing, logout URIs, `initiate_login_uri`) | ✅ | `4410659` + gate (3rd-party 12/12) |
| M2 | Authorization response types + nonce rules | ✅ | `73928df` + fixes; gate v10 |
| M3 | Session management (`session_state`, `check_session_iframe`) | ✅ | `97b4080`; session ×6 green |
| M4 | Registration-backed deep features (sector fetch, signed userinfo, `jwks_uri` verification) | ✅ | `c9c6fd5`; dynamic ×6 green |
| M5 | Harness & rotation automation | ✅ | matrix in `run-conformance.sh`; sidecar validated live |
| M6 | Full-matrix gate + submission prep | 🔶 | gate v10 green; remaining: dynamic_client certification reruns + OIDF submissions |

## Status by profile (634 module executions total)

| Profile | Tests | Suite green? | Notes |
|---|---|---|---|
| Config OP | 1 | ✅ (v5.3.2, gate v10) | |
| Basic OP | 36 | ✅ (v5.3.2, gate v10) | |
| Form Post OP (basic leg) | 36 | ✅ (v5.3.2, gate v10) | |
| Implicit OP | 58 | ✅ static (55 modules; published count assumes dynamic_client) | certification-grade dynamic rerun is M6 |
| Hybrid OP | 102 | ✅ static (97 modules) | same M6 note |
| Form Post OP (implicit+hybrid legs) | 160 | ✅ static (55+97) | same M6 note |
| Dynamic OP | 127 | ✅ ×6 (rotate-keys: expected in-plan failure + sidecar PASSED) | |
| 3rd Party-Init OP | 12 | ✅ ×6 | |
| RP-Initiated OP | 66 | ✅ ×6 | |
| Session OP | 12 | ✅ ×6 | |
| Front-Channel OP | 12 | ✅ ×6 | |
| Back-Channel OP | 12 | ✅ ×6 (2 expected TLS-header warnings/run — proxy-header harness artifact) | |

## How to resume (verbatim commands)

```bash
git checkout feat/oidc-certification-expansion
git log --oneline main..HEAD          # what has landed on this branch
cat certification/JOURNAL.md          # this file — status + next action

# Run the current conformance gate (3 passing plans):
cd tests/conformance && ./run.sh

# Focused single-module debugging:
cd tests/conformance && ./run-focus.sh <module-name>

# Repo gates that must stay green at every commit:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --lib
```

## Log

### 2026-10-11 — plan baseline + suite bump to v5.3.2

- Commit `1ec2070` — plan documents created: `certification/README.md`
  (master plan), `certification/execution-matrix.md` (run matrix), verified
  against suite `release-v5.2.4`.
- Suite clone moved `release-v5.2.4` → `release-v5.3.2` (latest tag; fetched
  from gitlab.com/openid/conformance-suite). **Full `run.sh` against v5.3.2:
  ALL GREEN** (Config 39 conditions; Basic 36/1858; FormPost 36/2010; 0
  failures, 0 warnings — identical to the v5.2.4 baseline; evidence in
  `tests/conformance/results/html-reports-20261011-075455`). Suite-tag
  references updated everywhere: `tests/conformance/README.md`, `run.sh`,
  `COVERAGE.md`, `.github/workflows/heavy.yml`, `AGENTS.md`.
- **Module-count re-verification at v5.3.2: unchanged.** All 13 OIDCC OP plan
  classes byte-identical between the tags; `execution-matrix.md` counts stand
  as written. Noted behavioral deltas (no count impact): unsolicited-nonce
  id_tokens are now a FAILURE (`ValidateIdTokenNonce` fix — issuerd only
  echoes requested nonces; covered by the green run); lenient JWKS parsing;
  REVIEW now outranks WARNING in module status.
- Plan restructured into **convergence-ordered milestones M1–M6**
  (`certification/README.md` §5): M1 client-metadata/DCR foundation → M2
  response types & nonce → M3 session management → M4 deep registration
  features → M5 harness/rotation automation → M6 full-matrix gate. Each
  milestone turns profiles green immediately (see the convergence table).
- Working rules adopted (commit often, journal before stopping, everything in
  `./certification/`) — `certification/README.md` §6; journal file created.
- Decisions recorded so far (details in README §8): nonce-tightening gets a
  realm-attribute escape hatch; open registration stays opt-in per realm;
  `session_state` mirrors Keycloak's session-id approach; iframe JS is
  ES5-grade string comparison only (HtmlUnit); `oidcc-server-rotate-keys`
  evidence comes from a standalone suite-API-driven run.
- **Next:** begin M1 — C1 (RFC 7591 metadata acceptance in
  `crates/issuerd-server/src/routes/client_registration.rs`).

### 2026-10-11 — M1 complete: 3rd-Party-Init OP green (85/634)

- Commit `4410659` — M1 server-side (delegated to a coder subagent, all repo
  gates green): new `crates/issuerd-server/src/client_metadata.rs`
  (constants + typed accessors); RFC 7591 request translation in
  `client_registration.rs` (client_name/grant_types/response_types/
  token_endpoint_auth_method/scope/jwks/jwks_uri/subject_type/
  sector_identifier_uri/initiate_login_uri/post_logout_redirect_uris/
  front+backchannel fields/logo/policy/tos/signed-alg fields; https and
  allowlist validation with 400 `invalid_client_metadata`); additive RFC
  response fields (`registration_access_token`, `registration_client_uri`,
  `client_id_issued_at`, `client_secret_expires_at`, `client_secret`) + full
  metadata echo on create/read/update; `post_logout_redirect_uris` allowlist
  preferred over `redirect_uris` in logout validation; `sid` omitted from
  logout tokens / `iss`+`sid` from front-channel URLs when the per-client
  `*_session_required` attribute is `false`. 23 new unit tests; integration:
  `dynamic_client_registration.rs` +3, `logout_channels.rs` +3; full
  integration suite 375/375.
  Notable sub-decisions by the implementer (recorded in the commit report):
  `response_types` attribute stores a JSON array (space-joining is lossy for
  multi-token types); `client_id_issued_at` stamped on every DCR create;
  Keycloak spelling wins when both spellings of a field arrive.
- Commit `593379a` — harness: bootstrap enables
  `dynamic_client_registration_enabled` on the conformance realm, pre-
  registers logout URIs on both static clients, mints an unlimited
  initial-access token into `/results/initial-access-token.txt`; config
  template `configs/issuerd-3rdparty-init-op.json`; run-conformance runs the
  3rd-party plan once per response type.
- Commit `281f93b` — fix: the 3rd-party/dynamic/logout plans PIN
  server_metadata/client_auth/response_mode; only `response_type` (and
  `client_registration` on logout plans) may be passed. First gate attempt
  failed plan creation on exactly this; matrix + runner corrected.
- **Gate result:** `run.sh` exit 0 — existing 3 plans unchanged-green, plus
  6/6 3rd-party runs PASSED (2 modules each; evidence
  `tests/conformance/results/html-reports-20261011-092241`).
- **Decision (supersedes README WS-C C4):** no open-registration changes —
  the suite's `client.initial_access_token` + issuerd's unlimited initial
  access tokens cover dynamic registration; the open endpoint and its rate
  limit are untouched. README updated.
- Sector `sector_identifier_uri` fetch+validation turned out to already exist
  (`issuerd_core::pairwise::validate_pairwise_subject_config`, wired into
  registration) — M4 scope shrinks to sector *confirmation tests* + signed
  userinfo + `jwks_uri` verification.
- **Next:** M2 — response types & nonce (see "Where we are").

### 2026-10-11 — M2 in flight: implicit/hybrid green, logout fixes applied

- Commit `73928df` — M2 server-side (agent-2): all six OIDC response types
  accepted at the authorization endpoint (bare `token` still rejected);
  unified `mint_authorization_artifacts` mints code/access/id_token per leg
  from both the SSO-resume and fresh-login paths; alg-aware `at_hash`/`c_hash`
  wired; nonce REQUIRED for id_token-bearing response types (303
  fragment-delivered `invalid_request` redirect; realm attribute
  `compat.nonceless_hybrid=true` is the escape hatch, default off);
  discovery lists all six response types + `implicit` grant. PAR/JAR paths
  share the one acceptance+nonce gate. Integration: 12 new tests in
  `tests/integration/implicit_hybrid.rs`, full suite 387/387.
- Commit `367627b` — M2 harness: implicit/hybrid/formpost-implicit/
  formpost-hybrid configs cloned from the basic browser profile; three logout
  plan configs with a logout-page placeholder task; runner wired.
- **Gate run 1 findings** (exit 1, expected — fixes followed):
  - Implicit 55 modules 0F/3W; FormPost-implicit same; **Hybrid 97 modules
    0F/0W; FormPost-hybrid 97 0F/0W** — hybrid fully green on first attempt.
  - The 3 implicit warnings: `VerifyScopesReturnedInAuthorizationEndpointIdToken`
    — the pure-implicit id_token carried only IdToken-targeted mapper claims;
    with no access token, userinfo is unreachable so the id_token must carry
    the full scope set (OIDCC-5.4).
  - RP-initiated logout: 6 failures ×6 runs. Root cause 1: the shared static
    clients carried `frontchannel_logout_uri` (M1 bootstrap), so every logout
    rendered the front-channel interstitial and the suite counted the
    (unserved) iframe request as FAILURE. Root cause 2: the interstitial's
    1.5s `setTimeout` continue never fires under the suite's HtmlUnit
    WebRunner (no timer pumping after page load) → 240s hangs.
  - Front-channel plan: main module hung 240s → UNKNOWN (same timer issue).
- Fixes: commit `579c4bf` (agent-2) — pure-implicit id_token overlay now
  unions IdToken+UserInfo targets (`build_claims_overlay_for_targets`,
  regression-guarded for hybrid/code); logout without redirect target renders
  a 200 "signed out" confirmation page instead of bare 204 (placeholder
  modules get a capturable page). Commit `944bbf1` (harness) — dedicated
  per-plan logout clients (`conformance-client-rpi/-fc/-bc`), base clients
  cleaned, front-channel config clicks the interstitial's Continue link.
- Gate run 2 in progress at commit `944bbf1`+`579c4bf`.
- **Next:** evaluate gate 2; close out M2 (journal + COVERAGE) when green.

### 2026-10-11 (evening) — M2/M3/M4 landed; gate v5 (full matrix) in flight

- Gate runs 2–4 iterated on the logout/session plans. Fixes that landed:
  - `579c4bf` — pure-implicit id_token overlays union IdToken+UserInfo
    mapper targets; logout without a redirect target renders a 200
    confirmation page (was bare 204 — the suite's screenshot-placeholder
    modules need a rendered page).
  - `944bbf1` — dedicated per-plan logout clients (rpi/fc/bc): the
    RP-initiated plan FAILs on front-channel iframe calls to unserved paths,
    so each logout profile gets its own static client. Front-channel config
    clicks the interstitial's Continue link (see WebRunner note below).
  - `432fbe3` — `claims.userinfo` entries ride the pure-implicit id_token.
  - `ba7a95c` — `claims.id_token` section evaluated on all
    authorization-endpoint id_tokens + token-endpoint code grant (the
    claims-essential module sends the id_token section for implicit/hybrid).
  - `78ba43b` + `1c832cf` — `[outbound_http] extra_ca_bundle` config knob
    (all outbound HTTPS: back-channel dispatch, broker, jwks.url, sector
    fetch); the conformance OP mounts the stack CA. Without it the
    back-channel logout POST failed TLS verification and the module hung.
  - `9e6c7d8` — dynamic-plan harness (config + expected-failures for
    rotate-keys), session-config wait task, expected-warnings glob fix
    (`configuration-filename` matches the full passed path).
- **WebRunner mechanics (important for any future browser-page work):** the
  suite's Selenium driver CLOSES when the matched task list completes —
  pending JS timers die with it. Any OP/suite page that continues via
  `setTimeout` needs either a click task or a `["wait","contains",…]` task
  keeping the page open (session verify pages, our logout interstitial).
- **Session plan root cause chain:** session_state in the authorization
  response worked on first try; the stall was purely the WebRunner/timer
  interaction above.
- M4 server-side (`c9c6fd5`): per-client `id_token_signed_response_alg`
  (strict — no fallback), signed userinfo (`application/jwt`), JAR-by-
  reference (`request_uri`: pre-registered exact-match list, SSRF-guarded
  fetch, 64 KiB cap, extra-CA trust), dual `token id_token`/`id_token token`
  discovery spelling, sector + jwks-rotation confirmations. 411 integration
  tests green.
- M5.1: `run-rotation-check.sh` + `scripts/rotate-check.py` — standalone
  suite-API-driven rotation evidence (create module → CONFIGURED → admin
  key rotation → start → require PASSED). NOT yet executed against the live
  stack — validate after gate v5.
- **Next:** evaluate gate v5; close out M2 (journal + COVERAGE) when green.

### 2026-10-11 (late) — M2/M3/M4 nearly green; dynamic-plan debugging campaign

Gate iterations 2–5 + live debug against a long-running stack:

- **Session OP root cause + fix:** the suite drives the browser DIRECTLY to
  its own session_verify pages; `BrowserControl.goToUrl` only automates URLs
  matching a top-level `browser[].match` — the OP-side entry never covered
  them, so the dance page never loaded. The session config gained a
  suite-side browser entry that waits for the dance's `*session_result`
  navigation (the WebRunner closes its driver — and its pending JS timers —
  when the task list completes). Result: session plan PASSED (code), 1.4s.
- **Dynamic OP debug chain** (each layer found by reading suite module logs
  via the suite's `/api/log/{id}` from the test-runner container):
  1. `invalid_scope` on auth requests — DCR clients seeded from realm
     defaults lack `openid`; fixed by exempting the `openid` protocol marker
     in the authorization scope check (`60f3953`, authorization.rs).
  2. `invalid_client` 400 at the token endpoint — the suite sends
     private_key_jwt WITHOUT a `client_id` form field; RFC 7523 allows
     identification from the assertion. `e294dd1` adds
     `resolve_form_client_id` (iss/sub, iss≠sub rejected).
  3. `invalid_scope` on refresh — same openid exemption needed in
     `TokenRequest::validate` (token.rs), `5c0ecdd`.
  4. `CheckTokenEndpointCacheHeaders` — token-endpoint ERROR responses lacked
     no-store/no-cache; `token_handler` now decorates (same commit).
  5. `oidcc-redirect-uri-regfrag` — DCR now rejects fragment-bearing
     redirect_uris with 400 invalid_redirect_uri (`355011e`).
  6. SSRF-guarded fetches (client jwks_uri / sector docs / request_uri
     objects) refused the all-private conformance network — new
     `[outbound_http] allow_private_addresses` knob (`86602f6`, default off,
     enabled in the rig).
  7. `oidcc-refresh-token`'s SECOND registration needs
     `client2.initial_access_token` — added to the dynamic config.
  8. Login-page client branding (`fab3fc2`): login-context exposes
     client_logo/policy/tos URIs (M1 attributes); the static login page
     renders them (http(s) only). The logo/policy/tos modules fill their
     screenshot placeholders via the login task's
     update-image-placeholder-optional wait (dynamic config only).
  9. Skips bookkeeping: `issuerd-expected-skips-dynamic.json` (the dynamic
     plan's self-skipper is `oidcc-request-uri-unsigned`, a different name
     than the basic plans') + `oidcc-idtoken-unsigned`; rotate-keys is an
     expected FAILURE in-plan (`issuerd-expected-failures-dynamic.json`,
     glob-matched config filename) with real evidence from the sidecar.
- **Rotation sidecar validated live** (`run-rotation-check.sh`): the module
  finishes PASSED with a real admin-API rotation. Detail: rotate with
  `{"algorithm":"RS256"}` — the suite's verify condition can't parse Ed25519
  (OKP) keys, and per-alg rotation keeps the EdDSA default active.
- Dynamic plan (code) after the campaign: all modules green/REVIEW except
  the expected rotate-keys failure; refresh-token 162 conditions green.
- **Next:** gate v6 (full 41-invocation matrix, fresh stack); then M6
  closeout docs (COVERAGE/README/AGENTS) and updating
  `certification/execution-matrix.md` statuses.

### 2026-10-11 (final) — FULL MATRIX GREEN (gate v10, exit 0)

- All 43 plan invocations pass: Config, Basic, FormPost-basic, Implicit (55),
  Hybrid (97), FormPost-implicit (55), FormPost-hybrid (97), RP-initiated ×6,
  Front-channel ×6, Back-channel ×6 (2 expected TLS-header warnings each),
  Session ×6, 3rd-party ×6, Dynamic ×6 (rotate-keys expected failure;
  sidecar PASSED).
- Final debug-chain commits after gate v5: `60f3953` (openid scope exemption,
  authorization), `e294dd1` (client identified from private_key_jwt
  assertion), `5c0ecdd` (openid exemption at token endpoint + no-store on
  error responses), `355011e` (DCR rejects fragment redirect_uris),
  `86602f6` (SSRF-guard allow_private_addresses knob), `fab3fc2`
  (login-page client branding), plus harness bookkeeping (`8cc877b`,
  `13863de`, `da4f1cd`, `83c67ff`, `e743274`, `99f500c`).
- **M6 remaining:** dynamic_client certification-grade re-runs of
  Implicit/Hybrid/FormPost (published counts assume that variant; the static
  runs cover 55/97/36+97 legs) and the OIDF submissions per README §9.

### 2026-10-12 — branch review + fixes (pre-merge)

- Five parallel read-only review tracks (plan: `certification/REVIEW.md`)
  over `git diff main..HEAD`: protocol correctness, security, backward
  compatibility, evidence integrity, tests/docs. **No blockers.** 7 major +
  ~25 minor/nit findings.
- **Majors, all fixed:**
  - RFC 7592 PUT re-applies the open-registration policy for open-created
    clients (`dcr.policy=open` marker; logout-URI scheme validation on the
    open path) — `fdabf80`.
  - Module-count bookkeeping corrected everywhere: counts are the exact
    `[1:N]` listings (the runner prints listing+1; published OIDF counts mix
    conventions). Dynamic = 23/22/22/23/18/19 = 127 (= published).
    Implicit/Hybrid static = 54/96 listed; published 58/102 assume
    dynamic_client (static N/A: id-token-signature ×2/×3 + idtoken-unsigned
    ×2/×3). Basic/FormPost-basic: 35 listed.
  - Journal headline now reads **612/612 executed green** (22 published-count
    modules are deferred to the M6 dynamic re-runs).
  - run.sh always starts from a clean slate (`down -v` first): a reused
    stack's suite DB silently mixed stale plans into the exported evidence.
  - Rotation evidence now runs inside every standard `run.sh` (tee'd into
    results/) — CI produces and archives it via heavy.yml for free.
  - `run-focus.sh` generalized (any plan[variants]:module + config; dynamic
    configs auto-render the token) — the previously dropped M5.3.
  - `docs/client-integration.md` response-types bullet rewritten (was
    contradicting the headline feature).
- **Minors fixed in the same pass:** `token id_token` accepted/normalized in
  DCR + bare `token` rejected (`3ac5c00`); shared fragment-default rule for
  pre-parse errors (`8c9b333`); login-API mint failure returns a generic
  `server_error` body (`c8193f5`); debug `eprintln!` removed (`18934c8`);
  RFC 7592 responses carry no-store/no-cache (`72ec83c`); companion-cookie
  name falls back to the realm id for cookie-unsafe realm names (`742fbbc`);
  account-console cookie-clear arms unit-tested (`6a8e146`); stale doc
  comments (`06aaa42`); CHANGELOG: breaking marker on the nonce tightening,
  openid-exemption + no-store entries, fragment-rejection explicitness,
  merged duplicate Added sections, published-trait note; KEYCLOAK_DIFFS:
  post_logout_redirect_uris + session_state notes; dead override blocks and
  stale prose cleaned.
- **Accepted with rationale (journaled, not fixed):**
  - `check_session_iframe` answers postMessage from any origin (no
    expected-origin allowlist, spec-MUST clause): Keycloak-parity; impact
    negligible-by-design (122-bit UUID session ids; `changed` for absent and
    mismatch alike). Disclosed in README §9 for the submission narrative.
  - Out-of-band session teardowns flip the iframe verdict only at the next
    browser-present event (cookie-only design; Keycloak parity; suite only
    exercises browser-present logout). README B5 updated to as-built.
  - Alg-pinning TOCTOU (keyset reload mid-issuance could sign with a
    fallback alg): one-request wide, reloads are atomic swaps; accepted.
  - Logout confirmation page renders in the default locale (the interstitial
    pattern; `login.signedOut` bundles exist) — i18n when the page is next
    touched.
- Final gate rerun follows (code moved after gate v10).

### 2026-10-12 — gate v11: full matrix green WITH review fixes (exit 0)

Final validation after the review batch: all 43 invocations pass, the
rotation sidecar ran inside the standard run ("PASSED with a real key
rotation", archived at `results/rotate-check-output.log`), the evidence
tarball carries no credentials, and the stack started from a clean slate.
Evidence: `tests/conformance/results/html-reports-20261011-221213`.
Branch is merge-ready.
