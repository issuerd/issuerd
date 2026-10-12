# Review Plan — `feat/oidc-certification-expansion`

> Goal: an independent review of all 33 branch commits (M1–M4 server features
> + conformance harness + docs) BEFORE merge. Each track reports findings with
> a severity (blocker/major/minor/nit) and file:line evidence. Reviewers are
> read-only agents; fixes are out of scope for this stage (they land as
> separate commits after triage).

## Scope

`git diff main..HEAD` — crates/ (issuerd-core, issuerd-protocol,
issuerd-token, issuerd-server, issuerd-admin-api), tests/conformance/,
certification/, docs/, AGENTS.md, CHANGELOG.md, webclientsrc.

## Tracks

### T1 — Protocol correctness (OIDC Core/Discovery/Session/Logout)

- Response-type matrix: fragment/form_post assembly for `id_token token`,
  `code token`, `code id_token token`; `at_hash`/`c_hash` correctness and
  alg-awareness; `expires_in`/`token_type` fields; no refresh token on
  implicit issuance; sub consistency across endpoints.
- Nonce rule: required iff an id_token is issued from the authorization
  endpoint; `code token` without nonce succeeds; the
  `compat.nonceless_hybrid` realm attribute; behavior through PAR/JAR.
- `claims.id_token`/`claims.userinfo` evaluation: mapper precedence,
  no-overwrite rule, boundaries (refresh/device/CIBA — documented).
- Session Management: session_state = sid; companion-cookie flags
  (SameSite=None; Secure under TLS); the iframe postMessage protocol vs
  §4.2 (reply to e.origin, "error" on malformed); cookie cleared on every
  logout path; discovery field.
- Logout: `post_logout_redirect_uris` takes precedence over redirect_uris;
  `*_session_required=false` drops iss/sid; `LogoutTokenClaims.sid` is
  Option; the 200 confirmation page.
- DCR: RFC 7591 translation (all fields), 7592 read/echo, fragment
  rejection, `none`-alg rejection, sector validation, client identification
  from assertions (iss/sub), cache headers on error responses, the openid
  exemption in both scope checks.

### T2 — Security

- `[outbound_http] allow_private_addresses`: blast radius (only guarded
  fetches? the dispatcher?), default off, no silent enablement path.
- SSRF guard without the flag: request_uri / sector / jwks.url — private
  addresses blocked; DNS resolve-then-connect race?
- The `issuerd_session_state_*` companion cookie: non-HttpOnly,
  SameSite=None — what XSS on any RP origin could do with it; correlation;
  no writes keyed by the cookie (read-only path).
- DCR: the open endpoint's strip list covers ALL new dangerous attributes
  (jwks, logout URIs, request_uris, sector, algs); the token-gated path
  allows no privilege escalation; registration access token rotation/burn.
- Identification from the unverified JWT: no client_id confusion (iss≠sub
  rejected; verification after identification unchanged).
- Per-client alg: a pinned alg with no key → 500 (no silent downgrade);
  alg=none refused; HS* rejected in DCR.
- Error pages: no internal detail leakage; JSON error bodies carry no
  secrets; no open redirect via error redirects (all errors go to the
  validated redirect_uri).
- Log hygiene: the new log sites carry no secrets/PII (dylint is green —
  but verify by eye).

### T3 — Backward compatibility (hard requirement, AGENTS.md)

- Nonce tightening: the escape hatch works; CHANGELOG marks it breaking.
- Logout 204→200: clients expecting 204 (the SPA logout API is a separate
  endpoint?); documented.
- Discovery: new fields are additive; `GrantType::Implicit` stays
  unparseable at the token endpoint (documented unreachable arm); JSON
  snapshot compatibility (`LogoutTokenClaims.sid` Option + serde default;
  Realm attributes).
- DCR: the Keycloak response shape kept (`registrationAccessToken` in
  place); existing clients without the new attributes keep working
  (redirect_uris fallback).
- Migrations: none (everything rides attributes) — confirm.

### T4 — Conformance-evidence integrity

- Expected skips/failures: globs no wider than necessary (condition:"*" +
  current-block:"*" — justified?); no "expected" entries masking real bugs.
- REVIEW modules: placeholder filling is legitimate (real pages); the
  logout negative modules genuinely render an error page.
- Sidecar: the rotation really happens between CONFIGURED and start; the
  RS256 choice doesn't fake the evidence.
- Configs: the dedicated clients isolate the profiles correctly; bootstrap
  is deterministic; config secrets are test-only.
- `run.sh` exit 0 reproducible from a clean state (down -v → run).

### T5 — Tests and docs

- Every new behavior branch has unit+integration coverage; negative paths
  (400/401) covered; the compat attribute covered; both cookie-flag modes.
- CHANGELOG: every user-visible change is listed (check completeness
  against the diff); Keep-a-Changelog format.
- AGENTS.md/docs/OpenAPI in sync with the code (openapi.json regenerated
  after the login-context change — does the openapi-sync CI job pass?);
  examples regenerated.
- webclientsrc: lint/test/build green; branding is XSS-safe (URL
  validation).

## Execution order

1. T1–T5 in parallel (read-only agents).
2. Findings merged by severity; every major+ gets its own fix commit (or a
   journal entry with a rejection rationale).
3. Final gate rerun if code moved; journal + review closeout.

---

## Round 2 (2026-10-12) — verification + regression pass

Round 1 produced 19 fix/docs commits. Round 2 reviews the review:

- **R1 — Fix verification.** Every round-1 finding ↔ its fix commit
  (`fdabf80`, `8c9b333`, `3ac5c00`, `c8193f5`, `18934c8`, `72ec83c`,
  `742fbbc`, `6a8e146`, `06aaa42`, `88e835c`, `8b54962`): does the fix
  actually close the finding (not cosmetically), and is it complete across
  all call sites?
- **R2 — Regression on the fix diffs.** Adversarial re-read of the fix
  commits themselves for NEW bugs (marker-stamping semantics, PUT policy
  re-application, cookie-fallback call sites, the token_handler wrapper,
  the run.sh down -v ordering, the in-run rotation sidecar).
- **R3 — Blind spots of round 1.** New lens: provision-YAML coverage of the
  new client metadata, admin SPA surface, cluster/multi-node interactions
  (discovery-cache version blindness), storage-backend attribute semantics,
  published-trait consumers, and any first-review misses.
