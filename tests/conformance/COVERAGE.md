# Issuerd OIDC Conformance Test Coverage

> Latest full run: **2026-10-31** (suite `release-v5.3.3`) — the full OP certification matrix across 43 plan invocations: **all plans OK, 0 unexpected failures and 0 unexpected warnings**. The 24 failures are the declared Dynamic expected set (the three branding modules per response type plus in-plan key rotation), and the 12 warnings are the declared Back-Channel proxy-header set. Standalone `oidcc-server-rotate-keys` finished **PASSED** with a real admin-API rotation. The run used the hermetic pristine environment: isolated network, local-CA TLS, and an unpatched suite JAR/runner. Current evidence: `results/html-reports-20261031-033356/index.html` (43 plan reports and matching HTML zips); raw logs are in `results/`.
> Conformance Suite version: release-v5.3.3
>
> The detailed per-module tables below preserve the earlier 2026-10-11 baseline analysis. Use the current run's raw logs for exact current condition counts.

## Test Environment

- **Hermetic docker network** (`internal: true`, no internet): bind9 is the only DNS (authoritative for `conformance.test` only, no recursion/forwarders → external names refused instantly)
- **Run command**: `docker compose up` (or `run.sh`) — builds images, generates the PKI, bootstraps, runs all plans, exports reports; see README.md
- **Issuerd OP**: Docker container (canonical root Dockerfile), **native rustls TLS** on `https://op.conformance.test:8443`, in-memory storage
- **Conformance Suite Server**: Docker container (`Dockerfile.suite`), **pristine JAR** built in-docker from untouched upstream sources; **native Spring Boot HTTPS** on `https://suite.conformance.test:8443`; the only deviation from stock is the local root CA imported into the JVM truststore at container start
- **TLS everywhere**: local root CA (`pki/gen-certs.sh`) issues the OP and suite certs; no TLS-terminating or intercepting proxies anywhere; runner scripts are the pristine upstream ones, mounted from the clone
- **MongoDB**: Docker container (`mongo:6.0`)
- **Test Runner**: Docker container (`Dockerfile.runner`, host-UID, deps baked in)

## Realm Configuration

- Realm: `conformance` (with `dynamic_client_registration_enabled` — the Dynamic / 3rd-Party-Init plans register via DCR with a bootstrap-minted unlimited initial access token)
- User: `conformance-user` / `conformance-password`
- Client 1: `conformance-client` / `conformance-secret`
- Client 2: `conformance-client-2` / `conformance-secret-2`
- Logout-profile clients (per-plan isolation — the RP-Initiated plan fails on front-channel calls it doesn't expect): `conformance-client-rpi` (post_logout_redirect_uris only), `conformance-client-fc` (+ `frontchannel_logout_uri`, session-required), `conformance-client-bc` (+ `backchannel_logout_uri`, session-required)
- Redirect URIs: `https://suite.conformance.test:8443/test/a/issuerd/callback`; post-logout: `…/post_logout_redirect`

## Test Plans

### 1. Config OP (`oidcc-config-certification-test-plan`)

Validates discovery metadata and JWKS. Requires no browser automation.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 2 test modules, 39 successes, 0 failures, 0 warnings (0.3s)

| Module | Result | Notes |
|--------|--------|-------|
| `oidcc-discovery-endpoint-verification` | **PASSED** | 39/39 conditions passed (includes RFC 8414 metadata schema validation, issuer-URL syntax, scopes/locales syntax checks) |

**Summary**: **PASSED** — Discovery, issuer URL, JWKS endpoint, and all metadata fields validated successfully.

### 2. Basic OP (`oidcc-basic-certification-test-plan`)

Validates authorization code flow with `response_type=code`.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 36 test modules, 1858 successes, 0 failures, 0 warnings (47.3s)

| Module | Result | Notes |
|--------|--------|-------|
| `oidcc-server` | **PASSED** | 55 SUCCESS, 0 FAILURE |
| `oidcc-response-type-missing` | **PASSED** | 30 SUCCESS, 0 FAILURE — the suite's `update-image-placeholder-optional` browser command resolves the error-page placeholder with the real page source at runtime; no human-review flag |
| `oidcc-userinfo-get` | **PASSED** | 52 SUCCESS, 0 FAILURE |
| `oidcc-userinfo-post-header` | **PASSED** | 53 SUCCESS, 0 FAILURE |
| `oidcc-userinfo-post-body` | **PASSED** | 51 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | **PASSED** | 26 SUCCESS, 0 FAILURE |
| `oidcc-scope-profile` | **PASSED** | 55 SUCCESS, 0 FAILURE — optional profile claims from bootstrap user attributes; `updated_at` emitted from real per-user modification tracking (migration `006_users_updated_at.sql`) |
| `oidcc-scope-email` | **PASSED** | 57 SUCCESS, 0 FAILURE |
| `oidcc-scope-address` | **PASSED** | 54 SUCCESS, 0 FAILURE |
| `oidcc-scope-phone` | **PASSED** | 54 SUCCESS, 0 FAILURE |
| `oidcc-scope-all` | **PASSED** | 55 SUCCESS, 0 FAILURE — optional profile claims from bootstrap user attributes; `updated_at` emitted from real per-user modification tracking (migration `006_users_updated_at.sql`) |
| `oidcc-alternate-happy-flow` | **PASSED** | 57 SUCCESS, 0 FAILURE |
| `oidcc-display-page` | **PASSED** | 46 SUCCESS, 0 FAILURE |
| `oidcc-display-popup` | **PASSED** | 46 SUCCESS, 0 FAILURE |
| `oidcc-prompt-login` | **REVIEW** | 80 SUCCESS, 0 FAILURE, 0 WARNING — test completed; flagged for manual review by conformance suite (session re-auth path) |
| `oidcc-prompt-none-not-logged-in` | **PASSED** | 32 SUCCESS, 0 FAILURE |
| `oidcc-prompt-none-logged-in` | **PASSED** | 79 SUCCESS, 0 FAILURE |
| `oidcc-max-age-1` | **REVIEW** | 82 SUCCESS, 0 FAILURE, 0 WARNING — test completed; flagged for manual review by conformance suite (forced re-auth path) |
| `oidcc-max-age-10000` | **PASSED** | 82 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-unknown-parameter-succeeds` | **PASSED** | 46 SUCCESS, 0 FAILURE |
| `oidcc-id-token-hint` | **PASSED** | 80 SUCCESS, 0 FAILURE |
| `oidcc-login-hint` | **PASSED** | 47 SUCCESS, 0 FAILURE |
| `oidcc-ui-locales` | **PASSED** | 47 SUCCESS, 0 FAILURE |
| `oidcc-claims-locales` | **PASSED** | 47 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-acr-values-succeeds` | **PASSED** | 48 SUCCESS, 0 FAILURE |
| `oidcc-codereuse` | **PASSED** | 54 SUCCESS, 0 FAILURE |
| `oidcc-codereuse-30seconds` | **PASSED** | 58 SUCCESS, 0 FAILURE |
| `oidcc-ensure-registered-redirect-uri` | **REVIEW** | 22 SUCCESS, 0 FAILURE — unregistered redirect_uri returns the HTTP 400 error page (never redirects); screenshot uploaded for review |
| `oidcc-ensure-post-request-succeeds` | **PASSED** | 46 SUCCESS, 0 FAILURE |
| `oidcc-server-client-secret-post` | **PASSED** | 45 SUCCESS, 0 FAILURE |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | **SKIPPED** | 16 SUCCESS, 0 FAILURE — expected skip; conformance suite skips when `none` is not advertised in `request_object_signing_alg_values_supported` (correct for a signed-only OP) |
| `oidcc-claims-essential` | **PASSED** | 56 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-object-with-redirect-uri` | **SKIPPED** | 16 SUCCESS, 0 FAILURE — expected skip; self-skips for the same reason as the unsigned-request-object module |
| `oidcc-refresh-token` | **PASSED** | 137 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | **PASSED** | 47 SUCCESS, 0 FAILURE |

### 3. Form Post OP (`oidcc-formpost-basic-certification-test-plan`)

Runs the same module set as Basic OP with `response_mode=form_post` — the authorization response is delivered as an auto-submitted HTML form instead of a query redirect.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 36 test modules, 2010 successes, 0 failures, 0 warnings (46.2s)

| Module | Result | Notes |
|--------|--------|-------|
| `oidcc-server` | **PASSED** | 59 SUCCESS, 0 FAILURE |
| `oidcc-response-type-missing` | **PASSED** | 34 SUCCESS, 0 FAILURE — placeholder resolved at runtime by the suite's own browser mechanism; no human-review flag |
| `oidcc-userinfo-get` | **PASSED** | 56 SUCCESS, 0 FAILURE |
| `oidcc-userinfo-post-header` | **PASSED** | 57 SUCCESS, 0 FAILURE |
| `oidcc-userinfo-post-body` | **PASSED** | 55 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | **PASSED** | 30 SUCCESS, 0 FAILURE |
| `oidcc-scope-profile` | **PASSED** | 59 SUCCESS, 0 FAILURE |
| `oidcc-scope-email` | **PASSED** | 61 SUCCESS, 0 FAILURE |
| `oidcc-scope-address` | **PASSED** | 58 SUCCESS, 0 FAILURE |
| `oidcc-scope-phone` | **PASSED** | 58 SUCCESS, 0 FAILURE |
| `oidcc-scope-all` | **PASSED** | 59 SUCCESS, 0 FAILURE |
| `oidcc-alternate-happy-flow` | **PASSED** | 61 SUCCESS, 0 FAILURE |
| `oidcc-display-page` | **PASSED** | 50 SUCCESS, 0 FAILURE |
| `oidcc-display-popup` | **PASSED** | 50 SUCCESS, 0 FAILURE |
| `oidcc-prompt-login` | **REVIEW** | 88 SUCCESS, 0 FAILURE, 0 WARNING — test completed; flagged for manual review (session re-auth path) |
| `oidcc-prompt-none-not-logged-in` | **PASSED** | 36 SUCCESS, 0 FAILURE |
| `oidcc-prompt-none-logged-in` | **PASSED** | 87 SUCCESS, 0 FAILURE |
| `oidcc-max-age-1` | **REVIEW** | 90 SUCCESS, 0 FAILURE, 0 WARNING — test completed; flagged for manual review (forced re-auth path) |
| `oidcc-max-age-10000` | **PASSED** | 90 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-unknown-parameter-succeeds` | **PASSED** | 50 SUCCESS, 0 FAILURE |
| `oidcc-id-token-hint` | **PASSED** | 88 SUCCESS, 0 FAILURE |
| `oidcc-login-hint` | **PASSED** | 51 SUCCESS, 0 FAILURE |
| `oidcc-ui-locales` | **PASSED** | 51 SUCCESS, 0 FAILURE |
| `oidcc-claims-locales` | **PASSED** | 51 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-acr-values-succeeds` | **PASSED** | 52 SUCCESS, 0 FAILURE |
| `oidcc-codereuse` | **PASSED** | 58 SUCCESS, 0 FAILURE |
| `oidcc-codereuse-30seconds` | **PASSED** | 62 SUCCESS, 0 FAILURE |
| `oidcc-ensure-registered-redirect-uri` | **REVIEW** | 22 SUCCESS, 0 FAILURE — unregistered redirect_uri returns the HTTP 400 error page (never redirects); screenshot uploaded for review |
| `oidcc-ensure-post-request-succeeds` | **PASSED** | 50 SUCCESS, 0 FAILURE |
| `oidcc-server-client-secret-post` | **PASSED** | 49 SUCCESS, 0 FAILURE |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | **SKIPPED** | 16 SUCCESS, 0 FAILURE — expected skip (see Basic OP) |
| `oidcc-claims-essential` | **PASSED** | 60 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-object-with-redirect-uri` | **SKIPPED** | 16 SUCCESS, 0 FAILURE — expected skip (see Basic OP) |
| `oidcc-refresh-token` | **PASSED** | 145 SUCCESS, 0 FAILURE |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | **PASSED** | 51 SUCCESS, 0 FAILURE |

### 4. 3rd Party-Init OP (`oidcc-3rdparty-init-login-certification-test-plan`)

Validates RFC 7591/7592 dynamic registration handling of `initiate_login_uri`:
the client registers an https initiate-login URI (echoed on the RFC 7592 read)
and a non-https URI must be rejected with HTTP 400 `invalid_client_metadata`.
The plan pins `client_registration=dynamic_client` and runs once per response
type (menu-selected, never exercised by the modules); registrations use the
bootstrap-minted initial access token.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 6 response-type runs
(`code`, `code id_token`, `code id_token token`, `code token`, `id_token`,
`id_token token`) × 2 test modules, 0 failures, 0 warnings (≤0.1s per run)

| Module | Result | Notes |
|--------|--------|-------|
| `oidcc-3rd_party-init-login` | **PASSED** ×6 | 30 SUCCESS, 0 FAILURE per run — `initiate_login_uri` accepted, stored, and echoed in the 201 response and the RFC 7592 management read |
| `oidcc-3rd_party-init-login-nohttps` | **PASSED** ×6 | 20 SUCCESS, 0 FAILURE per run — non-https `initiate_login_uri` rejected with 400 `invalid_client_metadata` |

**Summary**: **PASSED** — 12/12 module executions green.

### 5. Implicit OP (`oidcc-implicit-certification-test-plan`)

Validates the implicit flow (`response_type=id_token` and `id_token token` in one run — fragment responses, mandatory nonce, `at_hash`).

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 54 test modules listed (`[1:54]`), 0 failures, 0 warnings (27.9s), static_client. The suite's "Overall totals" line prints 55 (one bookkeeping entry counts as a module); the published profile count 58 assumes the dynamic_client variant — the static run omits `oidcc-id-token-signature` ×2 and `oidcc-idtoken-unsigned` ×2 (both `@VariantNotApplicable(static_client)`); they are covered by the M6 certification-grade dynamic re-runs.

| Module group | Result | Notes |
|--------------|--------|-------|
| Happy flows, scope profiles (profile/email/address/phone/all) | **PASSED** | the pure-implicit id_token carries the full scope claim set (userinfo is unreachable without an access token) |
| Nonce enforcement | **PASSED** | nonce-less implicit requests fail with an `invalid_request` fragment redirect |
| display/prompt/max_age/locales/acr/claims-essential | **PASSED** (2 REVIEW) | `oidcc-prompt-login`, `oidcc-max-age-1` REVIEW-flagged as in Basic OP |
| `oidcc-ensure-registered-redirect-uri` | **REVIEW** | error page, screenshot review (as Basic OP) |
| `oidcc-id-token-signature` ×2 | N/A (static_client) | runs only under dynamic_client — the published count 58 assumes that variant |

### 6. Hybrid OP (`oidcc-hybrid-certification-test-plan`)

All three hybrid types (`code id_token`, `code token`, `code id_token token`) in one run: `c_hash`/`at_hash`, per-type nonce rules, sub consistency between the authorization- and token-endpoint id_tokens.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 96 test modules listed, 0 failures, 0 warnings (145s), static_client. Same bookkeeping note: the runner prints 97; published 102 = dynamic_client adds `oidcc-id-token-signature` ×3 and `oidcc-idtoken-unsigned` ×3.

### 7. Form Post OP — implicit + hybrid legs (`oidcc-formpost-implicit/hybrid-certification-test-plan`)

The implicit/hybrid module sets with `response_mode=form_post` (auto-submitted POST callback, no credentials in the URL query).

**Previous detailed run**: 2026-10-11 — implicit leg: 54 modules listed (runner prints 55), 0 failures, 0 warnings; hybrid leg: 96 listed (prints 97), 0 failures, 0 warnings. Static-vs-published deltas as in §5/§6.

### 8. Dynamic OP (`oidcc-dynamic-certification-test-plan`)

Dynamic registration (RFC 7591/7592) + per-client signing algs + signed userinfo + JAR-by-reference — one run per response type, `client_registration=dynamic_client`, `client_auth_type=private_key_jwt`.

**Previous detailed run**: 2026-10-11 (suite `release-v5.3.2`) — 6 runs (code 23 / code id_token 22 / code id_token token 22 / code token 23 / id_token 18 / id_token token 19 modules = **127 executions**, the published profile total), 0 failures, 0 warnings beyond the expected set below. (The runner's "Overall totals: ran N" line counts one bookkeeping entry extra per run — the `[1:N]` module listings above are the exact counts.)

| Module group | Result | Notes |
|--------------|--------|-------|
| DCR lifecycle (register → RFC 7592 read → update → delete) | **PASSED** | incl. `initiate_login_uri`, logo/policy/tos, `jwks`/`jwks_uri`, sector docs |
| `oidcc-idtoken-rs256` / `oidcc-userinfo-rs256` | **PASSED** | per-client `id_token_signed_response_alg` / `userinfo_signed_response_alg` = RS256 (signed userinfo = `application/jwt`) |
| `oidcc-request-uri-signed-rs256` | **PASSED** | JAR-by-reference: pre-registered `request_uris` exact-match, SSRF-guarded fetch |
| `oidcc-refresh-token-rp-key-rotation` | **PASSED** | client JWKS rotation picked up via kid-miss refetch (61s module) |
| `oidcc-registration-sector-uri` / `-sector-bad` | **PASSED** | sector document fetched/validated; bad sector → 400 `invalid_client_metadata` |
| `oidcc-registration-logo/policy/tos-uri` | **REVIEW** | login page renders the client branding; screenshot review |
| `oidcc-server-rotate-keys` | **expected failure in-plan** | manual-step module (upstream's own CI also can't rotate mid-run); real evidence: `run-rotation-check.sh` drives it standalone with a real admin-API rotation → **PASSED** |
| `oidcc-request-uri-unsigned`, `oidcc-ensure-request-object-with-redirect-uri`, `oidcc-idtoken-unsigned` | **expected skips** | signed-only OP (`none` not advertised) |

### 9. RP-Initiated Logout OP (`oidcc-rp-initiated-logout-certification-test-plan`)

**Previous detailed run**: 2026-10-11 — 6 response-type runs × (1 discovery + 10 logout modules), 0 failures, 0 warnings (≈10s per run). Negative variants (bad/modified/missing `id_token_hint`, unregistered `post_logout_redirect_uri`, missing params/state) land on rendered error/confirmation pages — REVIEW-flagged screenshot modules, as in Basic OP. `post_logout_redirect_uris` validated as the dedicated allowlist (redirect_uris fallback); the SSO session is genuinely destroyed (post-logout `prompt=none` fails).

### 10. Session Management OP (`oidcc-session-management-certification-test-plan`)

**Previous detailed run**: 2026-10-11 — 6 response-type runs × 2 modules, 0 failures, 0 warnings. `session_state` rides every authorization response; `check_session_iframe` serves the OP-iframe postMessage protocol (`unchanged`/`changed`/`error`); the JS-readable companion cookie is cleared on logout (second check flips to `changed`).

### 11. Front-Channel Logout OP (`oidcc-frontchannel-rp-initiated-logout-certification-test-plan`)

**Previous detailed run**: 2026-10-11 — 6 response-type runs × 2 modules, 0 failures, 0 warnings. The logout interstitial renders the client's `frontchannel_logout_uri` iframe with `iss`+`sid` (session-required semantics); the suite validates both against the id_token.

### 12. Back-Channel Logout OP (`oidcc-backchannel-rp-initiated-logout-certification-test-plan`)

**Previous detailed run**: 2026-10-11 — 6 response-type runs × 2 modules, 0 failures, **2 expected warnings** per run: `EnsureIncomingTls13` / `EnsureIncomingTls12WithSecureCipherOrTls13` read the `x-ssl-protocol` request header, which the suite's own fronting nginx sets in its standard deployment — the hermetic stack serves the suite over direct HTTPS (no proxy), so the header cannot exist (`configs/issuerd-expected-warnings-backchannel.json`). The signed `logout_token` (events claim, `sub`/`sid` matching the id_token, no nonce) is delivered over TLS 1.3-capable rustls.

## Known Gaps vs. Conformance Suite Requirements

| Feature | Status | Impact |
|---------|--------|--------|
| **PKCE `plain`** | S256 only — `code_challenge_methods_supported` advertises `["S256"]` | plain-PKCE variants cannot pass |

## Expected Failures

- `oidcc-server-rotate-keys` (Dynamic OP plan, in-plan): manual-step module — the pristine runner force-starts it without rotating (upstream's own CI lists it identically). Real rotation evidence comes from `run-rotation-check.sh` (standalone suite-API run with an admin-API rotation interposed, PASSED). Declared in `configs/issuerd-expected-failures-dynamic.json`.

## Expected Skips

See `configs/issuerd-expected-skips.json` (basic/formpost legs: unsigned-request-object modules) and `configs/issuerd-expected-skips-dynamic{,-other}.json` (dynamic runs, per-response-type split — a listed-but-absent skip fails a run).
