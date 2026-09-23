# Issuerd OIDC Conformance Test Coverage

> Latest full run: **2026-09-13** (suite `release-v5.2.4`) — Config OP 39 conditions, Basic OP 36 modules / 1858 conditions, Form Post OP 36 modules / 2010 conditions; **0 failures and 0 warnings** across all three plans. Run in the **hermetic pristine environment**: isolated network (`internal: true`, bind9-only DNS), TLS everywhere from a local root CA, conformance suite JAR and runner scripts byte-pristine (no patching, no intercepting proxies — the only suite deviation is the root CA in the JVM truststore). Per-module tables below reflect this run.
> Conformance Suite version: release-v5.2.4

## Test Environment

- **Hermetic docker network** (`internal: true`, no internet): bind9 is the only DNS (authoritative for `conformance.test` only, no recursion/forwarders → external names refused instantly)
- **Run command**: `docker compose up` (or `run.sh`) — builds images, generates the PKI, bootstraps, runs all plans, exports reports; see README.md
- **Issuerd OP**: Docker container (canonical root Dockerfile), **native rustls TLS** on `https://op.conformance.test:8443`, in-memory storage
- **Conformance Suite Server**: Docker container (`Dockerfile.suite`), **pristine JAR** built in-docker from untouched upstream sources; **native Spring Boot HTTPS** on `https://suite.conformance.test:8443`; the only deviation from stock is the local root CA imported into the JVM truststore at container start
- **TLS everywhere**: local root CA (`pki/gen-certs.sh`) issues the OP and suite certs; no TLS-terminating or intercepting proxies anywhere; runner scripts are the pristine upstream ones, mounted from the clone
- **MongoDB**: Docker container (`mongo:6.0`)
- **Test Runner**: Docker container (`Dockerfile.runner`, host-UID, deps baked in)

## Realm Configuration

- Realm: `conformance`
- User: `conformance-user` / `conformance-password`
- Client 1: `conformance-client` / `conformance-secret`
- Client 2: `conformance-client-2` / `conformance-secret-2`
- Redirect URIs: `https://suite.conformance.test:8443/test/a/issuerd/callback`

## Test Plans

### 1. Config OP (`oidcc-config-certification-test-plan`)

Validates discovery metadata and JWKS. Requires no browser automation.

**Latest run**: 2026-09-13 (suite `release-v5.2.4`) — 2 test modules, 39 successes, 0 failures, 0 warnings (0.3s)

| Module | Result | Notes |
|--------|--------|-------|
| `oidcc-discovery-endpoint-verification` | **PASSED** | 39/39 conditions passed (includes RFC 8414 metadata schema validation, issuer-URL syntax, scopes/locales syntax checks) |

**Summary**: **PASSED** — Discovery, issuer URL, JWKS endpoint, and all metadata fields validated successfully.

### 2. Basic OP (`oidcc-basic-certification-test-plan`)

Validates authorization code flow with `response_type=code`.

**Latest run**: 2026-09-13 (suite `release-v5.2.4`) — 36 test modules, 1858 successes, 0 failures, 0 warnings (47.3s)

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

**Latest run**: 2026-09-13 (suite `release-v5.2.4`) — 36 test modules, 2010 successes, 0 failures, 0 warnings (46.2s)

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

## Known Gaps vs. Conformance Suite Requirements

| Feature | Status | Impact |
|---------|--------|--------|
| **Session Management** (`check_session_iframe`, `session_state` iframe polling) | Not implemented; not advertised in discovery | Session-management plans cannot pass |
| **PKCE `plain`** | S256 only — `code_challenge_methods_supported` advertises `["S256"]` | plain-PKCE variants cannot pass |

## Expected Failures

None. `configs/issuerd-expected-failures.json` is an empty list.

## Expected Skips

See `configs/issuerd-expected-skips.json`.
