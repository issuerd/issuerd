# Keycloak Compatibility Differences

This document records the current behavioral differences between Issuerd and
Keycloak, discovered while running the integration test suite against both
implementations. Differences that were fixed to match Keycloak are removed from
this document.

**Version baselines.** The dual-target integration suite runs against
**Keycloak 24.0** (`docker-compose.integration.yml`); the performance harness
(`tests/perf/`) compares against **Keycloak 26.7**, which supports DPoP and
CIBA out of the box. Statements about Keycloak feature availability below
refer to current Keycloak (26.x) unless a version is named.

## Test Infrastructure

- **Keycloak image**: `keycloak/keycloak:24.0` (Docker Hub)
- **Keycloak database**: H2 (embedded, dev mode)
- **Admin credentials**: `admin` / `admin` (via `KEYCLOAK_ADMIN*` env vars)
- **Port**: `8081` on host → `8080` in container

## Remaining Behavioral Differences

| Scenario | Keycloak | Issuerd | Test handling |
|---|---|---|---|
| Client credentials, invalid secret | `401` + `invalid_client` | `400` + `invalid_client` (shared client-auth pre-check, all grants) | Accepted; RFC 6749 §5.2 permits `400` when the client does not authenticate via an Authorization header |
| Client credentials with `scope=openid` | returns an `id_token` | no `id_token` (no user involved) | The spec mandates neither shape; tests tolerate both |
| UserInfo error | `401` with an empty body | `401` + JSON `{"error":"invalid_token"}` | Tests assert the status; the body is checked conditionally |
| Logout | `200 OK` | `204 No Content` | Tests accept either; both are valid RP-initiated logout responses |

Two further differences are absorbed by the test harness rather than by
assertions:

- **Client credentials provisioning**: Keycloak requires
  `serviceAccountsEnabled: true` on confidential clients for the grant to
  work; Issuerd needs no flag. `KeycloakTarget::create_client` sets it.
  Issuerd honors `service_accounts_enabled`: when enabled, the grant is
  backed by the lazily created `service-account-{client_id}` user (via
  `GET /admin/realms/{realm}/clients/{id}/service-account-user` or
  automatically when the flag flips on), `sub` is that user's id, and its
  role mappings flow into `realm_access`/`resource_access` — Keycloak's
  token shape. When disabled, Issuerd keeps its legacy synthetic token
  (`sub = client_id`, no role claims); Keycloak rejects the grant outright.
- **User profile requirement**: Keycloak requires `firstName`/`lastName` on
  new users (default `VERIFY_PROFILE` required action), otherwise the
  password grant fails with "Account is not fully set up". Issuerd has no
  such requirement; `KeycloakTarget::create_user` sets both.

## Unchanged / Acceptable Divergences

The following areas are intentionally not compared because they fall outside
the core OIDC protocol surface or are explicitly acceptable:

- **Authorization code flow browser mechanics**: Issuerd uses an internal SPA login API (`/api/v1/auth/login`). Keycloak uses a traditional HTML login form. Login mechanics differences are intentionally out of scope for parity.
- **Admin API**: Issuerd's REST Admin API is implementation-specific and not compared against Keycloak.
- **Device / CIBA flows**: Tested only against Issuerd (implementation-specific internal endpoints). Issuerd's device-verification endpoint accepts username/password directly, where Keycloak's verification page routes through the standard browser flow; both sides subject those password checks to the realm's brute-force protection (lockout after `max_login_failures` per username+IP).
- **Concurrency / stress tests**: Issuerd-only because Keycloak's rate limiting and locking behavior differs.

## Client Scopes & Protocol Mappers

Issuerd implements the Keycloak client-scope domain model (client scopes with
protocol mappers + scope-mappings, default/optional assignments, realm default
tables, client roles, service accounts). Deliberate divergences:

- **Built-in scope set**: Issuerd seeds 8 built-in scopes (`profile`, `email`, `address`, `phone`, `roles`, `offline_access`, `web-origins`, `acr`). Realm defaults are `profile` + `email` + `roles` (default) and the remaining five (optional) — a smaller set than Keycloak's (which also defaults `web-origins`, `acr`, `microprofile-jwt`, etc.).
- **Profile claims in access tokens**: only `preferred_username` (the `profile` scope's `username` mapper) targets access tokens; the other profile/email/address/phone mappers stay ID-token/userinfo-only, keeping access tokens minimal. Keycloak adds most profile claims to access tokens as well. Admins can flip any mapper's `access.token.claim` flag. Realms seeded before this change keep the stored mapper config (seeders never mutate existing scopes) — enable the toggle or reseed to get `preferred_username` in access tokens there.
- **`roles` auto-assignment**: every new client gets the `roles` scope as a default scope, preserving the long-standing behavior where access tokens always carried `realm_access`. Keycloak does the same via its default client scope set.
- **Scope validation unchanged**: requesting a scope outside the client's `default_scopes`/`optional_scopes` lists is rejected with `invalid_scope` (HTTP 400) at both the authorization and token endpoints; scope resources are resolved by name only after validation passes.
- **Assignment ↔ string-list sync**: the `default-client-scopes`/`optional-client-scopes` endpoints keep the client's scope string lists in sync with assignment rows (rows drive access-token default-scope expansion; lists drive request validation). Keycloak has no such dual bookkeeping.
- **`offline_access` has no special refresh gating**: it is a plain scope resource; refresh tokens are issued per realm policy regardless. Keycloak ties offline (persistent) sessions to this scope.
- **Scope-mappings `composite` endpoints** return the stored allow-list without composite expansion (simplification; Keycloak recurses composites there).

## Consent, Session Logout Channels, Login Theming & i18n

Issuerd implements the consent screen, back-/front-channel logout, and login-page
theming + internationalization. Deliberate divergences:

- **Logout channel client attributes**: Issuerd reads the plain attributes `backchannel_logout_uri` / `frontchannel_logout_uri`; Keycloak uses the dotted spellings (`backchannel.logout.url`, `frontchannel.logout.url`, plus `backchannel.logout.session.required` / `backchannel.logout.revoke.offline.tokens`, which Issuerd does not have — the logout token always carries `sid` when the session is known, and offline sessions die with their user session).
- **`post_logout_redirect_uri` validation**: validated against the client's registered `redirect_uris` (exact match or trailing-`*` wildcard prefix, same rule as the authorization endpoint); without a recognized client (via `id_token_hint` or `client_id`) the redirect is refused with HTTP 400 rather than acting as an open redirector. Keycloak's separate `post.logout.redirect.uris` attribute list with `+`/`-` relative-URL syntax is not implemented.
- **`id_token_hint` decoding**: access-token validation first, then `TokenService::validate_id_token_hint` (signature/expiry/issuer-family only; `aud`/`azp` read for client binding only *after* cryptographic validation).
- **Front-channel interstitial**: when any client session has a `frontchannel_logout_uri`, logout returns a small HTML page embedding one hidden iframe per client (called with `iss` + `sid`) that then navigates to the post-logout target (or renders a plain confirmation). Keycloak renders a similar iframe page.
- **Back-channel delivery**: fire-and-forget with a 5 s timeout and one retry; deliveries are recorded as admin events (`backchannel-logout/{client_id}`) but failures never block or fail the logout response.
- **Consent scope**: consent is only consulted on the interactive browser paths (SSO branch and fresh login); device authorization and CIBA never show a consent page (no interactive surface exists at grant time). Keycloak likewise only prompts in browser flows.
- **`prompt=none` + consent needed**: redirects back with `error=consent_required` (OIDC Core 3.1.2.6).
- **Consent persistence**: grants are stored keyed on the internal client UUID; coverage is decided by scope-set containment (stored ⊇ requested). `prompt=consent` always forces the page regardless of stored grants.
- **Locale resolution order** (login pages): `ui_locales` → `Accept-Language` → realm `default_locale` → `en`; gated on `internationalization_enabled`, candidates restricted to `supported_locales` (language-subtag match, so `de-AT` matches a supported `de`). Outbound email prefers the user's `locale` attribute over the realm default (Keycloak semantics). Keycloak additionally has a locale cookie and per-user profile UI locale; Issuerd pins the resolved locale into the pending flow instead.
- **Theming**: theme resources are served from a filesystem directory (`[themes] dir`, default `themes/`) at `/realms/{realm}/theme/{*path}` with per-realm `login_theme`/`email_theme` overrides falling back to the built-in `issuerd` theme; login.html consumes `--issuerd-*` CSS variables. Deliberately smaller than Keycloak's Freemarker theme engine (no template overrides, no per-theme message bundles beyond the shipped locales).
- **OIDC session management** (`check_session_iframe`, `session_state` iframe polling) remains unimplemented; discovery does not advertise it.

## Admin API Depth

The management surface includes editable flows, credentials CRUD,
execute-actions-email, impersonation, groups hierarchy, role composites,
events config, key rotation, and partial import/export. Deliberate divergences:

- **Credential `moveAfter` renumbers**: moving a credential re-sorts the list and renumbers priorities sequentially `1..=n`; priorities are the single source of truth. Keycloak stores its own ordering semantics.
- **Keys disable == passive**: `PUT /keys/{kid}/disable` marks the key inactive — still published in JWKS and still validating previously issued tokens, but never signing new ones. Keycloak distinguishes `disabled` from `passive` (a passive key can still sign as a fallback); Issuerd has one non-signing state.
- **Execute-actions email is English-only**: the mail body is rendered from a fixed English template, not the i18n bundles. The link target (`/realms/{realm}/login/execute-actions`) is localized as usual once the browser lands.
- **Partial import FAIL is 409 and non-transactional**: with `ifResourceExists=FAIL` the first conflicting resource aborts the import with HTTP 409 (`{resource} '{name}' already exists`); earlier resources are NOT rolled back. Keycloak's partialImport likewise reports and aborts on the first conflict without a surrounding transaction.
- **Impersonation returns tokens, not cookies**: `POST /users/{id}/impersonation` responds `200` with a `TokenResponse`-shaped JSON body whose tokens carry an `impersonator` claim set to the caller's user id; the session is recorded with `auth_method = "impersonation"`. Keycloak instead sets session cookies on the admin console response and returns no body. Issuerd's shape is friendlier to API consumers and the SPA.
- **`push-revocation` is a no-op stub**: returns 204 and records only an admin event. Actual revocation is `PUT /realms/{realm}` with `notBefore` — the admin middleware and the userinfo/introspection/refresh paths then reject tokens with `iat < not_before`. Keycloak pushes revocation policies to registered clients; Issuerd clients observe revocation through ordinary token/session validation instead.
- **Non-browser flow bindings are representation-parity only**: `browserFlow`, `directGrantFlow`, `resetCredentialsFlow`, `firstBrokerLoginFlow`, and `registrationFlow` round-trip through GET/PUT, but only `browserFlow` and `registrationFlow` are honored at runtime; the others are stored for Keycloak-representation compatibility while the corresponding paths keep their built-in behavior. The built-in direct-grant path enforces the same conditions as Keycloak's default direct grant flow: OTP-enrolled users must present a valid `totp` (with a persisted replay watermark), and required-action accounts are rejected. One deliberate hardening divergence: accounts whose only second factor is WebAuthn are rejected — Keycloak's direct grant has no WebAuthn stage and lets such accounts in with the password alone; Issuerd fails closed.
- **Built-in flows are seeded per realm**: `browser` and `registration` are materialized into storage at realm creation (visible in the admin API, read-only — edits require a copy, matching Keycloak's built-in-flow rule). Keycloak additionally seeds `direct grant`, `reset credentials`, `first broker login`, etc.; Issuerd resolves those aliases to code defaults instead.
- **Authenticator config lives on the execution**: an execution carries at most one `AuthenticatorConfig` (embedded in the stage's stored document, addressed by execution id) rather than Keycloak's separate config entities with their own ids.
- **Events expiration is read-path clamping**: `eventsExpiration` clamps `date_from` at query time (`max(requested, now - expiration)`); expired events are never physically deleted. Keycloak schedules a periodic cleanup instead. Listener list defaults to `logging`-only, matching Keycloak's fresh-realm defaults.
- **Event recording defaults to ON**: fresh realms get `eventsEnabled=true` and `adminEventsEnabled=true` (Keycloak defaults both to OFF — deliberate parity break so a new deployment has an audit trail out of the box). `adminEventsDetailsEnabled` (representation capture) still defaults to OFF, matching Keycloak.
- **Admin-event wipe is self-auditing**: `DELETE /events` and `DELETE /admin-events` each record the wipe as one fresh admin event — but that write is itself gated by `adminEventsEnabled`, so with admin events explicitly turned off nothing remains.
- **Event representations carry resolved names**: `GET /events` returns `username` (resolved from `user_id`, falling back to the recorded `username` detail) and `session_id`; `GET /admin-events` returns `auth_username` resolved against `auth_realm_id`. Keycloak returns only the raw IDs. Filtered totals come from `GET /events/count` and `GET /admin-events/count`, which have no Keycloak counterpart.
- **Realm PUT merges by default**: `PUT /admin/realms/{realm}` applies only the fields present in the body — omitted (or null) fields keep their stored values; `?merge=false` restores full replacement (also the only way to clear a nullable field, since merge treats `null` like an absent field). Keycloak's realm PUT is always a full replacement, where a partial body silently resets every omitted setting. Deliberate hardening break: a partial Issuerd PUT cannot switch brute-force protection back off or reset lifespans/events config. Full-document GET-round-trip callers see identical results under both modes.

## Pushed Authorization Requests (RFC 9126)

Issuerd serves the PAR endpoint (`/realms/{realm}/protocol/openid-connect/ext/par`,
same path as Keycloak) and `request_uri` consumption at the authorization
endpoint. Deliberate divergences:

- **Fixed 90 s request-URI lifetime**: `expires_in` is always 90 and is not configurable. Keycloak defaults to 60 s and honors the `parRequestUriLifespan` realm attribute.
- **Strict single-use consumption**: a `request_uri` is burned by the first authorization request that presents it (atomic `get_and_delete`), even if that request then fails. Keycloak also rejects reuse (its `ParTest.testFailureParUsedTwice`); Issuerd additionally guarantees the burn on failure. RFC 9126 §4's browser-reload tolerance is deliberately not implemented — FAPI conformance requires reuse rejection.
- **No extra parameters alongside `request_uri`**: the authorization request may carry only `client_id` + `request_uri`; anything else is `invalid_request`. Keycloak merges query parameters over the stored request (its own `ParTest` sends `state` alongside `request_uri`). Issuerd's strict reading keeps the pushed request the single source of truth — the integrity property PAR exists for.
- **Realm-wide require-PAR attribute name**: Issuerd reads the realm attribute `require_pushed_authorization_requests` (the RFC 9126 discovery-metadata spelling, also mirrored into the discovery document). Keycloak has no realm-wide switch — only the per-client attribute `require.pushed.authorization.requests`, which Issuerd also honors (checked after client validation, so the `invalid_request` error redirects to the registered `redirect_uri`).
- **Error rendering**: PAR resolution failures (unknown/expired/used/mismatched `request_uri`, missing `client_id`, extra params, realm-level require-PAR violations) render the standard error page (browsers) or a JSON `invalid_request` body — never a redirect to the client, since no `redirect_uri` has been validated at that point. Keycloak renders its own error page for the same cases.
- **Push-time validation is complete**: parse + client policy (redirect URIs, scopes, response type allowlist) + implemented-response-type checks all run at the PAR endpoint; the stored parameters re-run the identical pipeline when consumed (the RFC 9126 §7.4 policy-change window is the 90 s TTL).

## JWT Client Authentication (`private_key_jwt`, `client_secret_jwt`)

Issuerd implements JWT client assertions (RFC 7523 §2.2 / OIDC Core §9) at
every client-authenticated endpoint (token, PAR, revoke, introspect),
dispatched on the client's `client_authenticator_type` (Keycloak spellings
`client-secret` / `client-jwt` / `client-secret-jwt`). Client JWKS
configuration uses Keycloak's attribute spellings: `use.jwks.string` +
`jwks.string` (inline JWKS) or `use.jwks.url` + `jwks.url` (fetched, cached
300 s per client, one refetch-on-kid-miss retry). Deliberate divergences:

- **`client_id` is required alongside the assertion**: Issuerd identifies the client from the `client_id` form parameter and then requires `iss` == `sub` == that value. Keycloak additionally tolerates a missing `client_id` and peeks at the unverified assertion's `iss`. All major client libraries send `client_id`, so the stricter reading is interop-safe.
- **`jti` is required and single-use**: an assertion without a `jti`, or one whose `jti` was seen before (atomic cache counter, TTL = remaining assertion lifetime), is rejected with `invalid_client`. RFC 7523 marks `jti` optional and Keycloak does not enforce replay rejection outside FAPI profiles; Issuerd always enforces it.
- **300 s maximum assertion lifetime**: `exp` further than 300 s (+ 60 s leeway) in the future is rejected, bounding the replay cache. Keycloak's `maxExp` is configurable with a similar default; Issuerd's cap is fixed.
- **Strict one-method-per-request**: presenting `client_secret` and `client_assertion` together is rejected (RFC 6749 §2.3's MUST NOT), and a client pinned to a JWT method is rejected when presenting anything else (and vice versa) — the dispatch is exactly the configured `client_authenticator_type`, matching Keycloak.
- **Accepted `aud` values**: the realm issuer URL, the token endpoint URL, and the PAR endpoint URL (RFC 9126 §2 rule), all under the realm-name issuer form that discovery advertises. Keycloak's accepted-audience list additionally includes its CIBA and device endpoints; Issuerd's CIBA backchannel endpoint authenticates with the shared secret only and does not accept assertions.
- **`client-x509` remains unimplemented**: such clients fall back to the shared-secret check, and `tls_client_auth` / `self_signed_tls_client_auth` stay unadvertised in discovery.

## Token Exchange (RFC 8693)

Issuerd implements the `urn:ietf:params:oauth:grant-type:token-exchange`
grant at the token endpoint in two modes: internal exchange (`audience` =
target `client_id`) and impersonation exchange (`requested_subject` = target
user id). The grant is advertised in discovery `grant_types_supported`.

Keycloak context: it has two implementations — **legacy V1** (fine-grained
admin permissions; deprecated in 26.6) and **standard token exchange V2**
(RFC-compliant, supported and enabled by default since 26.2). "Keycloak"
below refers to V2 unless noted. Deliberate divergences and design notes:

- **Permission model is a single client attribute**: the target client must carry `token.exchange.enabled=true`, otherwise the exchange fails with `invalid_grant` — a boolean opt-in (surfaced as a switch on the admin client form) in place of Keycloak V1's fine-grained permission model. The flag is also required when `audience` is omitted (self-exchange for scope narrowing).
- **Subject-token audience must include the requesting client** (parity, mandatory): the requesting client must appear in the subject token's `aud` (string or array form; `azp` is not considered), or the exchange — internal or impersonation — fails with `invalid_grant`. This matches Keycloak V2's rule (the requester must be the token's recipient or in its audience). The former opt-in `require_requester_in_subject_aud` attribute was removed after a security review; the check is now unconditional.
- **Subject tokens must be access tokens of the same realm**: `subject_token_type` must be `urn:ietf:params:oauth:token-type:access_token`, and the token must pass stateless validation plus the revocation blocklist, realm binding, `not_before`, session-liveness, and enabled-user checks. Refresh/ID tokens and cross-realm tokens are rejected with `invalid_grant`. Keycloak additionally accepts external-IdP subject tokens (deferred here) and can mint external tokens for `requested_issuer` (not planned).
- **Impersonation exchange is gated only by the realm `impersonation` role** on the subject token's owner (evaluated from the token's `realm_access` claim, the same rule the admin impersonation endpoint applies). The `token.exchange.enabled` flag is NOT required on the `audience` client in this mode — the role is the gate, matching Keycloak where impersonation permission is checked on the caller, not the target client. Self-impersonation, disabled targets, and unknown target ids are rejected.
- **Access-token-only responses**: neither mode issues refresh or ID tokens. The response carries `issued_token_type: urn:ietf:params:oauth:token-type:access_token` per RFC 8693 §2.2; other `requested_token_type` values are rejected with `invalid_request`, as is `actor_token` — delegation is out of scope (Keycloak 26.7 ships an experimental `may_act` delegation; Issuerd does not).
- **Scope semantics**: for internal exchange the requested `scope` must be a subset of the subject token's grant (else `invalid_scope`); when omitted, the subject grant is kept. This is stricter than Keycloak V2, where the exchanged token's scope resolves through the requesting client's default/optional scopes and can *widen* unless a client policy with the `downscope-assertion-grant-enforcer` executor is configured — Issuerd's monotonic narrowing is the safe default for token-attenuation chains. For impersonation exchange an omitted scope defaults to `openid profile email`. In both modes the minted token's claims go through the claims pipeline for the TARGET client, so client-scope/protocol-mapper resolution and `full_scope_allowed` narrowing apply to the target.
- **Audit**: internal exchange emits `token_exchange` / `token_exchange_error` login events (gated on the realm's events config). Impersonation exchange additionally records an `ACTION` admin event on `users/{id}/impersonation` (gated on `adminEventsEnabled`, representation stripped unless `includeRepresentations`) plus a `login` event with `details.method=impersonation` that deliberately bypasses the events gate. Exchanged tokens minted from an impersonated session keep the `impersonator` claim (refresh-grant parity).
- **`resource` parameter ignored**: RFC 8693's `resource` is accepted but not evaluated (Keycloak likewise only documents `audience`); `invalid_target` is not used — unknown or disabled `audience` clients fail with `invalid_grant`.

## Offline Token Semantics

Issuerd implements Keycloak's offline-token model: refresh tokens are issued
by every flow as before, but the **offline** class — a separate offline
session and a `typ: Offline` refresh token that uses the realm's
`offline_session_idle_timeout` and survives SSO session expiry and browser
logout — is unlocked only when the granted scopes include `offline_access`.
Deliberate divergences and design notes:

- **Gating is scope-only**: Keycloak additionally requires the user to hold the realm role `offline_access` (`UserSessionManager.isOfflineTokenAllowed`). Issuerd gates on the granted scope alone (the client must still have `offline_access` among its assigned optional scopes — the usual scope-assignment rule).
- **Offline sessions get their own session id**: Keycloak persists the offline session in a separate store keyed by the online session's id, so both share one id. Issuerd keys all sessions in a single table, so the offline session created at authorization-code redemption is a separate row with its own id; the redemption's tokens point at the offline session while the SSO cookie keeps pointing at the online session. ROPC, device, and CIBA grants (no SSO cookie involved) mark their single session offline instead of creating a second row.
- **Offline refresh tokens carry an `exp`**: Keycloak's offline tokens omit `exp` unless `offlineSessionMaxLifespanEnabled` is on. Issuerd mints them with `exp = iat + offline_session_idle_timeout`, re-minted on every rotation; combined with the server-side idle check against `last_session_refresh`, the effective cutoff matches Keycloak's idle semantics.
- **Refresh rotation preserves the offline class** from the session flag (not from the presented token's scope string as Keycloak does), so narrowing `scope` on refresh cannot silently downgrade an offline token to online.
- **Offline sessions never serve SSO**: `resolve_session_from_cookie` refuses them (no silent SSO login, and the SSO idle sweeper never deletes them). Deleting an online session leaves the offline session — and its refresh token — working; deleting the offline session kills it.
- **SSO and remember-me cookies are realm-scoped by name**: `issuerd_session_{realm-id}` / `issuerd_remember_{realm-id}` rather than one shared cookie, so logging into realm B no longer clobbers realm A's SSO session. Keycloak achieves the same isolation by path-scoping `KEYCLOAK_SESSION` / `KEYCLOAK_REMEMBER_ME` to `/realms/{realm}`. Cookies minted before the switch (single `issuerd_session` / `issuerd_remember`) are still honored as a fallback, and the SPA logout endpoint destroys every realm session the browser carries and clears both spellings.
- **Admin visibility**: `UserSessionRepresentation` carries `offline: bool` in realm and per-user session listings; the SPA renders an "Offline" badge. Keycloak's dedicated `GET /users/{id}/offline-sessions/{client}` endpoint was not added — offline sessions appear in the regular listings, typed.

## Algorithm Agility

Issuerd implements per-realm token-signing algorithm selection and fixed
ES512 (P-521) signing. Deliberate divergences and design notes:

- **Per-realm attribute, server-global keys**: the realm attribute `default_signature_algorithm` selects which **active** key from the shared `signing_keys` table signs that realm's tokens. Keycloak keeps signing keys per realm and picks the algorithm per client (`id.token.signed.response.alg`); Issuerd's keys are server-global and the selector is per realm.
- **Realm reincarnation does not invalidate old tokens**: issuers embed the realm NAME and signing keys are server-global, so deleting a realm and recreating it under the same name lets that realm's still-unexpired tokens verify and bind to the new realm (user tokens mostly dead-end because their sessions cascade-delete; the stateless admin-token binding is the sharpest exposure). Keycloak is immune because its per-realm keys die with the realm. Mitigation: rotate keys after recreating a realm, or set the new realm's `not_before`.
- **ES512 is signed outside `jsonwebtoken`**: `jsonwebtoken` (ring) has no P-521 support, so ES512 JWS is produced and verified manually in `issuerd-token/src/es512.rs` via the `p521` crate (fixed-width `R || S` signature, RFC 7518 §3.4). External JWTs (client assertions, broker ID tokens) still do not accept ES512 — `token_endpoint_auth_signing_alg_values_supported` stays truthful.
- **Rotation keeps one active key PER ALGORITHM**: `POST /admin/realms/{r}/keys/rotate` accepts an optional body `{ "algorithm": "ES256", "key_size": 2048 }` (defaults to the newest active key's parameters; EdDSA when no key exists; unknown algorithms → 400). Only same-algorithm active keys are demoted. On an EMPTY key set the rotation establishes the fresh-deployment pair — the requested key plus, unless it is RS256 itself, an active RS256 key — so the OIDC Core §15.1 MTI advertisement holds there too. The last remaining active key overall cannot be disabled; disabling an algorithm's only active key makes realms pinned to it fall back to the default signing key.
- **Fallback on missing algorithm**: a realm whose configured algorithm has no active key (or whose attribute value is unknown) is signed with the default signing key (newest active overall) instead of failing — availability over strictness. Keycloak generates per-realm keys for every configured provider, so it never needs this fallback; Issuerd admins create the key first (rotate with the algorithm), which switches the realm over on the next issued token.
- **Realms without the attribute follow the EdDSA server default**: issuance resolves the realm attribute, then the server default (`CryptoConfig::default_alg`, EdDSA since the asymmetric-first policy change), then — only when no key of that algorithm is active — the newest active key. Fresh deployments therefore boot with an Ed25519 key AND an active RS256 key (OIDC Core §15.1 makes RS256 mandatory-to-implement, so discovery advertises it from the start and realms explicitly pinned to RS256 work without a rotation). Upgraded deployments with an RS256-only key set are unaffected until an EdDSA key is deliberately rotated in; from that moment un-pinned realms switch to EdDSA (previously issued RS256 tokens keep validating), so pin `default_signature_algorithm=RS256` on realms that must stay on RSA before rotating EdDSA in.
- **Discovery**: `id_token_signing_alg_values_supported` lists exactly the algorithms of the ACTIVE signing keys (newest first), computed per request from the keystore — not Keycloak's static everything-supported list.
- **HMAC algorithms never sign realm tokens**: HS* keys publish no usable public material (the JWKS exposure boundary strips `k`), so a realm signed with one could not validate its own tokens from the JWKS snapshot. `Realm::default_signature_algorithm()` therefore ignores symmetric values. HS* keys can still be generated via rotation (they simply never sign realm tokens); the Keys page lists all algorithms and discloses the exclusion.

## DPoP (RFC 9449)

Issuerd implements **DPoP** sender-constraining; mTLS (option B) stays
deferred (it needs TLS termination at Issuerd plus a client-cert capture
contract, and no deployment asked for it). The dual-target suite's baseline
(Keycloak 24.0) has no DPoP, so DPoP tests run Issuerd-only; in current
Keycloak DPoP is a supported feature since 26.4 (preview since 23.0), and the
perf harness exercises both sides. Deliberate divergences and design notes:

- **Binding trigger**: any token-endpoint request carrying a valid `DPoP` proof header gets its issued tokens bound to the proof key (`cnf.jkt`) — every grant (authorization_code, password, refresh_token, client_credentials, device_code, CIBA, token-exchange). No proof: plain Bearer flow, byte-identical behavior.
- **Refresh binding is uniform, not public-clients-only**: RFC 9449 §5.1 mandates DPoP-bound refresh tokens for public clients; Issuerd binds refresh tokens for every client type when a proof is presented. A bound refresh token may only be redeemed with a proof from the same key (`invalid_grant` otherwise, and the token is NOT burned on that failure — the binding check runs before rotation), and rotation slides the binding onto the new tokens. An unbound refresh token presented with a proof becomes bound going forward.
- **Access tokens are bound through the claims-overlay path** (`cnf` is deliberately absent from `RESERVED_OVERLAY_CLAIMS`); refresh tokens take the binding as a typed `issue_refresh_token(.., dpop_jkt)` parameter. The typed `cnf` field on both claims structs is the decode/validation surface (userinfo, introspection).
- **`htu` comparison is exact** against the discovery-advertised endpoint URL; because `resolve_realm` serves both realm-name and realm-id URL spellings, both are accepted. Proofs whose `htu` carries a query/fragment never match (RFC 9449 §4.3 forbids them anyway).
- **Replay protection rides on `jti` + `iat`** (300 s acceptance window, 60 s future leeway): the `jti` is burned in the distributed cache (`dpop_jti:{realm}:{jti}`, TTL = the proof's remaining window, atomic `increment`, fail-closed).
- **Server-provided nonces (RFC 9449 §8/§9) are an opt-in** (`[dpop.nonce] mode = "supported" | "required"`, default `disabled`, `lifetime_secs` default 30): single-use nonces issued via the `DPoP-Nonce` response header, stored in the distributed cache (`dpop-nonce:{realm}:{nonce}`), and missing/stale/used nonces are challenged with a `use_dpop_nonce` error plus a fresh nonce. With the default `disabled` mode, `use_dpop_nonce` is never returned and replay protection is `jti`-only.
- **Proof alg accept set**: RS256/384/512, ES256/384, EdDSA — identical to the external-JWT accept set used by identity brokering and JWT client authentication. ES512 proofs are unsupported (`jsonwebtoken` has no P-521; the manual ES512 path only covers our own signing keys). `dpop_signing_alg_values_supported` advertises exactly this set.
- **Userinfo** accepts `Authorization: DPoP <token>` plus a proof with a matching `ath` (SHA-256 of the token), `htm` checked against the actual method. A bound token presented as Bearer is rejected `401 invalid_token`; the DPoP scheme on an unbound token is likewise `invalid_token`; proof failures are `401 invalid_dpop_proof`. All three carry the RFC 9449 §7.1 `WWW-Authenticate: DPoP error="..."` challenge. Bearer requests to unbound tokens are byte-identical to before.
- **Introspection** (RFC 9449 §6.1) reports `token_type: "DPoP"` and the `cnf` claim for bound tokens.
- **Not consumed** at the PAR/revocation/introspection endpoints themselves (a proof sent there is ignored); binding is established at the token endpoint only. Backchannel/frontchannel logout, device authorization, and CIBA user-facing endpoints are out of DPoP scope (no user key exists there).
- **Accepted downgrade surface (documented, not a bug)**: DPoP-bound access tokens are enforced as sender-constrained at userinfo, the token endpoint, and token exchange, but the admin API and account console API accept them as plain bearer tokens. Deployments needing proof-of-possession on those paths should front them with a DPoP-enforcing gateway.

## JAR (RFC 9101), JARM (`response_mode=jwt`), `form_post`

Issuerd implements signed Request Objects (`request`), JWT-secured
authorization responses (the `jwt`/`query.jwt`/`fragment.jwt`/`form_post.jwt`
response modes), and the `form_post` response mode. Deliberate divergences
and design notes:

- **Unsigned Request Objects are always rejected** (`invalid_request`, error page for browsers / JSON otherwise, never a client redirect — the object carrying the redirect_uri failed validation, so nothing inside it is trusted). Keycloak only rejects unsigned objects when the client pins a signature algorithm (`request.object.signature.alg`); Issuerd is strict unconditionally (FAPI-aligned). The per-client signature-alg pinning attribute itself is not implemented: any algorithm from the advertised `request_object_signing_alg_values_supported` accept set with matching verification material works.
- **HMAC request objects are accepted** (HS256/384/512 keyed with the client secret, RFC 9101 §10.2) in addition to asymmetric signatures against the client JWKS (`use.jwks.string` inline wins over `use.jwks.url` fetched — the JWT-client-auth plumbing, including the one-shot refetch-on-kid-miss retry).
- **`iss` is required and must equal the query `client_id`** (RFC 9101 §4); Keycloak ignores `iss` entirely. `aud` is allowlist-checked against the realm issuer **only when present** (absence tolerated for Keycloak compatibility). `exp` is optional but enforced when present; future `iat` is rejected.
- **Merge semantics follow Keycloak's `AuthzEndpointRequestParser`**: object claims win per-key over the query parameters; `client_id` present in both must match (as must `response_type`); a `request_uri` claim inside the object is rejected. JAR-by-reference from arbitrary URLs stays unimplemented and is advertised truthfully as `request_uri_parameter_supported: false`.
- **JAR over PAR**: a Request Object pushed to the PAR endpoint is validated at push time (the client is already authenticated there) and its extracted claims are stored — the authorize endpoint consumes a plain parameter map either way.
- **JARM envelope**: `iss` (realm issuer), `aud` (client_id), `exp`, `iat`; the response parameters ride as claims; signed with the realm's token-signing key (clients verify against the realm JWKS). The JWT lives 60 s — it only needs to survive the front-channel redirect. Error responses are wrapped exactly like success responses. `response_mode=jwt` resolves to the response type's default delivery (query for code, fragment for implicit/hybrid), JARM-wrapped.
- **`form_post` page** is a minimal auto-submitting HTML form (plain `<form>` + `body onload`, `<noscript>` fallback button — HtmlUnit-safe per the login-page rule), not the themed page chrome: it is invisible in practice and must never execute modern JS.
- **Pre-parse errors honor `response_mode` too**: `try_auth_error_redirect` packages the error per the requested mode whenever `response_mode` itself parses — the Form Post OP module `oidcc-response-type-missing` requires the error POSTed to the client.
- **Conformance note**: both request-object modules (`oidcc-unsigned-request-object-...`, `oidcc-ensure-request-object-with-redirect-uri`) are EXPECTED skips — they self-skip when `request_object_signing_alg_values_supported` does not advertise `none`, which is exactly right for a signed-only OP (Keycloak skips them the same way). The unsigned-rejection behavior itself is covered by the integration tests.
- The standalone **SPNEGO endpoint** (`/realms/{realm}/kerberos`) honors an explicitly requested `response_mode` (form_post/JARM) on its code delivery; without one it stays a plain query redirect. Device authorization and CIBA are out of response-mode scope (no front-channel response exists there).

## RAR: `authorization_details` (RFC 9396)

Issuerd implements Rich Authorization Requests: `authorization_details` at
the authorization endpoint (parse + structural validation), carried through
the login continuations and the authorization code into the grant, emitted as
the `authorization_details` access-token claim, echoed in token responses
(RFC 9396 §7), and reflected in userinfo and introspection (§9). No
payment/open-banking type profiles exist — types are opaque to Issuerd.

- **Keycloak has no generic RFC 9396 support** (only custom extensions), so there is no behavioral baseline to match; the shape follows the RFC directly.
- **Type registry is realm-pinned, not built-in**: RFC 9396 §5 requires the AS to refuse unknown types, but Issuerd defines no types of its own. Deployments pin their types via the realm attribute `authorization_details_types` (space-separated): unlisted types are rejected with `invalid_authorization_details` and discovery advertises the list as `authorization_details_types_supported`. Without the attribute, **any** type is accepted (types are extensible per §2.1) and the metadata is omitted — advertising an empty list would falsely claim "no types supported".
- **Structural validation only**: the value must be a JSON array of objects, each with a non-empty string `type`. Type-specific fields are not validated (§11.3).
- **Narrowing is exact element containment**: with no type-specific comparison logic (§6.1 leaves semantics to each type), a requested set must consist of elements byte-identical (post-JSON-parse) to granted elements. A restricted-field narrowing legitimate for a specific type is rejected — conservative and safe by default.
- **Grant carry-over lives on the refresh token**, not the user session (Keycloak stores granted details in its session model). The refresh token is the durable artifact of the grant in Issuerd's stateless design, so `authorization_details` rides as a claim; rotation keeps the **original** granted set on the new refresh token even when the request narrowed the access token (§6.1: the resource owner's authorization is unchanged).
- **Token-request `authorization_details`** (§6) is honored only for the `authorization_code` and `refresh_token` grants. Every other grant (password, client_credentials, device, CIBA, token exchange) rejects the parameter with `invalid_authorization_details` rather than silently dropping it. §6 allows client_credentials against "the client's policy" — no such policy surface exists yet.
- **No consent/enrichment integration**: stored-grant coverage stays scope-only (changing `authorization_details` does not by itself trigger re-consent), and details pass through verbatim (no §7.1 server-side enrichment).
- **PAR and JAR needed no changes**: both pass `authorization_details` through generically, so pushed/signed RAR requests work — also the RFC's recommended transport for large payloads (§11.4).
- The standalone **SPNEGO endpoint** does not pick up `authorization_details`; the main authorize endpoint is the RAR entry point.

## Dynamic Client Registration (RFC 7591/7592)

Issuerd implements Keycloak's `clients-registrations` endpoints: open
registration at `POST /realms/{realm}/clients-registrations/default`,
initial-access-token-gated registration at
`POST /realms/{realm}/clients-registrations/openid-connect`, and
client-configuration CRUD at
`GET/PUT/DELETE .../clients-registrations/openid-connect/{client_id}` with
the registration access token, plus the admin
`GET/POST/DELETE /admin/realms/{realm}/clients-initial-access[/{id}]`
surface. Deliberate divergences and design notes:

- **Realm toggle, default off**: Keycloak's registration endpoints are always on; Issuerd treats open registration as a public attack surface and gates every registration endpoint (and the discovery `registration_endpoint` advertisement) on the realm attribute `dynamic_client_registration_enabled`. When off, all endpoints return a uniform 404 — a disabled realm is indistinguishable from an unknown one.
- **Opaque cache-backed tokens, not JWTs**: Keycloak's initial access tokens and registration access tokens are JWTs; Issuerd's are opaque strings stored in the distributed cache (multi-node safe, revocable, naturally expiring via cache TTL). Initial access tokens have the form `{id}.{secret}`: the `id` addresses the cache entry, the whole token is verified against a stored SHA-256 hash in constant time. Registration access tokens are stored per client (`registration-access:{realm}:{client_id}`, no expiry — Keycloak's JWTs also have no `exp`) and rotate on every PUT (RFC 7592 §3).
- **Count consumption is eager**: a presented-and-verified initial access token consumes one use atomically even if the registration itself then fails validation — abuse-resistant; Keycloak's exact consumption point is unspecified.
- **`count: 0` / `expiration: 0` mean unlimited / never expires**, and the admin DTOs use snake_case (`remaining_count` where Keycloak writes `remainingCount`), consistent with the rest of the Issuerd admin API.
- **Client payload is the admin `ClientRepresentation`** (Keycloak's own shape, not the RFC 7591 metadata spelling), so registered and admin-managed clients validate identically (shared scope seeding, shared client_id conflict check, secret generated for non-public clients, secret/scope-mappings preserved across PUT). `client_id` is auto-generated when omitted. Two fields are deliberately fenced off because Issuerd has no client-registration policy engine (Keycloak's `ClientRegistrationPolicy`): caller-supplied **`protocol_mappers` are silently dropped** (an unchecked `oidc-audience-mapper` would let an anonymous registrant mint tokens naming any resource server in the realm), and **`enabled` is admin-only** — a PUT cannot flip it, and a disabled client's registration access token stops working (uniform 401). Mapper attachment and enablement stay available through the admin API.
- **Registration mutations are audited**: create/update/delete write an `AdminEvent` (resource path `clients/{id}`, no representation — it would carry the secret), gated on `admin_events_enabled` like the admin API.
- **Error codes follow RFC 7591 §3.2.2** (`invalid_redirect_uri` / `invalid_client_metadata`) rather than Keycloak's 400s; a duplicate `client_id` maps to `invalid_client_metadata` (RFC 7591 defines no conflict code). Bearer failures are a uniform 401 with `WWW-Authenticate` (unknown client == bad token).
- **The open endpoint is per-IP rate-limited** (50 registrations/hour, fixed window in the distributed cache) → 429 `rate_limited`; Keycloak has no equivalent. The token-gated endpoint needs no rate limit (the initial access token is the throttle).
- **Discovery advertisement** points at the `openid-connect` (token-gated) path, Keycloak's spelling.

## Pairwise Subjects (OIDC Core §8)

**Keycloak does not implement pairwise subject identifiers** (the
long-standing upstream request KEYCLOAK-5460 is unimplemented; every Keycloak
token carries the internal user id as `sub`). Pairwise subjects are therefore
a feature beyond Keycloak parity rather than a behavioral match; the design
follows OIDC Core §8 and uses the OIDC dynamic-registration metadata
spellings.

- **Attribute spellings follow OIDC Core §8.1 registration metadata**: `subject_type` (`public` default | `pairwise`) and `sector_identifier_uri`, carried in the client's `attributes` map. Keycloak has no equivalent attributes.
- **Derivation**: `sub = base64url(HMAC-SHA256(sector_key, sector_identifier || user_id))` (no padding). `sector_key` is a per-realm secret stored in the realm attribute `pairwise_sector_key`, generated at realm creation and backfilled for pre-existing realms by storage seeding (stable across restarts and cluster nodes). The key is visible to realm admins via the attributes map (they can read internal user ids directly anyway); rotating it changes every pairwise subject of the realm.
- **Sector identifier**: host of `sector_identifier_uri` when set — the document is fetched and validated at registration time (admin create/update client, DCR register/update): it must be a JSON array of URI strings listing every registered redirect URI, else 400. Without a sector URI, all registered redirect URIs must share one host; multiple hosts are rejected at registration. Issuance never fetches the document. The §8.1 `https`-scheme requirement **is** enforced (the fetch is unauthenticated-reachable via open DCR, i.e. an SSRF surface): the fetch goes through `BrokerClient::get_json_untrusted` — https only, publicly routable resolved IPs, no redirects, 64 KiB body cap, and one generic `sector_identifier_uri could not be fetched` error for every failure mode (details logged server-side only).
- **Refresh and logout tokens are pairwise too** (beyond the minimum list of ID token / access token / userinfo / introspection): refresh tokens are client-readable JWTs, so a public `sub` there would let colluding clients correlate users across sectors; the refresh grant resolves the user through the token's session (`sid`) instead of `sub`. Backchannel logout tokens carry the pairwise sub because the client must correlate the logout with the subject it knows from its ID tokens.
- **Server-side user resolution is session-first** wherever an access-token `sub` must be mapped back to a user (userinfo, token exchange subject validation): pairwise subjects are keyed HMACs and cannot be reversed. Sessionless tokens (client credentials) still resolve via the public `sub`.
- **Client-credentials subjects are exempt**: the synthetic subject (`sub = client_id`) and the per-client service-account user (`service-account-{client_id}`) are already unique per client, so derivation is skipped for them.
- **Discovery**: `subject_types_supported` is `["public", "pairwise"]` for every realm (always available; per-client opt-in).

## Passwordless Email-Code Login (Issuerd extension)

- **Issuerd**: ships an `auth-email-code` browser authenticator
  (`issuerd-auth-flow/src/email_code.rs`) — a 6-digit single-use code mailed
  to the user (localized `email/login-code.*` template), with resend and
  attempt/send caps, enabled per realm via the `email_code_login` attribute.
  Realm attributes `email_code_ttl_secs` (default 300) and
  `email_code_length` (default 6) tune the code.
- **Keycloak**: has no stock email-OTP browser authenticator (only
  TOTP/WebAuthn second factors); comparable setups require community plugins.
- **Resolution**: intentional extension, no parity target. The authenticator
  is used as an `ALTERNATIVE` stage next to `auth-cookie`, mirroring how
  `auth-username-password` sits in the default browser flow.

## Registration Hint on the Authorize Endpoint (Issuerd extension)

- **Issuerd**: the authorize request accepts `registration=true` — when the
  realm allows self-registration and the request would render the login page,
  the browser is redirected to the registration form instead (carrying the
  paused flow's execution id), and the login flow resumes after the account
  is created: the user lands on the client redirect, signed in, without a
  second password prompt. Any other value (or absence) is ignored;
  SSO-completable requests and realms with registration disabled are
  unaffected.
- **Keycloak**: has no such authorize parameter — registration is reachable
  only from the login page's register link, and Keycloak's `kc_action` covers
  required actions, not registration.
- **Resolution**: intentional extension, no parity target. Lets applications
  offer a Register button that behaves exactly like their Login button
  (deep-link `returnUrl` semantics) instead of stranding the user on a
  standalone registration page.
