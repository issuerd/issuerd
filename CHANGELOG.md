# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## How to update

- Every pull request adds an entry under `## [Unreleased]` in the fitting
  category: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- Write entries for the reader of the release notes, not for the author of the
  diff: what changed from a user/operator perspective, plus any required action
  (migration, config change, deprecation window).
- PRs with no user-visible impact (CI, docs, pure refactorings) skip this via
  the `no-changelog` label; the `Changelog` workflow enforces the rule.
- On release: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a
  fresh empty `## [Unreleased]` section above it, and bump
  `[workspace.package] version` in `Cargo.toml` accordingly.

## [Unreleased]

### Added

- **Complete same-realm MCP read inventory (Phase 1B).** The endpoint now exposes 23 curated read tools, adding `serverinfo_get`, `events_search`, `sessions_list`, `keys_list`, `client_scopes_list`, `idp_list`, `idp_get`, and `flows_list`. The new outputs preserve Admin filtering and retention behavior while omitting private keys, audit representations, arbitrary authenticator configuration, IdP credentials, and raw protocol-mapper configuration. Dynamic server capabilities come from the same composition-root service as the Admin API, and every tool participates in dual-era schema, role/scope, strict-DPoP, and external TypeScript acceptance coverage. ([#39](https://github.com/issuerd/issuerd/issues/39))
- **User-directory MCP read tools (second Phase 1B batch).** The read-only endpoint now exposes `users_get_groups`, `users_get_role_mappings`, `users_get_sessions`, `users_get_credentials`, and `attack_detection_status`, bringing the inventory to 15 tools. Role mappings distinguish direct, available, and effective realm/client roles; sessions use curated Admin fields; credential output contains only scalar metadata without secret or credential-data payloads; attack status aggregates real distributed failure and lockout state and requires `manage-users`. All tools have strict schemas, repeated scope/role checks, Admin parity, redaction, dual-era `rmcp`, strict-DPoP, and external TypeScript acceptance coverage. ([#39](https://github.com/issuerd/issuerd/issues/39))

### Fixed

- **Phase 1C MCP read correctness.** `users_get_role_mappings` now returns a tool error instead of incomplete direct/available/effective mappings when group role reads fail. The `attack_detection_status` output schema covers the full unsigned 32-bit failure-counter range while remaining compatible with the official TypeScript validator.

### Security

- **Reproducible build and test dependencies.** Container builds now verify the rustup installer, Python images use hash-locked requirements, Windows release builds enforce Chocolatey checksums, and the Flux installer and remaining Node base image are pinned. The fuzz lockfile is synchronized with current workspace dependencies.
- **ChatApp dependency security.** Upgrade FastAPI to 0.162.0 and Starlette to 1.6.0 to include fixes for host/path validation, endpoint dispatch, Windows StaticFiles SSRF, and urlencoded form resource limits.

## [0.2.0] - 2026-10-28

### Added

- **Read-only MCP server endpoint (Phase 1A).** `[mcp].enabled` exposes `POST /realms/{realm}/mcp` with `realm_get`, `users_search`, `users_get`, `clients_list`, and `clients_get`. The stateless dual-era Streamable HTTP server supports 2025-06-18, 2025-11-25, and 2026-07-28, authorization-filtered tools, curated secret-free DTOs, and distributed per-client+subject invocation limits. Same-realm exact resource provenance and realm roles are enforced on every call; DPoP is required by default, with an explicit Bearer compatibility mode and no downgrade in either direction. Protected-resource metadata now describes the real DPoP/Bearer profile and minimal `mcp:read` scope. ([#39](https://github.com/issuerd/issuerd/issues/39))
- **Group and role MCP read tools (first Phase 1B batch).** The same endpoint now also exposes `groups_list`, `groups_get`, `groups_members`, `roles_list`, and `roles_get` with curated hierarchy/role DTOs and no arbitrary attribute maps. Group configuration and role reads require realm read roles; group member reads require user read roles, matching the Admin API. Role pages are fetched on demand through the existing `Storage::list_roles` API and filtered before caller pagination, so empty pages do not read storage. All ten tools participate in filtered discovery, repeated policy checks, output schemas, distributed invocation limits, dual-era `rmcp` coverage, Admin parity checks, and the external TypeScript DPoP acceptance rigs, including paginated setup and fixture discovery in populated realms. ([#39](https://github.com/issuerd/issuerd/issues/39))
- **External TypeScript MCP acceptance client and read-only rigs.** `examples/mcp-admin` adds a pinned official-SDK public native CLI for authorization-code + PKCE + exact-resource issuance with DPoP, legacy and modern all-tool acceptance runs, idempotent lab setup, a finite in-memory local runner, and a PostgreSQL + Redis Compose rig. The CLI validates RFC 9207 issuer responses on success and error paths and keeps tokens, proofs, keys, cookies, and Authorization headers out of its JSON output.

### Fixed

- **MCP/OAuth protocol hardening.** Authorization responses now carry RFC 9207 `iss` on success and error paths, discovery advertises it together with public `none` client authentication, and authorization-code redemption accepts an omitted `redirect_uri` while retaining exact comparison when present. MCP resource requests require code + PKCE S256 and exact/native-loopback redirect matching, and access tokens carry trusted resource provenance alongside `aud`. Canonical realm URL construction now covers issuer/resource/DPoP paths, duplicate DPoP proofs are rejected, and nonces cannot be downgraded or consumed by an invalid proof.
- **MCP authorization and transport review remediation.** The strict resource code profile now also covers SPNEGO and resources introduced only at token redemption; stored code redirects are revalidated so a resource-less wildcard flow cannot be upgraded at redemption. Canonical special-realm issuers work across account, Admin authorization/audit, broker SSO, cookie authentication, and token exchange. MCP transport accepts standard default-port Host and valid media-header representations without late SDK rejection, rejects omitted non-default ports before authentication, and redacts invalid Origin configuration errors.
- **MCP/DPoP correctness and acceptance.** DPoP HTU comparison now applies URI syntax normalization without accepting backslash/control/whitespace-repaired targets, and mandatory fresh-nonce failures return 503 during both challenges and post-proof processing. No-`id` tool calls cannot consume invocation allowance, and their structural header errors retain precedence. `users_get` validates canonical UUID input. Acceptance now includes adapter-level authenticated SSE, modern resumption headers, strict-DPoP scope challenges, compatibility downgrades, expired tokens, and a window-stable concurrent two-node rate-limit test against real Redis.

## [0.1.24] - 2026-10-25

### Added

- **GHCR publication and cosign-signed container images.** Every tag release now also publishes `ghcr.io/issuerd/issuerd` with `latest`, `X.Y.Z`, `X.Y`, and per-architecture tags alongside Docker Hub. Both multi-arch manifests (Docker Hub and GHCR) are signed and verified by digest with keyless cosign (GitHub OIDC). The first GHCR package starts private; an organization owner must make it public once in Package settings, after which it stays public.


- **Built-in French (`fr`) message bundle.** Login-flow pages and outbound email now ship a complete French translation alongside English, German, and Simplified Chinese; it serves as the generic fallback for every `fr-*` region until a regional theme bundle refines it. `GET /admin/enums/locales` and `GET /admin/serverinfo` list it as a built-in (`French`); enable it per realm via `supported_locales` once internationalization is on. Theme overrides and per-key English fallback are unchanged. ([#1](https://github.com/issuerd/issuerd/issues/1))

- **Built-in Brazilian Portuguese (`pt-BR`) message bundle.** Login-flow pages and outbound email now ship a complete Brazilian Portuguese translation, selected explicitly by the full `pt-BR` locale tag. `GET /admin/enums/locales` and `GET /admin/serverinfo` list it as a built-in (`Portuguese (Brazil)`); enable it per realm via `supported_locales` once internationalization is on. Theme overrides and per-key English fallback are unchanged.

- **Keycloak-compatible exact client-ID filtering in the Admin API.** `GET /admin/realms/{realm}/clients?clientId=my-app` now returns a one-element list for an exact client-ID match and an empty list when no match exists. The filter takes precedence over `first`/`max`; requests without `clientId` retain the existing paginated behavior. ([#23](https://github.com/issuerd/issuerd/issues/23))

- **Built-in `mcp:read` / `mcp:write` client scopes (groundwork for the MCP endpoint).** Every realm now seeds two coarse, agent-facing authorization gates for the upcoming MCP (Model Context Protocol) admin endpoint. The scopes carry no protocol mappers (they emit no claims), are never part of the realm default/optional scope sets, and are never auto-assigned to newly created clients — an administrator assigns them to specific agent clients explicitly. They are also absent from the discovery document's `scopes_supported`; they will be advertised via the RFC 9728 protected-resource metadata instead. Existing realms gain the two scopes through the storage seeding backfill on next start. ([#39](https://github.com/issuerd/issuerd/issues/39))

- **RFC 9728 protected-resource metadata endpoint, gated by the new `[mcp] enabled` config key (default `false`).** `GET /.well-known/oauth-protected-resource` is an explicit `resource_metadata` alias for the master realm; the canonical per-realm route is `GET /.well-known/oauth-protected-resource/{issuer-path}/realms/{realm}/mcp` (RFC 9728 §3.1, including issuer path prefixes). Metadata uses only canonical realm names and advertises the realm issuer, built-in `mcp:read`/`mcp:write` scopes, and the shared `Algorithm::DPOP_SIGNING_ALG_VALUES_SUPPORTED` accept set. While disabled, both routes answer `404` indistinguishable from an unknown realm; existing configurations boot unchanged. Groundwork for the MCP endpoint. ([#39](https://github.com/issuerd/issuerd/issues/39))

- **RFC 8707 resource indicators, gated by the same `[mcp] enabled` key (fail-closed).** The `resource` parameter is honored at the authorization endpoint (plain, PAR-pushed, and JAR requests) and on `authorization_code` and `refresh_token` grants. The allowlist holds exactly one canonical realm-name value per realm — `{issuer_url}/realms/{realm}/mcp`, compared byte-for-byte — and at most one value per request; repeated parameters are rejected with `invalid_target`. A granted resource becomes the access token's `aud` (`[client_id, resource]`, preserved through validation and introspection) and rides the refresh token as a `resource` claim: code redemption may restate, omit, or introduce it, while refresh may only restate or omit. Other grants refuse `resource` when MCP is enabled; supported flows carrying it while disabled fail closed with `invalid_target`, except token exchange, which keeps its legacy ignore behavior while disabled. Requests without `resource` are unchanged. ([#39](https://github.com/issuerd/issuerd/issues/39))

- **In-repo cargo-fuzz harness for the OIDC/OAuth2 parsers.** A new detached `fuzz/` workspace (never part of the default build) ships three libFuzzer targets exercising the pure `issuerd-protocol` parsing/validation entry points: authorization-request parsing, token-request parsing, and PKCE verifier/challenge verification (the PKCE target also asserts the computed-challenge roundtrip invariant against the RFC 7636 length window). No runtime, API, or dependency changes for the daemon — the targets exist for local security testing and the OpenSSF Scorecard "Fuzzing" check; run them with `cargo +nightly fuzz run <target>` from `fuzz/` (requires `cargo install cargo-fuzz` and a nightly toolchain).
- **Release assets now ship cosign signatures.** Starting with the next tag release, every archive, SBOM, the conformance-evidence bundle, and `SHA256SUMS.txt` on the GitHub Release carry a `*.sig` signature and `*.crt` certificate produced by cosign in keyless mode (GitHub OIDC identity, Rekor transparency log) — no project key to manage. Verify with `cosign verify-blob --signature <asset>.sig --certificate <asset>.crt --certificate-identity-regexp 'https://github.com/issuerd/issuerd/.github/workflows/release.yml.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <asset>`.

### Changed

- **MCP rollout and downstream Rust migration.** Keep `[mcp] enabled = false` until every cluster node runs the resource-aware version: older nodes drop the refresh-token `resource` claim during rotation. Reconcile legacy custom `mcp:*` scopes before enabling; MCP-enabled startup rejects unsafe definitions and default assignments. Public structs including `AuthorizationRequest`, `TokenRequest`, and `RefreshTokenClaims` gained a `resource: Option<String>` field (downstream literals need `resource: None`), and `OAuth2ErrorCode` / `IssuerdError` gained `InvalidTarget` variants (downstream exhaustive matches need an arm). `AdminApiState` also gained `mcp_enabled: bool`; downstream struct literals should set it to `false` to preserve legacy behavior. `TokenIssuer::issue_refresh_token` keeps its original signature; resource-aware issuance uses the additive `issue_refresh_token_with_resource` extension.

- **Required-action continuation provenance.** `PendingActionsData` gained optional `auth_method` and `method_label` fields so broker and SPNEGO authentication methods survive continuations. Existing cached entries deserialize with the legacy password fallback. Rust embedders constructing the public struct literally should set both fields to `None` for the old behavior, or the appropriate method/label for a federated flow.

### Fixed

- **Release artifact checkout order.** `actions/checkout` runs before artifact downloads, so downloaded release assets are not removed before the idempotent upload step. ([#81](https://github.com/issuerd/issuerd/pull/81))

- **Cosign v3 keyless release signing.** Cosign is pinned to v3.0.6 and uses its detached-file compatibility mode so the promised `.sig`/`.crt` assets are produced instead of failing on new bundle-format defaults. ([#76](https://github.com/issuerd/issuerd/pull/76))

- **Release jobs on hosts without Docker.** The two PostgreSQL MCP backfill tests now probe Docker availability and skip gracefully instead of panicking on a missing socket. They continue to run against real PostgreSQL testcontainers wherever Docker is available, restoring Windows ARM64, macOS, and glibc 2.28 release coverage. ([#74](https://github.com/issuerd/issuerd/pull/74))

- **Idempotent GitHub Release asset uploads.** The release job now uploads only missing assets and publishes only after all 48 are present. Retries no longer delete or rewrite existing assets, so a partial failed release can resume without API races or losing previously uploaded files. ([#79](https://github.com/issuerd/issuerd/pull/79))

- **Audience and resource-protocol correctness.** Multi-audience JWTs now round-trip every `aud` entry through typed validation and introspection instead of dropping all but the first. Resource metadata and allowlists use canonical realm-name URLs (including issuer path prefixes), and repeated `resource` parameters are rejected before query/form deserialization can make them order-dependent.
- **MCP scope onboarding and upgrade hardening.** With MCP enabled, anonymous DCR can no longer self-assign `mcp:*`; default assignments are rejected across Admin/provisioning/realm-default paths and optional-only assignment is enforced at issuance. Disabled legacy scopes keep their previous behavior. Legacy custom definitions and open-DCR assignments are validated before MCP starts, and concurrent built-in PostgreSQL backfills no longer abort on duplicate-key conflicts.

### Security

- **Failed provisioning is retryable instead of being recorded as complete.** First-boot provisioning now writes `in_progress` before applying resources and `applied` only after every step succeeds. Other nodes wait for completion rather than accepting a partial configuration, failures clear the marker for a same-marker retry, and an interrupted stale marker fails visibly instead of silently skipping provisioning. Built-in PostgreSQL, in-memory, and JSON backends persist marker deletion; external `Storage` implementations retain a fail-closed compatibility default. **Upgrade note:** a failure recorded as `applied` by an older version is indistinguishable from success; use a new marker once to retry such a deployment.
- **SPNEGO no longer bypasses consent or required actions.** The Kerberos endpoint now uses the shared login-completion path, so consent-required clients pause for a grant and pending required actions finish before any SSO session or authorization code is created. Required-action evaluation failures abort login, `prompt=none` returns protocol errors instead of interactive pages, and malformed nonce/response-mode values are rejected. Broker and SPNEGO continuations preserve their actual authentication method in sessions and audit events rather than degrading it to `password`.
- **Logout revokes remember-me tokens, not just their browser cookies.** SPA and RP-initiated logout record an expiring revocation entry for each presented token's signed `jti`, and remembered authentication rejects revoked tokens and revocation-store read failures. A copied cookie therefore cannot silently recreate a session after logout. Revocation writes fail with a retryable error rather than reporting successful logout without recording revocation; existing remember-me idle lifetimes are unchanged. Like other cache-backed revocation state, these entries do not survive a Redis wipe or an in-memory-cache restart; use durable Redis persistence when that guarantee is required.
- **Deleted sessions cannot be resurrected by delayed cache writes.** Positive session snapshots now carry the unique per-session invalidation tombstone observed while loading, and every cache hit revalidates it. Logout and session deletion rotate the bounded 24-hour tombstone before removing the snapshot, so an in-flight read cannot make a deleted session valid again, including after repeated invalidations.
- **Rendered userinfo entries cannot be stamped with newer invalidation counters.** Generation counters are captured before claims rendering and used verbatim for the cache write, so a mutation between rendering and insertion invalidates the old body on the next request instead of making it appear fresh.
- **Composite role expansion no longer picks arbitrary same-named client roles.** A realm-role fallback to a client role now requires that role name to be unique across clients; ambiguous legacy references grant nothing rather than privileges from an arbitrary client. Valid realm, same-client, and unique cross-client composites remain supported.
- **Passwordless login rejects ambiguous email identifiers.** When multiple accounts share an email address, email-code login no longer selects the backend’s first match; it sends no code and binds no account, preserving uniform anti-enumeration challenges and the unique-username fallback.
- **The account API is restricted to first-party interactive sessions.** Only `account-console` and `admin-cli` access tokens with a live stored user session are accepted; arbitrary relying-party and sessionless client-credentials tokens receive 401. This closes the path from an ordinary RP token to email, password, MFA, and linked-account changes. Custom callers must migrate to the first-party flow.
- **TOTP replay protection is atomic on every verification path.** Browser, password-grant, admin-token, and device verification now claim a matched step through `consume_totp_step` before succeeding, so concurrent submissions of the same code have exactly one winner instead of all passing the old read-modify-write check. Losing the race rejects the login/grant; storage errors remain fatal.
- **TOTP replay watermarks have an atomic storage primitive.** The new `consume_totp_step` operation advances only when the stored step is older, returning false for stale, replayed, missing, or wrong-type credentials. PostgreSQL uses a single conditional `jsonb_set` update; in-memory and JSON backends use one entry lock. Concurrent bursts have exactly one winner, and rejected JSON calls do not rewrite the snapshot.
- **Consent lookup failures no longer skip consent.** Authorization and login completion now return `temporarily_unavailable` when stored grants cannot be read, rather than treating the failure as permission to issue a session or code without a consent screen. Normal stored-grant and `prompt=consent` behavior is unchanged.
- **Broker transport requires secure channels by default.** IdP discovery, JWKS, token, and userinfo calls now require HTTPS and reject every HTTPS-to-HTTP redirect hop, preventing code, verifier, secret, and bearer-token disclosure through cleartext transport or downgrade redirects. Internal development IdPs retain the explicit `allow_private_identity_providers` escape hatch, including plain HTTP.
- **Required actions can no longer disappear on failures.** Broker login uses `try_evaluate` and detects registry, storage, and explicitly assigned unknown-action errors before issuing a session or code. Required-action GET/POST continuations return generic operational errors instead of silently dropping unknown actions, preserving entries for retry where applicable.
- **Administrative password writes always validate plaintext.** User creation and password reset now reject password credentials without a plaintext `value`, closing the raw `secret_data` path that bypassed password policy and history. Rejected resets leave existing credentials unchanged; opaque secrets for non-password credential types remain supported.
- **Aggregate Admin API reads enforce their specific capabilities.** Full realm export now requires `manage-realm`, and group-member listings require `view-users` or `manage-users`; `view-realm` alone can no longer retrieve every user/client or full member profiles. Authorized responses and credential redaction are unchanged.
- **Explicit authentication-flow bindings fail closed.** Internal authorization, login, and registration paths now use strict flow resolution: storage errors and missing explicitly bound aliases abort with generic server errors instead of silently selecting a password-capable default. Only unbound legacy realms may use the code fallback after a successful flow-list load. The legacy public wrapper remains for embedder compatibility.
- **SPNEGO enforces PKCE instead of discarding malformed challenges.** Public clients must present a valid S256 challenge, and non-S256 or malformed values are rejected before session/code creation. This closes the previous `.ok().flatten()` path that could silently turn malformed PKCE into a code without a verifier.
- **Password brute-force configuration and federated first import fail closed.** A realm lookup error can no longer silently disable lockout checks and failure recording. Invalid federated usernames now return an authentication error instead of panicking during first-login import, matching the per-record sync behavior.
- **Back-channel logout and guarded fetches use SSRF-safe transport.** Back-channel callbacks now require HTTPS and publicly routable addresses, refuse redirects, and pin DNS validation to the exact addresses dialed, closing rebinding and internal-POST paths. Internal HTTPS callbacks require explicit `[outbound_http] allow_private_addresses = true`; private CAs use `extra_ca_bundle`. Delivery remains best-effort and API compatibility is preserved.
- **Email-code login rechecks account enablement at verification.** Disabling an account after a code is issued now prevents that code from authenticating; storage errors fail closed and the existing uniform challenge behavior is preserved.
- **The convenience admin-token endpoint enforces the complete authentication policy.** It now applies the same out-of-band second-factor gate as password/device grants (with an optional `totp` request field and replay/lockout handling), rejects pending required actions, and refuses a disabled `admin-cli` client before creating a session or issuing an Admin-API-capable token.
- **MFA and required-action evaluation fail closed on operational errors.** Optional/Conditional stages no longer turn storage, cache, configuration, or cryptographic failures into password-only success; malformed assertions still re-challenge. Built-in required actions expose a backward-compatible `try_evaluate` API whose errors abort final evaluation instead of silently dropping password updates, email verification, profile updates, TOTP enrollment, or terms enforcement. Unknown optional authenticators and registry-listed missing actions also fail closed.
- **Pairwise sector keys no longer leak through administration reads.** The HMAC secret is omitted from realm GET/list/create responses, full exports, create/update audit bodies, and legacy admin-event representations while remaining accepted for deliberate rotation and preserved on redacted updates. Previously disclosed keys are not automatically rotated.
- **Local demo and test stacks no longer listen on every host interface.** Root, integration, cluster, and agentic-MCP Compose port publications bind to `127.0.0.1`; container-to-container networking is unchanged. The cluster load balancer has a static address and is the only trusted proxy, preventing peer containers and the NAT gateway from spoofing forwarded client IPs. Remote evaluation now requires an explicit secure tunnel/proxy rather than an all-interface listener.
- **Federation sync isolates malformed directory records.** Invalid overlong or control-character usernames now count as per-record failures with sanitized bounded logging instead of panicking and aborting the entire synchronization. Valid additions, updates, and group reconciliation continue without normalizing the rejected identity.
- **CIBA lifetimes are bounded and logout failures are truthful.** `requested_expiry` is capped at 600 seconds, preventing arithmetic panics and effectively permanent cache entries. SPA and RP-initiated logout now require durable session deletion before cache invalidation, client notifications, or success responses; storage failures return an error suitable for retry.
- **Email verification continuations are bound to the verified identity.** A verification token can clear `VERIFY_EMAIL` only from a continuation in the same realm and for the same user; an independently supplied execution ID can no longer advance another account's login. Mismatches return the generic expired-link response without modifying the continuation.
- **Authorization responses reject active-content redirect schemes.** `javascript:`, `data:`, and `vbscript:` URIs are refused at registration and again at the shared response-delivery sink, preventing auto-submitted `form_post` responses from executing script in the issuer origin. HTTP(S) and native-application custom schemes remain supported, and legacy stored values fail closed without a redirect or HTML page.
- **Disabled identities are rejected across alternate issuance and account paths.** Existing SSO cookies and account tokens now require an enabled user, final browser-login completion rechecks it, and disabled service accounts can neither mint client-credentials tokens nor use existing sessionless tokens. User resolution no longer returns disabled users for token claims.
- **Peer nodes reload signing keys on every relevant metadata change.** JWKS polling now uses an order-independent fingerprint of the complete stored keys rather than only key IDs, so disabling a key or changing its algorithm/material propagates without waiting for a key addition or node restart. Admin- and poll-triggered reloads are serialized.
- **Console token refresh is bound to the owning OAuth client.** Token sets are stored per realm and client, and the standalone account console now refreshes as `account-console` instead of `admin-cli`, preventing failed refreshes and unintended shared-SSO logout. Legacy admin token sets migrate as `admin-cli`; pre-migration account sessions require a fresh login rather than guessing ownership.
- **Client-role management can no longer escalate delegated administrators.** Dedicated composite additions and client-role create/update now compare the old and new effective role closures and reject newly introduced realm-management roles the caller may not grant. Existing privileges can still be retained or removed, and non-admin composites are unchanged.
- **Refresh-token rotation and revocation now contain replay.** Refresh tokens are claimed atomically so exactly one concurrent redemption succeeds; presenting an already-rotated token validates its client and realm, then revokes the backing session and descendants. RFC 7009 revocation enforces token ownership, falls back to the actual token type when the hint is wrong, and token exchange fails closed when the revocation store is unavailable.
- **Client/user identifier collisions and cross-realm authorization codes are contained.** Sessionless client-token detection no longer treats `sub == client_id` as sufficient when a real user has that ID, closing synthetic-client impersonation and post-logout renewal paths; ambiguous storage failures fail closed. Authorization codes now carry and are stored under their issuing realm, and redemption verifies that binding. Codes minted before this upgrade are rejected during their short TTL rather than risk cross-realm redemption.
- **Federated and passkey authentication enforce current identity state.** Disabled federated identities are rejected before first-login import, and a WebAuthn assertion no longer succeeds when its credential was deleted after the challenge; the verified credential must still exist uniquely and its counter update must persist.
- **JSON-file snapshots protect key and credential material.** On Unix, new and rewritten snapshots are owner-only (`0600`), and persistence uses a synced same-directory temporary file plus atomic rename instead of truncating the live snapshot in place. Existing snapshots are tightened when loaded and rewritten. In-memory mutation rollback on persistence failure remains unchanged.
- **External ID-token and authorization-response validation is stricter.** Broker ID tokens now require the expected audience and, when configured, issuer, and honor `nbf`. Authorization requests carrying ID or access tokens can no longer select `query` or signed-only `query.jwt`, which exposed credentials in redirect URLs; pure authorization-code query responses remain supported.
- **RustCrypto timing-safety update.** `p256`, `p384`, and `p521` move to 0.14, bringing `crypto-bigint` to 0.7.6 and fixing RUSTSEC-2026-0387 (timing variability in operations intended to be constant-time). No operator action required.
- **Dependency security updates.** `ctutils` 0.4.3 → 0.4.5 (RUSTSEC-2026-0385, non-constant-time comparisons), `tokio` 1.53.1 → 1.54.1 (RUSTSEC-2026-0386, `AsyncFd` I/O-safety soundness), and the web client's transitive `js-yaml` pinned to 4.3.2 via an npm `overrides` entry (GHSA-2883-xcg3-v3hh, GHSA-52cp-r559-cp3m, GHSA-5p4m-2wfm-xmqj — CPU-exhaustion YAML parsing issues in a build-time-only codegen dependency). No operator action required.
- **Web client HTTP parser security update.** The transitive `undici` dependency is pinned to 7.30.1 via npm `overrides`, covering GHSA-4qv8-2p9j-2685, GHSA-f72v-6w45-q472, and GHSA-xjj6-f33q-929c (EventSource memory exhaustion, mixed-case SRI algorithm bypass, and content-encoding process crash). No operator action required.

## [0.1.19] - 2026-10-22

### Fixed

- **RP-Initiated Logout errors now identify the actual failure.** Missing or invalid `id_token_hint` values and unknown `client_id` values no longer produce the misleading `invalid post_logout_redirect_uri` description. An invalid hint is rejected even when a valid `client_id` and registered post-logout target are also supplied; valid client-only logout redirects remain supported.

## [0.1.18] - 2026-10-21

### Added

- **New release archive for older Linux systems (`linux_amd64_glibc228`).** Tag releases now also ship `issuerd_<version>_linux_amd64_glibc228.tar.gz` — an x86_64 binary built on a glibc 2.28 toolchain (the canonical `linux_amd64` build targets glibc ≥ 2.35), for systems too old to run the canonical binary. OpenSSL 3 is statically linked into this variant, so its only runtime requirements are glibc ≥ 2.28 and the Kerberos GSS-API libraries (`libgssapi-krb5-2`); functionality is identical. The variant is best-effort: it may be dropped from future releases without notice once its upstream build inputs (the Rust toolchain's glibc baseline, Node.js, OpenSSL, webauthn-rs) no longer build on a glibc 2.28 toolchain.

### Security

- **Admin API tenant isolation and credential handling are hardened.** Realm binding now uses the same percent-decoded realm as the handlers, DPoP-bound-as-Bearer, revoked, and session-ended tokens are rejected, and only `admin-cli` or a custom client with `admin_api_access = "true"` can call the Admin API (ordinary relying-party tokens no longer work even with admin roles). Custom automation must be opted in by a `manage-realm` administrator; open dynamic registration cannot self-enable it. Admin-role grants are restricted to callers allowed to hold them, and service-account users are resolved by a deterministic client-UUID-linked identity rather than a username, closing pre-existing `service-account-*` squatting. Once the linked account exists, an unlinked legacy account occupying its conventional name is disabled without copying roles, and the Admin API refuses to re-enable it. **Action:** review legacy service-account users and reassign any intended roles to the new linked accounts once after upgrading.

- **Password and second-factor checks close enumeration, throttling, and reset bypasses.** LDAP federation rejects empty passwords before any bind. Unknown, disabled, locked, and hash-less accounts now incur dummy Argon2 verification on browser, admin-token, password-grant, and device paths; not-yet-imported federated users share the realm brute-force lockout, and password-reset mail is sent in the background so its latency no longer reveals accounts. Email-code login uses atomic per-code attempt counters and non-resettable per-user send budgets, with per-source send/verify caps and atomic single-use consumption; burning a code or racing parallel flows no longer resets or exceeds the limits, one source cannot consume the code reserved for another, and stale attempts cannot burn or overwrite a reissued code or extend its TTL.

- **Protocol, mapper, and tenant-input hardening.** Security-critical token claims cannot be forged through user-controlled protocol mappers, and the OIDC `claims` parameter releases PII only with the matching granted scope. Other fixes cover Windows drive-prefixed theme paths, cookie-attribute injection through malformed flow ids, recursive flow validation stack exhaustion, glob metacharacters in brute-force resets, forwarded-IP spoofing, cross-realm Kerberos principals, global SMTP credential redirection, read-only IdP/LDAP secret disclosure, and the integration BIND resolver's recursion ACL and loopback-only port.

- **Redis-backed security state fails closed and cannot be evicted.** All shipped compose stacks now use `maxmemory-policy noeviction`, preventing unauthenticated traffic from evicting refresh-token rotation/revocation, replay, or lockout markers. Revocation/rotation writes, replay teardown, and brute-force counters no longer ignore cache failures; revocation reads also fail closed, returning `503 temporarily_unavailable` where applicable rather than accepting a token or login. PAR, pending-login, and device payloads are capped at 64 KiB before cache insertion to reduce memory pressure. A Redis wipe still removes these entries, so continue to use the durable realm `notBefore` cutoff when revocation must survive it.

- **The in-memory/JSON-file master-realm bootstrap no longer seeds `admin`/`admin`.** The bootstrap `admin` user's password now comes from the new optional `bootstrap_admin_password` config key (env `ISSUERD_BOOTSTRAP_ADMIN_PASSWORD`); when it is unset or empty, a random password is generated and printed once to stderr. Previously `issuerd daemon` without a config file (including the bare Docker image) exposed a full master-realm admin with the well-known password on `0.0.0.0:8080`. **Action:** scripts that log in as `admin`/`admin` against an in-memory/JSON-file rig must set `bootstrap_admin_password = "admin"` (the root `issuerd.toml` dev rig and the conformance rig now do). PostgreSQL deployments, the Docker demo stack, and other provision-file-defined admins are unaffected.

- **Identity-broker calls are SSRF-gated (breaking default).** IdP discovery, JWKS, token and userinfo requests and the admin `identity-provider/instances/{alias}/test-connection` probe now dial only publicly routable addresses — every resolved address and every redirect hop is checked — and cap the response at 1 MiB, so a realm admin with `manage-realm` can no longer aim them at the internal network or cloud metadata endpoints. **Action required** for an IdP on a private, loopback or otherwise non-public address (internal Keycloak/ADFS, Keycloak in Docker, a `localhost` dev IdP): set the new `[outbound_http] allow_private_identity_providers = true` (env: `ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_IDENTITY_PROVIDERS`), which restores the previous unrestricted behaviour for IdP calls only (the body cap stays). Behind an outbound proxy set via `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, the IdP host must also resolve locally and only same-host redirects are followed; without those variables, IdP calls no longer use OS-configured proxies.
- **First broker login no longer auto-links onto an unverified local email (account pre-hijacking).** With `trustEmail=true`, an external identity was auto-linked to any local account holding the same address — even one whose owner had merely typed that address in (self-registration, account console) and never verified it, so an attacker could pre-claim a victim's address and capture their later IdP sign-in. Auto-link now also requires the local account's `email_verified`; otherwise the user gets the link-via-password page. Verify-email links are now bound to the address they were mailed to: redeeming one after the account's email changed no longer marks the new address verified. Behavior changes: realms whose local users have unverified emails see the link-via-password page instead of auto-link; verify-email links issued before the upgrade (24 h lifetime) are refused — request a new one.
- **IdP role mappers under `syncMode=force` now revoke the roles they granted once the claim stops matching.** Previously a role granted from an IdP claim (e.g. a group) outlived its removal at the IdP. Revocation is limited to roles the provider's mappers actually added — recorded per provider in the user attribute `idp_mapped_roles.{alias}` — so roles assigned locally or by another provider are never removed, and new links (auto-link, link-via-password) never revoke. Roles a mapper granted before this release carry no such record and are not revoked automatically — review holders of IdP-mapped roles once after upgrading.
- **Single-node (no `redis`) deployments: expired in-memory cache entries are now freed.** The built-in in-process cache only dropped an expired entry when that same key was read again, so keys written once and never revisited — abandoned login flows (`pending_auth:*`, reachable unauthenticated via `/auth`), DPoP and client-assertion replay markers — stayed in memory for the life of the process, and memory grew with total request count. Writes now sweep out all expired entries at most once every 30 s, bounding memory to entries still within their TTL (plus up to 30 s). No change to what any key returns or how long it lives; Redis-backed deployments are unaffected.
- **Client access tokens are no longer accepted as the browser SSO session cookie.** The `issuerd_session_{realm-id}` cookie was minted as a plain access token and validated as one, so any access token for a user's live session (held by every RP and resource server, or leaked from an implicit-flow fragment) could be planted as the cookie to take over that SSO session at every client in the realm, approve CIBA requests, or end the session. The cookie is now a dedicated JWT type (`typ: Serialized-ID`, Keycloak's identity-cookie type) that the token endpoint never issues; the authorization endpoint, the auth-cookie authenticator, CIBA approval, broker account linking and both logout paths accept only that type, and access-token validation (userinfo, introspection, account/admin APIs, token exchange) rejects it. Upgrade impact: SSO cookies minted before the upgrade stop resolving, so browsers holding one see the login form once.
- **The TOTP second factor is now throttled on every path that checks it.** Wrong codes in the browser flow only re-showed the OTP page, and the password grant (`totp` parameter, e.g. via `admin-cli`) and device verification never counted them. Anyone holding a user's password could guess the 6-digit code without limit. Every code check (browser OTP stage, password grant, device verification) now first reserves an attempt from one per-user budget in the login-failure tracker, shared by all three paths and across all source IPs. The attempt is counted before the code is checked, so parallel submissions cannot outrun the limit. Once the threshold of wrong codes is reached, no code is checked — the correct one is refused like a wrong one (the browser re-shows the OTP page, the token and device endpoints answer `invalid_grant`) until the lockout expires. After that one more code is checked, and a wrong one re-arms a longer lockout, as on the password path. The threshold and lockout follow the realm's brute-force settings when brute-force protection is enabled, and the built-in defaults (5 failures, 60 s lockout growing by 60 s per further failure up to 15 min, 300 s counting window) otherwise, so realms with protection off are throttled too. A correct code clears the budget; a successful password check does not. The entries appear in the attack-detection API with the IP `otp` and are cleared by the existing "clear user" call.
- **Web client dev tooling: `vite` 8.0.16 → 8.3.4** (floor pinned at `^8.1.6`), clearing the three `launch-editor` advisories (GHSA-r825-w8mm-5pxw CLI-flag command injection, plus the two Windows-specific escaping/existence-check issues) that Dependabot flagged against `webclientsrc/package-lock.json`. Dev-server-only dependency — nothing in the shipped SPA or the daemon is affected; SDK regeneration, eslint, the full Vitest suite, and the production build all pass unchanged.

- **`utoipa` 5.5 → 6.0.0 + `utoipa-swagger-ui` 9.0 → 10.0.2: the advisory-ignore list is now empty.** The swagger-ui 10.0.2 build dependency moved to `zip` ^9.0 (>= 9.0.0 is the patched line), clearing RUSTSEC-2026-0367 / -0368 / -0369 (zip extraction privilege-escalation trio — build-only exposure via the `vendored` Swagger UI archive, never linked into the daemon); the temporary ignores in `.cargo/audit.toml` and `deny.toml` are removed, so `cargo deny check advisories` and `cargo audit` pass with zero ignores. The utoipa 6 breaking changes do not affect this workspace (the `yaml` feature is unused; the `RefOr<SecurityScheme>` change touched one test). The regenerated OpenAPI document is byte-stable except `anyOf` branch ordering on `Option<T>` schemas (semantically identical); the web client SDK regenerated from it passes lint, all 1007 Vitest tests, and the production build unchanged.
- **`sqlx` 0.8 → 0.9.0: the last two dependency-audit exceptions are gone.** The 0.9 line moves its PostgreSQL TLS to `webpki-roots` ^1 (1.0.10, patched), eliminating the unpatched `webpki-roots` 0.26.x copy that `sqlx-core` 0.8 pinned (RUSTSEC-2026-0381 — bundled distrusted emSign root), and gates the MySQL driver's `rsa` dependency behind the off-by-default `mysql-rsa` feature, so `rsa` (RUSTSEC-2023-0071, Marvin — still no patched release) no longer appears even as a never-compiled lockfile entry; the `RUSTSEC-2023-0071` ignore in `.cargo/audit.toml` is removed. Code impact of the upgrade is nil: all queries use literal SQL with bind parameters (compatible with 0.9's `SqlSafeStr`), the embedded `sqlx::migrate!` runner is unaffected by the `Migrate` trait changes, and the deleted `runtime-tokio-rustls` combo feature is replaced by `runtime-tokio` + `tls-rustls` (identical ring-based rustls provider, same webpki-roots trust semantics — no operator-facing change).
- **`rustls-webpki` 0.103.15 → 0.103.16 and `webpki-roots` 1.0.9 → 1.0.10** fix two freshly published advisories covering the distrusted emSign intermediate CAs whose private keys are now public: RUSTSEC-2026-0382 (rustls-webpki could accept certificate paths containing those intermediates) and RUSTSEC-2026-0381 (webpki-roots bundled `emSign ECC Root CA - G3`). Both are patch-level bumps with no API changes.

## [0.1.17] - 2026-10-15

### Security

- **YAML parsing moved off the unmaintained `unsafe-libyaml` (RUSTSEC-2024-0449).** Server-config and provision-file YAML now parse and serialize through `serde-saphyr` (pure-Rust `granit-parser` backend, `#![deny(unsafe_code)]`) instead of the archived `serde_yaml`; figment keeps driving layered config via a custom in-tree `Format` provider, so `Yaml::file` semantics (file resolution, merge precedence with env/TOML/JSON) are unchanged. `serde_yaml`/`unsafe-libyaml` are out of the lockfile and the `deny.toml` advisory ignore for RUSTSEC-2024-0449 is removed. One intentional leniency change: an empty YAML config file now boots with defaults (matching empty TOML) instead of failing to parse. No operator action required — existing config and provision YAML keep loading unchanged.
- **`rustls` 0.23.45 → 0.23.46** fixes two freshly published advisories: RUSTSEC-2026-0346 (derived `Debug` impls on client session values could log TLS master secrets / resumption PSKs — issuerd never formats session-store values with `Debug`, so it is not affected in practice) and RUSTSEC-2026-0347 (ECH-rejection corner case; issuerd does not use ECH). Patch-level bump, no API changes.

### Added

- **Proptest coverage for the introspection/revocation and discovery parsers.** The RFC 7662 introspection and RFC 7009 revocation form parsers (`introspection.rs`) and the discovery wire types (`discovery.rs`: `SubjectType`, `TokenEndpointAuthMethod`, the `scope_vec` serde helper) now carry proptest suites with adversarial generators — empty, whitespace-only, over-long, non-ASCII and control-character values, near-miss parameter keys (`Token`, `token\0`) and near-miss hint spellings (`Access_Token`, `access_token `) — pinning that well-formed bodies parse and roundtrip byte-for-byte, that a missing `token` key is always `invalid_request` (400) regardless of what else the body carries, and that an unregistered `token_type_hint` is rejected with `invalid_request` whatever the token; arbitrary bodies never panic and the identical introspection/revocation parsers agree on every input. The discovery properties assert a string parses iff it is exactly a registered wire name and that `FromStr` and serde agree, with a compile-time guard that fails when a new enum variant is not added to the test lists. No new workspace dependencies: `proptest` was already a dev-dependency of the crate. ([#20](https://github.com/issuerd/issuerd/issues/20), [#34](https://github.com/issuerd/issuerd/pull/34))

## [0.1.16] - 2026-10-13

### Fixed

- **TOTP enrollment QR code is visible again in the account console.** The inline SVG returned by `POST /realms/{realm}/account/api/credentials/totp/start` carried only a `viewBox` and no intrinsic size, so the account console's React SPA rendered it at 0×0 (an empty white box) while the secret and `otpauth://` link showed fine. The SVG root element now carries explicit `width`/`height` attributes (240 px, scaled by the `viewBox`); the server-rendered required-action enrollment page is unaffected and unchanged. ([#35](https://github.com/issuerd/issuerd/issues/35))

## [0.1.15] - 2026-10-12

### Added

- **Built-in Chinese (Simplified) message bundle (`zh`).** The login-flow pages and outbound email now ship a compiled-in Simplified-Chinese translation alongside English and German; it serves as the generic fallback for every `zh-*` region (e.g. `zh-CN`, `zh-HK`) until a regional theme bundle refines it. `GET /admin/enums/locales` and `GET /admin/serverinfo` list it as a built-in (`Chinese`); enable it per realm via `supported_locales` once internationalization is on.
- **Regional locale variants in theme message bundles.** Bundle loading now layers the full BCP-47 tag over the primary language subtag — for `de-AT`: `messages_en.json` → `messages_de.json` → `messages_de-AT.json` — matching Keycloak's full-tag → language-subtag fallback, per key. This applies both to the compiled-in lookup slot (no built-in regional bundle ships today) and to theme bundles under `{themes.dir}/{theme}/`; the boot-time scan feeding `GET /admin/enums/locales` and `GET /admin/serverinfo` now exposes full tags (e.g. `de-AT`) from regional bundle file names.
- **`[outbound_http] allow_private_addresses` (test rigs only).** The new opt-in config key (env: `ISSUERD_OUTBOUND_HTTP__ALLOW_PRIVATE_ADDRESSES`, default `false`) lifts the public-IP check of the SSRF-guarded outbound fetches — client `jwks_url` documents, pairwise `sector_identifier_uri` documents, and JAR-by-reference `request_uri` objects — so they can dial private/loopback addresses such as a hermetic conformance network. The https-only scheme check, the no-redirect policy, the 64 KiB body cap, and the timeout stay enforced in both modes. Never enable in production: the address check is what keeps attacker-influenced URLs from probing the internal network.
- **Client branding on the login page.** A client carrying the `logo_uri` / `policy_uri` / `tos_uri` attributes (OIDC registration §2 metadata — settable via the Admin API attributes map or DCR) now has its logo rendered above the sign-in form and its policy/terms documents linked in a footer row while the user authenticates for that client. The login-context endpoint (`GET /realms/{realm}/login/context`) exposes them as `client_logo_uri` / `client_policy_uri` / `client_tos_uri` (plus `client_name` for the logo's accessible label) whenever the paused flow's client resolves; clients without the attributes get no markup change. Only absolute `http(s)` URLs render. This covers the Dynamic OP registration modules `oidcc-registration-logo-uri` / `-policy-uri` / `-tos-uri`.
- **OIDC Session Management 1.0.** Every successful authorization response now carries `session_state` (the SSO session id — the same value as the `sid` claim), and login writes the JS-readable companion cookie `issuerd_session_state_{realm}` with that value (`Path=/`; `SameSite=None; Secure` on TLS, `SameSite=Lax` on plain HTTP; refreshed on re-authentication, cleared on every browser-present logout path). The new OP iframe endpoint `GET /realms/{realm}/protocol/openid-connect/check_session_iframe` — advertised unconditionally as `check_session_iframe` in discovery — serves a self-contained page (ES5 JS, no external assets) answering the §4.2 postMessage protocol: `unchanged` when the cookie matches the posted `<client_id> <session_state>`, `changed` when it is absent or differs, `error` for malformed messages. RPs can poll session liveness from their own iframe; sessions ended out-of-band (admin delete, idle expiry) flip the answer at the next browser-present login/logout.
- **Extra CA bundle for outbound HTTP clients.** The new `[outbound_http] extra_ca_bundle` config key (env: `ISSUERD_OUTBOUND_HTTP__EXTRA_CA_BUNDLE`) points at a PEM file of additional root CA certificates trusted by every outbound HTTPS call the server makes — identity-broker metadata/JWKS fetches, client `jwks_url` documents, pairwise `sector_identifier_uri` documents, and back-channel logout POSTs. The bundle is additive to the public webpki roots; a missing file, unparseable content, or an empty bundle aborts the boot (fail closed). This is what real deployments behind corporate CAs (and hermetic test rigs with a private root CA) need.

- **Implicit and hybrid response types at the authorization endpoint.** `response_type=id_token token`, `code token`, and `code id_token token` are now accepted alongside the existing `code`, `id_token`, and `code id_token` (bare `token` remains rejected with `unsupported_response_type` — it is OAuth2-only). The authorization endpoint mints the access-token leg directly with the token endpoint's claims assembly (`token_type=Bearer` + `expires_in` included; implicit-issued access tokens never come with a refresh token and work at userinfo/introspection), and authorization-endpoint ID tokens carry alg-aware `at_hash`/`c_hash` whenever an access token / authorization code rides along. The fragment stays the default response mode for every token-bearing type, and form_post/JARM package the multi-value responses. Discovery advertises all six OIDC response types plus the `implicit` grant. PAR-pushed and JAR request-object flows share the same acceptance and nonce rules. The per-client `response_types` allowlist (settable via DCR) gates the new types as well.

- **RFC 7591/7592 conformance for dynamic client registration.** The `clients-registrations` endpoints now accept RFC 7591 request metadata alongside the Keycloak-shaped `ClientRepresentation` — `client_name`, `grant_types`, `response_types`, `token_endpoint_auth_method` (mapped onto the client authenticator; `none` forces a public client), `scope`, `subject_type`, `sector_identifier_uri`, inline `jwks` / `jwks_uri`, `initiate_login_uri`, `post_logout_redirect_uris`, the front/back-channel logout fields, `logo_uri`/`policy_uri`/`tos_uri`, `id_token_signed_response_alg`/`userinfo_signed_response_alg`, and a registrant-suggested `client_secret`. Invalid values fail with the RFC 7591 §3.2.2 errors (`invalid_client_metadata`; `invalid_redirect_uri` for malformed redirect/post-logout URIs — now including fragment-bearing ones, which were previously accepted; https-only for `initiate_login_uri`, `jwks_uri` and the logout/logo/policy/tos URLs; `none` and HMAC signing algorithms are rejected). Responses on create/read/update now also carry the RFC fields `registration_access_token` (alongside the Keycloak `registrationAccessToken`), `registration_client_uri`, `client_id_issued_at`, `client_secret_expires_at` and `client_secret`, plus an echo of every registered metadata field — RFC 7592 `GET` reads return the full current metadata. The Keycloak-shaped request/response path is unchanged, and the open (unauthenticated) endpoint's payload policy applies to RFC-spelled input exactly as before.
- **Per-client `post_logout_redirect_uris` attribute.** Clients can register a dedicated list of approved post-logout redirect targets (a JSON array of URI strings in the `post_logout_redirect_uris` client attribute, settable via DCR or the Admin API attributes map). When the list is present and non-empty, RP-initiated logout validates `post_logout_redirect_uri` against it (exact match or trailing-`*` prefix, same matcher as `redirect_uris`); when absent, the `redirect_uris` fallback keeps working for existing clients.
- **Per-client `id_token_signed_response_alg` is now honored.** A client registered with the attribute (DCR field or client attribute, e.g. `RS256`) gets its ID tokens signed with exactly that algorithm; clients without it keep the realm/server default. The pinning is strict: an unparseable value or an algorithm with no active signing key in the realm key set fails issuance loudly (HTTP 500) instead of silently falling back to another key.
- **Signed userinfo responses (`userinfo_signed_response_alg`, OIDC Core §5.3.2).** A client registered with the attribute receives the userinfo claim set as a signed JWT with `Content-Type: application/jwt` instead of plain JSON — the same claims the JSON body would carry, plus the server-set envelope (`iss` = realm issuer, `aud` = the client id, `iat`), signed with an active realm key for the registered algorithm (strict, like the ID-token pinning). Discovery advertises the realm's active signing algorithms as `userinfo_signing_alg_values_supported`.
- **JAR-by-reference (`request_uri`, OIDC Core §6.2 / RFC 9101 §4).** The authorization endpoint now accepts `request_uri` values beyond the PAR `urn:ietf:params:oauth:request_uri:` scheme: a client that registered `request_uris` (the DCR metadata array or the client attribute — https-only values, stored verbatim; the open registration endpoint strips them) may pass one of those exact URIs, and the server fetches the Request Object through the SSRF-hardened fetcher (https only, publicly routable IPs, no redirects, capped body) and runs it through the identical validation and merge path as an inline `request` object. `request` and `request_uri` in one request remain mutually exclusive (`invalid_request`), an unregistered URI is refused before any fetch, and a realm requiring PAR rejects non-PAR references. DCR also accepts `request_object_signing_alg` (validated, stored, echoed). Discovery now advertises `request_uri_parameter_supported: true`.
- **Discovery advertises both `id_token token` spellings.** `response_types_supported` now lists `token id_token` alongside `id_token token` (the parser has always normalized both orders to the same hybrid response type; the dual advertisement matches the OIDC registration metadata convention).

- **Logout `*_session_required` client flags honored.** Clients registering `frontchannel_logout_session_required = false` get front-channel iframe URLs called without the `iss`/`sid` query parameters, and clients with `backchannel_logout_session_required = false` receive back-channel logout tokens without the `sid` claim (the token correlates by `sub`, which is always present). Both default to `true`, preserving the previous always-include behavior for existing clients. Discovery keeps advertising `frontchannel_logout_session_supported` / `backchannel_logout_session_supported` as `true` (both modes are supported).

### Fixed

- **The built-in default login theme is now compiled into the binary.** Container images and `cargo install` builds ship no `themes/` directory, so every login-page render previously logged a 404 for `/realms/{realm}/theme/login.css` (the page itself was unaffected — the stylesheet only carries CSS custom properties, and the markup has matching inline fallbacks). The asset-serving chain is now on-disk realm theme → on-disk default theme → embedded default theme; operators mounting their own `themes/` see no change, and a custom `login.css` on disk still wins over the embedded copy.
- **DCR `response_types` now accepts the discovery-advertised `token id_token` spelling and rejects bare `token`.** Registration parses each entry through the protocol's `ResponseType` parser — both `id_token token` orderings register and are stored in the canonical `id_token token` spelling (previously `400 invalid_client_metadata` for the advertised alias). Bare `token`, which parses but is OAuth2-only and never accepted by the authorization endpoint, is now rejected with `invalid_client_metadata` instead of registering unusable metadata.
- **RFC 7592 client updates now re-apply the open-registration payload policy.** Clients created through the open (unauthenticated) registration endpoint carry a `dcr.policy=open` marker attribute; a `PUT` with the registration access token re-runs the open policy (JWKS-source/logout-URI/`request_uris` attribute strips, `service_accounts_enabled` forced off, redirect-URI scheme vetting) and re-stamps the marker, so the token can never resurrect a stripped attribute or shed the marker. The open policy additionally rejects logout-URI attributes with scriptable or non-loopback plain-http schemes outright (previously silently stripped). Trusted-path (initial-access-token) clients are unaffected.
- **JWT client assertions no longer require the `client_id` form field** (RFC 7523 §2.2). The token endpoint, the PAR/revoke/introspect endpoints, and the CIBA backchannel endpoint now resolve the client from an unverified peek at the assertion's `iss` (falling back to `sub`; both present but disagreeing is refused) when `client_id` is absent — signature verification against the resolved client's keys then gates exactly as before. Malformed assertions and missing iss/sub keep answering the uniform `invalid_client`. This fixes `oidcc-idtoken-rs256`-style code exchanges that send only `client_assertion`.
- **The `claims` request parameter's `id_token` section is now evaluated into issued ID tokens** (OIDC Core §5.5). Wherever an ID token is issued for a request that carried `claims` — the authorization endpoint (implicit and hybrid response types) and the token endpoint's authorization-code grant (the parameter rides the authorization code) — requested entries resolve from the user profile into the token: mapper-produced claims are never overwritten, unknown or unresolvable entries are omitted, and essential/voluntary marks are presence-based. The `userinfo` section semantics are unchanged (userinfo endpoint + the pure-implicit rider); the refresh, password, device and CIBA grants carry no `claims` context and are unaffected. This clears the OIDF suite's `oidcc-claims-essential` warning (`EnsureIdTokenContainsName`) on the implicit plans.
- **The `claims` request parameter's `userinfo` section is now honored in pure-implicit flows.** With `response_type=id_token` no access token is minted, so the userinfo endpoint cannot deliver userinfo-targeted requested claims (e.g. `claims={"userinfo":{"name":{"essential":true}}}`) — they now ride the ID token instead (OIDC Core §5.5, Keycloak parity; essential and voluntary entries alike; mapper-produced claims are never overwritten). Code, hybrid, and token-endpoint ID tokens are unchanged: userinfo serves those claims there.
- **Pure-implicit ID tokens now carry the full scope claim set.** With `response_type=id_token` no access token is minted, so the userinfo endpoint is unreachable for the client — the authorization-endpoint ID token now includes the UserInfo-targeted mapper claims (`website`, `zoneinfo`, `birthdate`, `gender`, `profile`, `middle_name`, `locale`, `picture`, `updated_at`, `nickname`, ...) alongside the IdToken-targeted ones (OIDC Core §5.4 permits this when userinfo cannot be reached; Keycloak behaves the same way). Hybrid and code flows are unchanged: their ID tokens stay lean and userinfo serves the rest.
- **RP-initiated logout without a redirect target now renders a sign-out confirmation page** (`200 OK` HTML, "You have been signed out") instead of an empty `204 No Content` — a browser-driven logout with no validated `post_logout_redirect_uri` leaves the user on human-readable feedback (the OIDF conformance suite's negative logout modules capture this page; Keycloak renders an equivalent info page). The front-channel interstitial and the redirect branches are unchanged; non-browser callers (form POST) get the same small HTML body.
- **The `openid` scope marker is always allowed at the authorization and token endpoints** (Keycloak parity). It is the OIDC protocol marker, not a client scope: previously a client whose scope lists omitted `openid` (notably a DCR-registered client seeded from the realm defaults) got `invalid_scope` on any OIDC flow or scope-carrying refresh. Other scopes are still enforced against the client's assigned lists.
- **Token-endpoint error responses now carry `Cache-Control: no-store` and `Pragma: no-cache`** (RFC 6749 §5.1 applies to errors too). Previously only success responses had them.
- **The canonical Dockerfile now copies `themes/` into the builder stage.** The embedded default login theme (new in this release) made the release build require `themes/issuerd/login.css` at compile time, but the Dockerfile's build stage never copied it — every image-based release job (linux amd64 binary, Docker Hub images, cluster E2E, conformance evidence) failed with `THEME_MISSING`. Native builds from a checkout were unaffected.

### Changed

- **Published-trait signature changes (0.1.x semver-tolerable, noted for downstream implementors).** `TokenIssuer::issue_logout_token` now takes `Option<&SessionId>` and gained `sign_userinfo_response`; `BrokerClient` gained the required `get_text_ssrf_guarded`. External implementors of these traits need a small update at upgrade; callers are unaffected.

- **`nonce` is now required for implicit and hybrid authorization requests (breaking-hardening, with per-realm opt-out).** (OIDC Core §3.2.2.1/§3.3.2.1 — `response_type` = `id_token`, `id_token token`, `code id_token`, `code id_token token`). A request without `nonce` fails at the authorization endpoint with an `invalid_request` error redirect (error description naming the nonce, `state` echoed, fragment-delivered per the response type's default mode) to the registered `redirect_uri`. `code` and `code token` requests stay nonce-optional. **Migration:** deployments with clients sending nonce-less implicit/hybrid requests can restore the previous acceptance per realm with the `compat.nonceless_hybrid=true` realm attribute during the deprecation window.

## [0.1.14] - 2026-10-10

### Added

- **Property-based (proptest) suites for the `issuerd-protocol` parsers.** The PKCE verifier/challenge handling (`pkce.rs`) and both request parsers (`authorization.rs`, `token.rs`) now carry proptest suites that assert both directions where meaningful: adversarial generators produce empty, over-long, non-ASCII and control-character inputs plus near-boundary lengths (43/128 for the RFC 7636 verifier window), and the tests pin that well-formed input is accepted and roundtrips while malformed input is rejected with the exact `IssuerdError` / OAuth2 error code (`invalid_request` with the documented message, `invalid_authorization_details`, `request_not_supported`, `invalid_grant`) — never panicking on arbitrary input. The generators are explicitly size-capped so the harnesses stay deterministic. No new workspace dependencies: `proptest` was already a dev-dependency of the crate.
- Added `dotenv` client installation provider: `GET /admin/realms/{realm}/clients/{id}/installation/providers/dotenv` renders a ready-to-save .env file (`ISSUERD_CLIENT_ID` / `ISSUERD_ISSUER` / `ISSUERD_REDIRECT_URI`, double-quoted values) served as `text/plain`; available in the admin console's "Download Adapter Config" dialog.

- **Full bundle-driven localization of every login-flow page and all outbound email.** The OTP, email-code and WebAuthn challenge pages, the CONFIGURE_TOTP enrollment, the required-action pages (UPDATE_PASSWORD, UPDATE_PROFILE, TERMS_AND_CONDITIONS, VERIFY_EMAIL), the registration and reset-credentials pages, the broker first-login pages and the error pages now render from the same layered message bundles as the consent page (`crates/issuerd-server/i18n/messages_{en,de}.json` compiled in, plus theme overrides at `{themes.dir}/{theme}/messages_{locale}.json` with per-key English fallback); the admin execute-actions email is localizable through the same mechanism. Locale resolution keeps the Keycloak precedence (flow-pinned `ui_locales` → `Accept-Language` → realm default → `en`, gated on the realm's internationalization toggle and restricted by its supported locales), and a realm without `login_theme`/`email_theme` reads the default theme's bundles. Locales are not limited to the compiled-in set: at boot the server scans `[themes] dir` for `messages_*.json` files and exposes the union via `GET /admin/enums/locales` and `GET /admin/serverinfo`, so theme-supplied locales appear in the admin console's realm i18n checkboxes. Provision YAML realms accept `internationalization_enabled`, `supported_locales` and `default_locale` (all optional; omitted keys keep the realm defaults). Theme message bundles are deployment-local content (`themes/*/messages_*.json` is gitignored). Before a locale becomes a filesystem path component it is reduced to a strict ASCII-alphanumeric language subtag, so request-controlled locale strings (`ui_locales`, `Accept-Language`, the user `locale` attribute) cannot be used for path traversal (CodeQL `rust/path-injection`). The admin and account consoles remain English-only.

### Fixed

- **Realm-scoped admin tokens can now read the `GET /admin/enums/*` listings (Keycloak console parity).** The enum endpoints serve the same server-global capability metadata that `GET /admin/serverinfo` aggregates (no realm-scoped data), but they still answered 403 for any non-master token because realm-less admin paths were master-only — the v0.1.12 relaxation covered `serverinfo` alone, so any console surface or script calling an enum endpoint directly with a delegated realm admin token broke the same way serverinfo did. Any authenticated admin token carrying `view-realm` or `manage-realm` may now read them; realm revocation cutoffs (`not_before`) still apply, and all other realm-less paths (realm creation/listing, signing-key administration) remain master-only.

## [0.1.13] - 2026-10-08

### Added

- **New release platforms: Windows ARM64 and macOS x86_64 (Intel).** Every tag now ships six binary archives: `issuerd_X.Y.Z_windows_arm64.zip` (built natively on a `windows-11-arm` runner, smoke-run and unit-tested on real ARM64 hardware) and `issuerd_X.Y.Z_macos_amd64.tar.gz` (cross-compiled on the Apple Silicon runner, smoke-run and unit-tested under Rosetta 2) join the existing Linux amd64/arm64, Windows amd64 and macOS arm64 builds — each with its CycloneDX SBOM, a `SHA256SUMS.txt` entry and a build-provenance attestation like the other platforms.

## [0.1.12] - 2026-10-06

### Fixed

- **Realm-scoped admin tokens can now read `GET /admin/serverinfo` (Keycloak console parity).** The endpoint serves server-global capability metadata only (enum/value lists, provider ids, server version — no realm-scoped data), but it answered 403 for any non-master token because realm-less admin paths were master-only, so a delegated realm admin's console rendered every serverinfo-derived Realm Health chip on the dashboard as "Degraded" and enum-driven forms stayed empty. Any authenticated admin token carrying `view-realm` or `manage-realm` may now read it — including tokens issued by a non-master realm; realm revocation cutoffs (`not_before`) still apply, and all other realm-less paths (realm creation/listing, signing-key administration) remain master-only.

### Changed

- **README/marketing assets:** the `acme` admin-console dashboard screenshot (`30-dashboard-acme.png`) was reshot against a healthy demo realm — the previous frame showed spurious "Degraded" Realm Health chips (a side effect of the serverinfo restriction fixed above) and a seeded failed-logins warning.

## [0.1.11] - 2026-10-03

### Added

- **Configurable LDAP federation mappers (Keycloak-parity).** An LDAP provider's `mappers` config key now wires the full built-in mapper chain instead of the group mapper alone: a JSON array of `{name, mapper_type, config}` entries — the same shape the Admin API mapper sub-resource (`/identity-provider/instances/{alias}/mappers`) and the admin console's mapper dialog manage — supporting `user-attribute-ldap-mapper` (directory attribute → email/first name/last name/custom user attribute, with `is.mandatory.in.ldap` and `attribute.default.value`), `full-name-ldap-mapper` (split one attribute, default `cn`, into first/last name), `group-ldap-mapper` (Keycloak dotted keys `groups.dn`/`memberof.ldap.attribute`/`group.name.ldap.attribute`, plus the Issuerd extension `groups.include`), and `msad-user-account-control-mapper` (AD `userAccountControl` → enabled flag, `pwdLastSet: 0` → `UPDATE_PASSWORD` attribute). Mapper config keys follow Keycloak's dotted spellings so exported Keycloak federation configs translate 1:1. The legacy `groupsDn` shorthand keeps working and is ignored when a `group-ldap-mapper` entry exists; malformed `mappers` JSON is logged and skipped rather than breaking the realm's federation. Provision YAML `identity_providers` entries accept a first-class `mappers:` list, and `GET /admin/enums/idp-mapper-types` advertises the new types to the console. Synced/imported users now carry directory email and names when the mappers are configured — previously each full sync cleared those fields on federated users.

### Fixed

- **`GET /admin/realms/{realm}/users` now honors the Keycloak-parity exact-match `username` and `email` query parameters.** Previously only the substring `search` parameter was read and the exact filters were silently ignored, so `?username=alice` returned the whole (unfiltered) first page — an admin scripting against the documented Keycloak query shape could resolve a different user than intended (e.g. pick the wrong account for a `reset-password` call). The exact filters take precedence over `search` and return at most one user.

### Security

- **Outbound client JWKS fetches are now SSRF-guarded, and the guard uses an explicit CIDR blocklist.** Client `jwks.url` documents (used by `private_key_jwt` client assertions and JAR request objects) are fetched through the same hardened HTTP path as `sector_identifier_uri`: https-only (plain-http `jwks.url` values are no longer contacted — Keycloak likewise expects TLS), publicly routable resolved IPs only, no redirect following, a 64 KiB body cap, and a uniform failure response. The guard's IP classification was replaced with an explicit blocklist of non-public ranges — adding CGNAT (100.64.0.0/10), benchmarking (198.18.0.0/15), reserved (240.0.0.0/4), NAT64/Teredo/6to4 translation, documentation, and IETF protocol-assignment ranges to the previously covered ones — and the guarded fetch is now a required `BrokerClient` trait method, so implementations cannot silently fall back to the unguarded client. **Migration:** clients whose `jwks.url` is plain http or resolves to a non-public address must move the JWKS behind a public https URL.
- **JAR request objects with an unknown `kid` now share the per-client 60-second JWKS refetch cooldown** already used by JWT client authentication; unauthenticated request objects can no longer force an outbound fetch on every request.
- **The anonymous dynamic-client-registration endpoint now applies a payload policy** (realms with `dynamic_client_registration_enabled=true`; token-gated and admin registration paths are unchanged): registrant-supplied JWKS and back/front-channel logout-URI client attributes are stripped, service-account enablement is forced off, redirect URIs are limited to https, loopback http, and custom schemes (scriptable schemes such as `javascript:`/`data:` are rejected outright with a 400 naming the offending URI), and the literal `"*"` web origin is refused.
- **Signing-key rotation and disable now require a master-realm admin token (breaking-hardening).** The server-global signing keys were previously mutable by any realm's delegated admin holding `manage-realm`; both operations now require a token issued by the `master` realm carrying `manage-realm`, and their audit events are always recorded against the master realm, so a path realm's events config can no longer suppress the trail of a global mutation. **Migration:** perform key administration with a master-realm admin.
- **PKCE is S256-only at the authorize and token endpoints (breaking-hardening).** `code_challenge_method=plain`, and a `code_challenge` sent without a method (which RFC 7636 defaults to plain), are rejected with `invalid_request`, matching the long-standing S256-only discovery advertisement; requests without a `code_challenge` are unaffected. **Migration:** clients relying on `plain` or omitting the method must switch to S256.
- **First-broker-login hardening against login CSRF and password guessing.** The identity-broker callback now requires the browser-correlation cookie established at kickoff before it consumes a login state entry (the flow cookie is issued `SameSite=None; Secure` on TLS deployments so `form_post` callbacks stay covered), the account-linking password prompt is wired into the realm's brute-force lockout tracking with login-failure events and a per-flow attempt cap, and account-linking action tokens are bound to the identity-provider alias (tokens minted before this change fail closed — re-request the link from the account console).
- **Eliminated both dependency advisory exceptions: the `rsa` crate left the compiled dependency graph, and `rustls-pemfile` left the lockfile.** RS256/384/512 JWT signing moved from jsonwebtoken's pure-Rust `rust_crypto` backend — which bundles the timing-side-channel-affected `rsa` crate (RUSTSEC-2023-0071 / CVE-2023-49092, Marvin Attack; no patched release) — to jsonwebtoken's FIPS-validated `aws_lc_rs` backend, and RSA signing-key generation moved from the `rsa` crate to OpenSSL (already an in-tree dependency). The PKCS#1 DER storage format of signing keys is unchanged, so existing deployments load their persisted keys without migration and token signatures remain interoperable. The `redis` 0.27 → 0.29 upgrade drops the unmaintained `rustls-pemfile` (RUSTSEC-2025-0134) from the lockfile entirely (via rustls-native-certs 0.8). `cargo deny check advisories` now passes with **zero** ignores. Build impact: aws-lc-sys needs only a C toolchain on standard targets (its cc-builder covers Linux/macOS/Windows — cmake is merely an exotic-target fallback), and Windows x86_64 builds use the pre-assembled objects shipped via the `aws-lc-rs/prebuilt-nasm` feature, so no NASM install is needed. One tooling note: `rsa` still appears in `Cargo.lock` as a never-compiled weak optional edge of sqlx (upstream cargo#10801, `sqlx-mysql?/...`); `.cargo/audit.toml` carries a single scoped ignore for cargo-audit's feature-blind lockfile scan, and `cargo tree -i rsa --target all` is the machine-checkable proof that the crate is never built.
- **`examples/agentic-mcp` demo stack: bumped PyJWT 2.14.0 → 2.15.1**, clearing the two Dependabot alerts for [GHSA-42vr-xj54-vc7v](https://github.com/advisories/GHSA-42vr-xj54-vc7v) (unauthenticated `RecursionError` DoS in pre-verification payload parse; the vulnerable paths are `PyJWKClient.get_signing_key_from_jwt` and `jwt.decode(..., options={"verify_signature": False})`, PyJWT ≤ 2.14.0). Both demo apps were pinned on 2.14.0: ChatApp (DPoP proof verification) and McpServer (JWKS client — the component the advisory names). Demo code only: the issuerd server is Rust and has no Python in its dependency tree. Verified against the ChatApp smoke suite (all checks pass on 2.15.1).
- **Corrected the documented risk basis of the `RUSTSEC-2023-0071` (Marvin Attack) advisory ignore.** The justification in `deny.toml`, `.cargo/audit.toml`, `Cargo.toml`, and the operator docs claimed the `rsa` crate was used only for key generation (with signing/verification done via `ring`) and that the advisory targets only a decryption oracle. In fact RS256/384/512 JWT signing runs through the `rsa` crate (jsonwebtoken's `rust_crypto` backend; `ring` is used only for Ed25519 key generation), and Marvin covers RSA private-key operations including PKCS#1 v1.5 signing — so the timing surface is reachable on realms pinned to RS256. The ignore remains, now documented as an accepted residual risk: no patched `rsa` release exists (upstream RustCrypto/RSA#626/#680/#702), the sign path applies RNG blinding, and issuerd performs no RSA decryption (the classic Marvin oracle). No code or dependency changes; the residual plan (migrate RSA key generation off `rsa`, evaluate jsonwebtoken's `aws_lc_rs` backend) is recorded in `deny.toml`.

### Changed

- **Release pipeline: publishing (crates.io + Docker Hub) is now the final, fully gated stage.** On release tags, the crates.io workspace publish and the per-arch Docker image builds/pushes (followed by the multi-arch manifest + Hub overview sync) run side by side, only after the heavy test suites, every platform build/test job, and the GitHub Release have all succeeded — a tag with failing tests no longer publishes crates or images. Expect crates and `issuerd/issuerd:X.Y.Z` tags to appear later in the release run than before; a late failure in any publish job is recovered by re-running the failed jobs of the same release run (crates.io uploads are resumable).

## [0.1.10] - 2026-09-30

### Changed

- **Realm update PUT merges by default (breaking, with opt-out).** `PUT /admin/realms/{realm}` no longer silently resets omitted fields to model defaults: the body is now merged over the stored realm — only the fields present are applied, omitted (or null) fields keep their current values. A partial PUT from automation/IaC can therefore no longer switch brute-force protection back off or reset token lifespans and the events config. The legacy full-replacement semantics remain available via the new `?merge=false` query parameter, which is also the only way to *clear* a nullable field (`loginTheme`, `display_name`, `browserFlow`, ...) back to unset, because merge mode treats an explicit JSON `null` exactly like an absent field. The admin console pins `merge=false` since it always sends the complete document. Deliberate divergence from Keycloak, whose realm PUT always fully replaces (see `tests/KEYCLOAK_DIFFS.md`). **Migration:** API callers that relied on reset-on-omit must append `?merge=false`; callers already sending full GET-round-trip documents need no change.

### Added

- **Dylint log-hygiene lint gate** (`lints/issuerd_log_hygiene`, deny-by-default, blocking `dylint` job in `verification.yml`): four syntax-only lints enforce the logging conventions at compile time — errors must be recorded as `error = %e` (not `?e`), no secret-named fields (`password`/`token`/`code`/`cookie`/...) in events or `#[instrument]` span fields, `session_id`/`sid` only at DEBUG/TRACE and never in span fields, and `#[instrument]` functions must `skip(...)`/`skip_all` sensitive arguments (state, headers, bodies, query params, client IPs, `*_token`/`*_secret`/...). Run locally with `scripts/dylint.sh --workspace` (or `scripts/test.sh dylint`; needs `cargo install --locked cargo-dylint dylint-link`). The lint crate is a detached workspace with its own pinned nightly (`nightly-2026-08-20` — must predate rustc's `--env-set` removal, see trailofbits/dylint#2078). Pre-existing violations found by the lints were fixed (error sigils, session-id fields, `#[instrument]` skip lists).
- **Type-aware dylint lints** (same `lints/issuerd_log_hygiene` library, late pass over the expanded tracing machinery): `secret_typed_value_in_log` flags any log field whose VALUE's type is a known secret (default list: the `issuerd_core::models` secret newtypes — `Password`, `ClientSecret`, `RefreshToken`, `Assertion`, `AuthorizationCode` — plus `Credential` and `StoredSigningKey`), catching secrets under innocuous field names; `unsanitized_username_in_log` requires a `username` field at INFO+ (or in any span) with a raw `&str`/`String`/`Cow<str>` value to be a `sanitize_log_str(...)` call (the validated `Username` newtype is legal). Both are configurable via `dylint.toml` (`[issuerd_log_hygiene]` table — keys `secret_types`, `username_fields`, `username_sanitizer`, `username_safe_types`; documented in the lint crate's README). The workspace is clean under both lints.

## [0.1.9] - 2026-09-27

### Fixed

- **Docker linux/arm64 image failed to start.** The 0.1.8 (and earlier) `issuerd/issuerd` arm64 image shipped `/usr/local/bin/issuerd` without the executable bit: the release workflow hands the natively built binary to the image-packaging job through a workflow artifact, which drops Unix mode bits, and the plain `COPY` in `Dockerfile.prebuilt` baked `0644` into the image. On ARM hosts (Apple Silicon, ARM Linux) any container run from the multi-arch tags (`latest`, `0.1.8`, `0.1`) died immediately with `exec: "issuerd": executable file not found in $PATH`. The packaging Dockerfile now uses `COPY --chmod=0755` so the mode no longer depends on how the build context was transported. Only the arm64 Docker image was affected — the amd64 image (compiled inside the container), the arm64 release tarball (tar preserves modes), and the crates.io crates are all fine. **Action for ARM users on 0.1.8:** pull `issuerd/issuerd:0.1.9` (or `latest`); alternatively force the amd64 image with `--platform linux/amd64`.

## [0.1.8] - 2026-09-27

### Security

- **`examples/agentic-mcp` demo stack: bumped vulnerable Python pins + fixed a regex DoS.** ChatApp requirements moved to PyJWT 2.14.0, cryptography 50.0.1, python-multipart 0.0.31, clearing 17 Dependabot alerts (HS256 public-key confusion forgery, PKCS#7 Bleichenbacher oracle, multipart header DoS / arbitrary file write, and others). Demo code only — the issuerd server is Rust and has none of these in its dependency tree. Also rewrote the ChatApp intent parser's order-id regex, which had a polynomial-backtracking DoS on long whitespace runs (CodeQL `py/polynomial-redos`); matching behavior is unchanged (verified against the old pattern plus the app's smoke suite).

### Added

- **macOS arm64 release binary.** GitHub Releases now ship `issuerd_X.Y.Z_macos_arm64.tar.gz` alongside the Linux and Windows archives: a natively built Apple Silicon binary (`MACOSX_DEPLOYMENT_TARGET=11.0`) with the usual archive contents (LICENSE/NOTICE, README, CHANGELOG, example configs) plus a CycloneDX SBOM, covered by `SHA256SUMS.txt` and the build-provenance attestation. The `macos-binary` release job packages it via `scripts/package-release.sh` after its native build + full workspace test run; the raw `macos-arm64-binary` workflow artifact is gone (the archive replaces it).

## [0.1.7] - 2026-09-27

### Added

- **Runnable agentic IAM example: `examples/agentic-mcp/`**. A self-contained docker compose stack — Issuerd + a FastAPI/HTMX support-chat agent + a FastMCP resource server + PostgreSQL with row-level security — demonstrating the full agentic scenario in a browser: OIDC login with DPoP-bound tokens, RFC 8693 audience/scope attenuation per tool call, CIBA human step-up for refunds (DPoP-bound step-up token), prompt-injection containment via RLS, and live attack buttons (stolen-token replay, missing scope, refund without step-up) with a security-trace panel narrating every protocol step. `cd examples/agentic-mcp && docker compose up -d`, then http://localhost:5108 (alice/changeme); a headless self-check (`docker compose run --rm setup python verify.py`) asserts the whole flow. Indexed from the new `examples/README.md` and linked from `docs/client-integration.md` / `docs/README.md`.

### Security

- **Token exchange: the requester-in-audience check is now mandatory** (RFC 8693 hardening, security-review remediation). The client authenticated at the token endpoint must always appear in the subject token's `aud` claim (string or array form), in both internal and impersonation modes, or the exchange fails with `invalid_grant` — Keycloak's semantics, now unconditional. Previously this was the opt-in `require_requester_in_subject_aud` realm/client attribute (default off), which let a client re-scope any valid token of the realm it had been handed. The attribute is removed; leftover occurrences in stored realms/clients are inert. **Migration:** if a client legitimately exchanges tokens issued to a different client, make the issuing client add the requester to the token audience — e.g. an `oidc-audience-mapper` protocol mapper with `included.client.audience` set to the requesting client. See `docs/client-integration.md` — "Token exchange and impersonation".
- **`examples/agentic-mcp`: the MCP resource server is now strictly DPoP-only.** Previously `auth.py` accepted `Authorization: Bearer` for any access token without a `cnf.jkt` claim (and even a valid DPoP proof rescued an unbound token), so the "every POST to /mcp must carry a DPoP-bound access token" invariant held only as a side effect of how the demo's clients happen to fetch tokens — an unbound `aud=mcp-server` token was mintable through the demo's own RFC 8693 exchange by omitting the DPoP proof (Issuerd's binding is opportunistic). The middleware now rejects Bearer outright (bound tokens keep the specific RFC 9449 §6.1 message) and rejects tokens without `cnf.jkt` under any scheme, making sender-constraining an enforced resource-server policy instead of an issuance-side coincidence.

## [0.1.6] - 2026-09-26

### Added

- **Conformance evidence shipped with releases:** the release pipeline now runs the full heavy test suites (LDAP user federation against Samba AD DC and OpenLDAP, two-node cluster E2E, Keycloak dual-target parity, and the OIDF conformance suite) against the exact tagged commit before cutting the GitHub Release, and attaches the packed conformance report bundle `issuerd_X.Y.Z_conformance-evidence.tar.gz` as a standalone release asset (checksum-covered and attested, alongside the SBOMs — not part of the binary archives).

## [0.1.5] - 2026-09-26

### Fixed

- **Fixed failing docs.rs builds:** `utoipa-swagger-ui` now uses the `vendored` feature, bundling the Swagger UI assets into the crate instead of downloading them from GitHub at build time (the download fails in network-isolated environments like docs.rs).
- **Fixed hardcoded `0.1.0` version reporting:** `GET /admin/serverinfo` returns the real package version in a new `version` field (rendered by the console), and the OpenAPI `info.version` uses it too.

## [0.1.4] - 2026-09-25

### Security

- **Login page redirect sanitization:** `public/login.html` took the `redirect_uri` query parameter raw and navigated to it with `window.location.href` after sign-in — a `javascript:` URL executed in the IdP origin (XSS) and any cross-origin URL was an open redirect on the login page. The parameter is now accepted only when it resolves to the page's own origin (relative URLs included); anything else falls back to the default console callback. (CodeQL `js/xss` + `js/client-side-unvalidated-url-redirection`.)

### Fixed

- **crates.io publish (v0.1.3 follow-up):** `scripts/publish.py --real` paused a fixed 30 s between crates for index propagation, but the sparse index lags the upload by a minute or more — the v0.1.3 run died at `issuerd-federation` with ``failed to select a version for the requirement `issuerd-cluster = "^0.1.3"` ``. After each upload the script now polls the sparse index until the new version is actually visible (`--index-timeout`, default 600 s) and only then proceeds; `--pause` remains as fixed rate-limit grace. The resume logic also learned the newer duplicate-version wording (`crate x@y already exists on crates.io index`) so re-runs skip already-live crates instead of aborting on the first one.
- **GitHub Release job:** the release job downloaded *all* run artifacts, including the `*.dockerbuild` build-record archives `docker/build-push-action@v6` auto-uploads — those fail to download (5 retries → job failure) in every run that reached the job. The job now downloads only the `*-dist` + `release-notes` artifacts it uses (the named `release-notes` artifact with an explicit `path:`, so the notes land where the release steps expect them), and both docker jobs set `DOCKER_BUILD_RECORD_UPLOAD: false` ([documented opt-out](https://docs.docker.com/build/ci/github-actions/build-summary/)) so the archives are no longer uploaded. `verification.yml` also declares `permissions: contents: read` (code scanning `actions/missing-workflow-permissions`).
- **Code scanning noise floor:** ~520 of the 528 open CodeQL alerts were intentional fixture secrets in test code (bulk-dismissed as *used in tests*; the 5 real ones were fixed — see Security above). `.github/codeql/codeql-config.yml` now excludes the test trees (`tests/**`, `webclientsrc/src/test/**`, `*.test.ts(x)`) from analysis via the `github-codeql-config-file` repository property ([default-setup config merge](https://github.blog/changelog/2026-08-04-customize-code-scanning-default-setup-at-scale/)) — production code keeps full coverage, and inline `#[cfg(test)]` modules (not path-excludable) remain covered with the dismissal convention.

## [0.1.3] - 2026-09-25

### Fixed

- **Release pipeline (v0.1.2 follow-up):** the `linux-arm64` cross-build job restricted apt sources to amd64 with a file-level guard, but runner images mix restricted and unrestricted entries within a single file — `security.ubuntu.com` stayed unrestricted and `apt-get update` 404'd on the foreign arch. The rewrite is now per line/stanza across all source files. The `crates-io` job now also installs `libkrb5-dev` so the staged `issuerd-federation` verify-build can compile `libgssapi-sys` (MIT Kerberos).

## [0.1.2] - 2026-09-25

### Added

- **linux/arm64 release artifacts**: the tag release now ships an `issuerd_<version>_linux_arm64.tar.gz` archive (cross-compiled on the same glibc 2.35 / OpenSSL 3 baseline as the amd64 build — no QEMU) alongside the existing Linux amd64 and Windows archives, and the `issuerd/issuerd` Docker image tags (`latest`, `X.Y.Z`, `X.Y`) are now multi-arch manifest lists resolving to linux/amd64 or linux/arm64 depending on the host (per-arch tags `X.Y.Z-amd64`/`-arm64` are also published).

### Fixed

- **Empty-body key rotation is deterministic on fresh deployments**: the initial EdDSA+RS256 key pair was stamped with a 1-nanosecond `created_at` gap that PostgreSQL's microsecond-resolution `timestamptz` truncates to a tie, so the rotation endpoint's "newest active key" default-algorithm selection degenerated to a kid-string coin flip and could rotate RS256 instead of the actual signing key. The RS256 MTI key is now stamped a full second older, and timestamp ties prefer the server-default algorithm (EdDSA).

### Security

- **MFA is now enforced on the non-browser password paths** (Keycloak direct-grant parity). `grant_type=password` and the device-verification endpoint (`POST .../auth/device-verify`) reject accounts with an enrolled OTP credential unless the request carries a valid `totp` code — the matched code's replay watermark is persisted, so it cannot be reused — and reject accounts whose only second factor is WebAuthn, since a WebAuthn ceremony cannot run outside the browser flow. Previously both paths authenticated with the password alone, silently bypassing MFA.
- **Device verification now applies the password grant's account checks**: accounts with pending required actions (temporary password, unverified email, …) are rejected, and federated users are validated against their directory (an active rejection is final; a provider error or dead link falls back to local credentials) instead of requiring a local password.
- **The account-console API enforces the same bearer-token validity gates as userinfo**: explicit revocation (RFC 7009), backing-session existence (logout and admin session revocation take effect immediately instead of at token expiry), and realm `not_before`. DPoP-bound tokens (`cnf.jkt`) presented as plain `Bearer` are rejected — the account API has no proof channel, so accepting them silently dropped sender-constraining.

## [0.1.1] - 2026-09-24

### Added

- **Release pipeline** (`.github/workflows/release.yml`): pushing a `v*` tag validates the tag against `[workspace.package] version` and the CHANGELOG section, publishes the `issuerd/issuerd` image to Docker Hub (`:latest`, `:X.Y.Z`, `:X.Y`, with SBOM + provenance attestations), and creates a GitHub Release with Linux and Windows binary archives (`issuerd_<ver>_<os>_amd64.{tar.gz,zip}` — binary, LICENSE/NOTICE, README/CHANGELOG, example configs, CycloneDX SBOM), `SHA256SUMS.txt`, build-provenance attestations, and release notes auto-extracted from CHANGELOG.md. Packaging lives in `scripts/package-release.sh` (shared by CI and the local nektos/act rehearsal, `.act/run-release.sh`, where publish steps auto-skip).

### Changed

- **The local demo stack now pulls the published image**: root `docker-compose.yml` uses `issuerd/issuerd:latest` instead of building from source, so a fresh clone with only Docker installed runs `docker compose up` without compiling. Building from local sources moves to the `docker-compose.from-source.yml` override (`docker compose -f docker-compose.yml -f docker-compose.from-source.yml up --build`).

### Fixed

- **`cargo install issuerd` now embeds the admin/account web consoles** — the
  root binary crate is publishable to crates.io. `issuerd-server`'s build
  script resolves the built web client from the crate-local `webclient-dist/`
  directory first and falls back to the dev-workspace `webclientsrc/dist`,
  and the publish staging copies the built SPA into the packaged crate;
  previously a crates.io release build aborted with the `DIST_MISSING` panic
  because `webclientsrc/dist` lives outside the packaged crate. The staging
  now also includes the root `build.rs` (git-hash version stamp), without
  which the packaged binary crate did not compile.

## [0.1.0] - 2026-09-23

### Security

- **Envelope encryption for signing keys at rest** (opt-in,
  `[crypto.key_encryption]` config section): the cluster-wide JWT signing keys
  in the PostgreSQL `signing_keys` table are now encrypted with a
  config/env-provided 32-byte Key Encryption Key (AES-256-GCM, random per-key
  nonce, KEK id persisted per row for rotation), so a database dump yields
  only ciphertext. The KEK is never stored in the database; the
  `KeyEncryptionKeyProvider` trait in `issuerd-core` is the SPI seam for a
  future external KMS/HSM backend. Reads decrypt transparently and legacy
  plaintext rows keep working: a boot-time sweep re-encrypts them under the
  active KEK, and new keys plus admin rotations write ciphertext from the
  start (expand-phase migration `017_signing_key_encryption.sql`; dropping the
  plaintext column is a later contract migration). Boot **fails closed** when
  the KEK cannot decrypt a row (wrong key or unknown `kek_kid`) — never a
  plaintext fallback. Decrypted key material is zeroized on drop
  (`zeroize` crate; residual copies inside `ring`/`jsonwebtoken` per sign call
  are documented). **Existing deployments boot unchanged**: without the
  section the behavior is identical to before, with a new startup WARN on
  PostgreSQL deployments recommending the feature. With a non-PostgreSQL
  backend the section is ignored (WARN) — protect JSON snapshots at the
  filesystem level. Enable on a cluster only after every node runs this
  version, with the identical section on all nodes; see
  `docs/configuration.md` — "[crypto.key_encryption]",
  `docs/CLUSTERING.md`, and `docs/backup-and-upgrade.md` (KEK backup and
  rotation procedure).

- The default token-signing algorithm is now **EdDSA (Ed25519)** instead of
  RS256 (asymmetric-first policy). New deployments generate an EdDSA signing
  key AND an active RS256 key on first boot — EdDSA is the signing default,
  while the RS256 key keeps the OIDC Core mandatory-to-implement algorithm
  supported and advertised in discovery — and realms without a
  `default_signature_algorithm`
  attribute resolve to the EdDSA server default (`CryptoConfig::default_alg`,
  `TokenManager::new`, admin key rotation with no existing keys); RS256
  remains fully supported as an explicit compatibility choice. **Existing
  deployments are unaffected**: stored keys are untouched, and an RS256-only
  key set keeps signing un-configured realms via the newest-active-key
  fallback. Note that deliberately rotating an EdDSA key into an existing
  deployment now switches un-configured realms to EdDSA (previously issued
  RS256 tokens keep validating — both keys stay published), so pin
  `default_signature_algorithm=RS256` on realms that must stay on RSA before
  rotating. The admin enum/serverinfo descriptions for the `HS*` algorithms
  now state they are not applicable to realm token signing (they were always
  ignored there — the contract is now visible to the SPA), and the
  `RUSTSEC-2023-0071` (rsa crate, Marvin) ignores in `.cargo/audit.toml` /
  `deny.toml` carry the verified justification plus the residual plan (RSA key
  generation only, retained for compatibility; switch to a maintained crate
  if a fix/fork lands). See `docs/configuration.md` — "Token signing
  algorithm".
- Token issuer (`iss`) validation is now **exact-match**: access, refresh,
  and ID token issuers are parsed as URLs and must equal the configured
  issuer base URL in scheme, host, and port, with a path of exactly
  `/realms/{name}` (a single valid realm-name segment; no userinfo, query,
  or fragment). The previous prefix check accepted look-alike issuers whose
  host merely starts with the configured one (e.g.
  `https://issuer.example.com.evil.test/realms/x`) and URLs with trailing
  slashes or extra path segments. Legitimate realm issuers are unaffected.
- CIBA and device-authorization grants now consume an approved `auth_req_id` /
  device code **atomically** (`DistributedCache::get_and_delete` — Redis
  `GETDEL`), matching the authorization-code grant. Previously the token poll
  read the cache entry and deleted it after validation, so concurrent polls of
  one approved request could each mint a token set. Only the first concurrent
  poller now succeeds; the rest receive `expired_token`. Poll pacing
  (`slow_down`) and single-request behavior are unchanged.
- Authorization-code issuance is now **fail-closed**: a code is only released
  to the client after the cache confirms its persistence. When the write fails
  (e.g. Redis outage), authorize/login endpoints return
  `error=temporarily_unavailable` (packaged per the requested `response_mode`
  on browser redirects, HTTP 503 on the SPA/API login), log an ERROR, and
  record a `login_error` event instead of redirecting with a code that could
  never be exchanged. Adds `IssuerdError::TemporarilyUnavailable`
  (`temporarily_unavailable` / HTTP 503).
- The authorization-code TTL is now **configurable**: `[oauth]
  auth_code_ttl_secs` (default 600 s — unchanged behavior, matching Keycloak;
  env `ISSUERD_OAUTH__AUTH_CODE_TTL_SECS`), with an optional per-realm
  override via the `auth_code_ttl_secs` realm attribute. Accepted range is
  10–600 seconds; out-of-range server values abort the boot with a clear
  error, and a malformed/out-of-range realm attribute falls back to the
  server value. A FAPI 2.0 high-assurance profile requires ≤ 60 s — set 60
  globally or per realm when assembling one (full FAPI 2.0 message signing
  remains out of scope). See `docs/configuration.md` — "[oauth]".
- Authentication cookies now carry the **`Secure` attribute whenever the
  configured `issuer_url` is `https://`** (`ServerConfig::secure_cookies`,
  derived from config, never from the request): the `issuerd_flow_{id}` flow
  correlation cookie previously went without it, and the SSO session
  (`issuerd_session_{realm-id}`), remember-me
  (`issuerd_remember_{realm-id}`), and logout-clear cookies — which
  unconditionally sent `Secure` — now follow the same rule. TLS deployments
  (direct or behind a TLS-terminating proxy with an `https` `issuer_url`)
  are unaffected; plain-HTTP development rigs now work on any hostname, not
  just `localhost`, because browsers no longer drop the cookies there. Cookie
  names, `HttpOnly`, `SameSite=Lax`, and paths are unchanged; a `__Host-`
  prefix migration was considered and deferred (renaming cookies would break
  in-flight login flows on upgrade and requires a compat read path).
- **DPoP server-provided nonces** (RFC 9449 §8/§9) as an opt-in strict mode:
  the new `[dpop.nonce]` config section (`mode = "disabled" | "supported" |
  "required"`, default `disabled` — **existing deployments are unaffected**;
  `lifetime_secs`, default 30, accepted range 5–300, env
  `ISSUERD_DPOP__NONCE__MODE` / `ISSUERD_DPOP__NONCE__LIFETIME_SECS`). When
  enabled, the server issues unguessable random nonces in the `DPoP-Nonce`
  response header, stores them in the distributed cache
  (`dpop-nonce:{realm}:{nonce}` with the configured TTL), and consumes them
  atomically on verification — each nonce is single-use, and every
  proof-carrying response issues the next one. In `supported` mode proofs
  without a `nonce` claim are accepted but an unknown/stale/used nonce is
  challenged; in `required` mode every proof must carry a live nonce.
  Challenges follow the RFC retry contract: `400` with
  `{"error": "use_dpop_nonce"}` at the token endpoint, `401` with
  `WWW-Authenticate: DPoP error="use_dpop_nonce"` at userinfo, both with a
  fresh `DPoP-Nonce` header — compliant clients recover transparently, and
  plain Bearer requests (no `DPoP` header) are never affected. Under
  `required`, a captured proof can no longer be replayed with a freshly
  minted `iat`/`jti`: only the server issues nonces. RFC 9449 defines no
  discovery metadata for nonce support, so none is advertised. See
  `docs/configuration.md` — "[dpop]", and `docs/security.md` — "DPoP
  sender-constraining".
- **Token exchange: opt-in strict audience policy** (RFC 8693): the new
  `require_requester_in_subject_aud` attribute switches a realm to Keycloak's
  stricter exchange semantics — the client authenticated at the token endpoint
  must appear in the subject token's `aud` claim (string or array form), or
  the exchange is rejected with `invalid_grant`. Without it, any valid access
  token of the realm may be presented regardless of its audience, which lets a
  client that was handed a foreign token re-scope it. Set as a **realm
  attribute** for the realm-wide default; the same-named **requesting-client
  attribute** overrides the realm setting in either direction (`"true"`
  enforces, `"false"` exempts). The policy guards internal and impersonation
  exchanges alike. **Default is off — existing deployments behave exactly as
  before.** See `docs/client-integration.md` — "Token exchange and
  impersonation".

### Fixed

- **Fresh deployments again support and advertise RS256** (OIDC Core §3 +
  §15.1 mandatory-to-implement), fixing a spec-compliance regression
  introduced on this branch by the EdDSA-by-default change: first boot with an
  empty `signing_keys` table generated only an EdDSA key, so discovery listed
  `["EdDSA"]` and the OIDF conformance Config OP plan failed
  `oidcc-discovery-endpoint-verification` ("RS256 support is required, but the
  server does not list it in `id_token_signing_alg_values_supported`"). A
  fresh deployment now boots with an **EdDSA key (the signing default) AND an
  active RS256 key**, so discovery advertises both and realms explicitly
  pinned to RS256 work without a rotation; the admin rotate-on-an-empty-key-
  set fallback establishes the same pair. EdDSA stays the default signing
  algorithm and existing (non-empty) key sets are untouched.

### Added

- Initial implementation of the Issuerd IAM server: OIDC/OAuth2 provider with
  SSO, MFA (TOTP, WebAuthn/passkeys), user federation (LDAP/Kerberos),
  identity brokering, client scopes and protocol mappers, a Keycloak-compatible
  Admin REST API with OpenAPI export, the embedded admin/account web consoles,
  multi-node clustering, and advanced OAuth profiles (PAR, JAR/JARM, DPoP, RAR,
  CIBA, token exchange, dynamic client registration). See `README.md` and the
  "Implemented Features" section of `AGENTS.md` for the full surface.
- GitHub CI: per-commit gates (fmt, check, clippy, test, doc, audit, deny, web
  client test/build, OpenAPI sync check), a PR changelog gate, and a manually
  triggered workflow for the Docker-based suites (federation, cluster E2E,
  Keycloak dual-target parity, release build).
