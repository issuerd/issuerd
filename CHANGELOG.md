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
