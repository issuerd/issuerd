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

### Security

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
