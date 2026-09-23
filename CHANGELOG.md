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
