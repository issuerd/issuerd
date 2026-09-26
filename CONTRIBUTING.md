# Contributing to Issuerd

Thanks for your interest in contributing. This guide covers the day-to-day
workflow; the deep engineering conventions (crate rules, testing strategy,
logging policy, frontend rules) live in [`AGENTS.md`](AGENTS.md) — read it
before your first non-trivial change.

Everyone participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Bug reports** — open an issue with a reproduction. Please **do not** open
  public issues for security vulnerabilities; report those privately to
  **security@issuerd.org** (see the
  [vulnerability reporting policy](docs/security.md#vulnerability-reporting)).
- **Features** — check the [project scope](README.md#project-scope) first:
  SAML 2.0, UMA/Authorization Services, FGAP, Organizations, FAPI 2.0 message
  signing, and CIBA ping/push modes are deliberately out of scope for now.
- **Documentation** — the operations set under `docs/` and the guides are as
  much part of the product as the code.

## Development setup

- **Rust 1.95+** (workspace MSRV), edition 2021.
- **Node.js 20+** — only needed if you touch the embedded admin/account
  consoles (`webclientsrc/`).
- **Docker** — only needed for the integration/federation/conformance stacks;
  unit and root integration tests run without it.

```bash
cargo build --workspace
cargo test --workspace          # unit + root integration tests, no Docker
```

## Workflow

1. Review the conventions in `AGENTS.md`.
2. Create a feature branch: `git checkout -b feat/<feature-name>`.
3. Implement with tests first (TDD is encouraged).
4. Make the gates pass locally:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace
   ```

5. Add a `CHANGELOG.md` entry under `## [Unreleased]` (Keep a Changelog
   format). CI fails PRs that touch neither `CHANGELOG.md` nor carry the
   `no-changelog` label — use the label for changes with no user-visible
   impact (CI, docs, pure refactorings).
6. If API shapes changed, regenerate the OpenAPI spec and the web client SDK:

   ```bash
   cargo run --bin issuerd -- openapi -o webclientsrc/openapi.json
   cd webclientsrc && npm run generate-api && npm run test && npm run build
   ```

7. Open a pull request — the template checklist mirrors the gates above.

Commit messages follow the conventional style seen in history
(`feat: …`, `fix(ci): …`, `docs(readme): …`).

## Standing rules

- **Backward compatibility is a hard requirement.** Database migrations are
  append-only — never edit an existing migration file; ship schema changes as
  new, sequentially numbered migrations. The Admin REST API and the
  OIDC/OAuth2 protocol surface change additively. New config keys and
  provision-YAML fields are optional with sensible defaults.
- **Truthful discovery.** The discovery document advertises exactly what is
  implemented and tested — nothing more.
- **The admin SPA stays fully dynamic** — every enum-driven dropdown bootstraps
  its values from the backend at runtime (the dynamic enum rule in
  `AGENTS.md`).
- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe` in
  first-party crates.
- **Secrets are never logged** — see the logging conventions in `AGENTS.md`.

## Testing expectations

- Every public function must be testable without network I/O or a database
  (storage/crypto/cache behind traits, in-memory fakes in tests).
- Unit tests live in `#[cfg(test)]` modules next to the code; integration
  tests under `tests/integration/`.
- Docker-backed suites (Keycloak dual-target parity, federation, conformance)
  must skip gracefully when their stack is not running.
