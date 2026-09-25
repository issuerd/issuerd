<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/white-logo.svg">
    <img src=".github/assets/logo.svg" alt="Issuerd" width="300">
  </picture>
</p>

<p align="center">
  <strong>Fast, Keycloak-compatible IAM with DPoP and CIBA — conformance-tested OIDC/OAuth2 in Rust, shipped as a single binary, horizontally scalable.</strong>
</p>

<p align="center">
  <a href="https://github.com/issuerd/issuerd/actions/workflows/ci.yml"><img src="https://github.com/issuerd/issuerd/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/MSRV-1.95-orange.svg" alt="MSRV: 1.95"></a>
  <a href="tests/conformance/README.md"><img src="https://img.shields.io/badge/OIDC%20conformance-Basic%20%C2%B7%20Form%20Post%20%C2%B7%20Config%20OP-brightgreen" alt="OIDC Conformance: Basic · Form Post · Config OP"></a>
  <a href="https://github.com/issuerd/issuerd/tree/badges"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fissuerd%2Fissuerd%2Fbadges%2Frust.json" alt="Coverage: Rust"></a>
  <a href="https://github.com/issuerd/issuerd/tree/badges"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fissuerd%2Fissuerd%2Fbadges%2Fwebclient.json" alt="Coverage: web client"></a>
</p>

> **Proof, not promises:** 3,907 conformance conditions with 0 failures and 0 warnings · 100,000-user LDAP sync in ~30 s · 2,690+ automated tests · one self-contained binary.

Issuerd is a modular Identity and Access Management (IAM) server implementing OpenID Connect and OAuth 2.x. It delivers the feature surface you expect from a mature identity provider — single sign-on, MFA and passkeys, user federation, social login, a full admin console and management API — with the operational profile of a Rust service: one self-contained binary, predictable latency, and no JVM to babysit. Keycloak is used throughout as the baseline reference implementation: protocol behavior, JSON shapes, and Admin API responses are continuously validated against a real Keycloak 24.0.

<p align="center"><img src=".github/assets/demo.gif" alt="Issuerd demo" width="100%"></p>

---

## Why Issuerd?

- **Conformance-proven, not "spec-inspired".** Issuerd passes the official [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) (release v5.2.4) with **zero failures and zero warnings** across the Basic OP, Form Post OP, and Config OP profiles — 3,907 conditions verified, run in a hermetic TLS environment against a pristine suite, with per-module results checked into the repo.
- **Keycloak-compatible where it counts.** Realms, clients, roles, client scopes, protocol mappers, authentication flows, and the Admin REST API follow the Keycloak model, so existing OIDC clients and Keycloak-hardened operational knowledge transfer directly. A dual-target test suite runs the same protocol assertions against Issuerd and a live Keycloak 24.0 container, and [every deliberate difference is documented](tests/KEYCLOAK_DIFFS.md).
- **Rust, end to end.** Memory safety without a garbage collector, async I/O on Tokio, constant-time secret handling, ~127k lines of Rust across 9 tightly-scoped crates with a strictly acyclic dependency graph. The entire server — including the embedded admin and account consoles — deploys as one binary.
- **Horizontally scalable from day one.** Access-token validation is stateless (no database lookup on the hot path), signing keys are shared cluster-wide through PostgreSQL, and transient coordination state lives in Redis. No sticky sessions — put any number of nodes behind any load balancer.
- **Built for real directories.** LDAP (Samba AD, OpenLDAP, MS Active Directory) and Kerberos/SPNEGO federation with full user and group sync — a complete 100,000-user import from a live MS AD finishes in ~30 seconds (~3,300 users/s). Password validation via bind, password write-through, and group-membership reconciliation included.
- **Batteries included.** Embedded React admin console and end-user account console served same-origin, themable login pages, per-realm i18n with localized emails, declarative YAML provisioning, one-command OpenAPI export, Prometheus metrics, health/readiness probes, TLS.
- **Engineered for testability.** 2,690+ automated tests; every public function is testable without network or database; authentication state transitions are proven at compile time via typestate markers. The discovery document advertises exactly what is implemented and tested — nothing more.

---

## Built for the Agent Era

AI agents acting on behalf of your users break the assumptions bearer tokens were designed around: an agent holds credentials for hours, calls many downstream services, and reads untrusted input all day. Prompt-injection is not a thought experiment — it is Tuesday. Issuerd already ships the three standards the industry has converged on for exactly this world. Not on the roadmap — implemented, test-covered, and recorded live:

- **Tokens that are worthless when stolen (RFC 9449 DPoP).** Every access token can be cryptographically bound to its holder's key via the `cnf.jkt` confirmation claim. Proofs are method- and URL-bound, short-lived, and single-use through a distributed `jti` replay cache. A token lifted from a log, a proxy, or a compromised MCP server is scrap metal: presenting it without the matching private key is a `401 invalid_dpop_proof`.
- **Agents that never forward their login token (RFC 8693 token exchange).** Each tool call mints a fresh, audience-narrowed, scope-attenuated token on the spot: a `get_orders` call travels with `aud = mcp-server` and `scope = orders:read` — nothing more. Scope can only ever shrink across an exchange (asking for more is `invalid_scope`), targets opt in explicitly, and the DPoP binding survives the exchange.
- **Humans in the loop for the dangerous actions (CIBA, poll mode).** Privileged scopes like `refunds:execute` exist nowhere in an agent's standing credentials. When an action crosses the agent's autonomy limit, Issuerd interrupts the user with an explicit approval request carrying a binding message — *"Refund $150 for order #123"* — and only an approval mints a short-lived, DPoP-bound step-up token. A denial is `access_denied`; without a human yes, that authority simply never exists.

Both scenarios below ran end-to-end against a live Issuerd rig — a scripted chat agent calling a real [MCP](https://modelcontextprotocol.io) server backed by PostgreSQL row-level security. The attacks are real too: prompt injection absorbed by row-level security, a stolen token replayed with bare `curl`, and a refund attempted without step-up. What you see is what the servers actually answered.

| MCP scenario — attenuated, sender-constrained tool calls | CIBA scenario — human step-up approval |
|---|---|
| <img src=".github/assets/demo-mcp.gif" alt="MCP demo: DPoP-bound token exchange, RLS holds against injection, stolen-token replay rejected" width="100%"> | <img src=".github/assets/demo-ciba.gif" alt="CIBA demo: in-app approval card, DPoP-bound step-up token, 403 without it" width="100%"> |
| Login → exchange down to `aud = mcp-server`, `orders:read` → orders listed → injection changes nothing → replayed token: **401** | Refund requested → approval card with binding message → short-lived step-up token → refund applied → same call without it: **403** |

Guides with the full protocol detail, curl walkthroughs, and the failure matrix: **[Agentic IAM: MCP tool calls with DPoP and token exchange](docs/agentic-iam-mcp.md)** and **[Human step-up approval for agent actions: CIBA](docs/ciba-step-up.md)**.

---

## Issuerd vs. Keycloak

Issuerd deliberately mirrors Keycloak's domain model and API surface — it is not a from-scratch reinvention of IAM concepts. The difference is in the implementation and operations:

| | Issuerd | Keycloak |
|---|---|---|
| Runtime | Single Rust binary | JVM (Quarkus) distribution |
| Cluster state | PostgreSQL + Redis | Embedded Infinispan grid |
| Protocol parity | Continuously diff-tested against Keycloak 24.0 | Reference |
| Conformance evidence | Suite results checked into the repo | Vendor certification program |
| SAML, UMA, FGAP, Organizations | Not implemented (see [scope](#project-scope)) | Implemented |

If your clients speak standard OIDC/OAuth2 and your team knows Keycloak's model, Issuerd is a drop-in alternative with a Rust operational footprint.

---

## Feature Overview

**Protocols & grants**
- OpenID Connect Core: authorization code flow with PKCE (S256/plain), implicit/hybrid response types, all response modes (`query`, `fragment`, `form_post`, and the JARM `*jwt` family)
- OAuth2 grants: `password`, `client_credentials` (service accounts), refresh token rotation with reuse detection, device authorization (RFC 8628), CIBA (poll mode)
- Advanced OAuth: PAR (RFC 9126), JAR (RFC 9101), JARM, RAR `authorization_details` (RFC 9396), token exchange & impersonation (RFC 8693), DPoP sender-constraining (RFC 9449), dynamic client registration (RFC 7591/7592), pairwise subjects (OIDC Core §8)
- Client authentication: `client_secret_basic/post`, `private_key_jwt`, `client_secret_jwt`
- Offline tokens, per-realm signing algorithm selection (RS256/384/512, ES256/384/512, EdDSA), key rotation
- Session management: logout with `id_token_hint`, backchannel + frontchannel logout, realm `not_before` revocation

**Identity**
- MFA: TOTP (RFC 6238) and WebAuthn/passkeys as second factors, required-action enrollment
- Passwordless email-code login (per-realm opt-in)
- Identity brokering: external OIDC + social IdPs (Google/GitHub/Microsoft presets), first-broker-login, account linking, IdP mappers
- User federation: LDAP (Samba AD, OpenLDAP, MS AD) and Kerberos/SPNEGO, full user + group sync, password validation via bind, password write-through
- Self-service: registration, forgot/reset password, remember-me, account console (profile, credentials, TOTP, passkeys, consents, linked accounts, sessions)
- Brute-force protection, password policies with history, attack-detection endpoints

**Administration**
- Reference-compatible REST Admin API with OpenAPI 3.0 export and an embedded React admin SPA
- Client scopes & protocol mappers (claim shaping into tokens), client roles, composite roles
- Editable authentication flows, required actions, events & admin-event auditing
- Partial import/export, key rotation/disable, client adapter-config download
- Declarative realm provisioning from YAML at first startup

**End-user experience**
- Themable login pages, per-realm locales, localized SMTP email templates
- Embedded account console with dark/light themes

**Platform**
- Horizontal scaling: stateless token validation, shared signing keys, no sticky sessions (PostgreSQL + Redis)
- Standalone daemon binary with TLS, Prometheus metrics, `/health` and `/ready` probes, graceful shutdown
- Official Dockerfile plus compose stacks for a full integration environment and a two-node cluster demo

---

## Standards Coverage

| Specification | Status |
|---|---|
| OpenID Connect Core 1.0 | Conformance-suite verified (Basic OP, Form Post OP, Config OP) |
| OpenID Connect Discovery | Full metadata, truthful capability advertisement |
| OIDC RP-Initiated, Front-Channel & Back-Channel Logout | Implemented |
| OAuth 2.0 (RFC 6749) + Bearer Tokens (RFC 6750) | Implemented |
| PKCE (RFC 7636) | S256 + plain, enforced for public clients |
| Token Introspection (RFC 7662) | Implemented |
| Device Authorization Grant (RFC 8628) | Implemented |
| Token Exchange (RFC 8693) | Implemented, incl. impersonation |
| Pushed Authorization Requests (RFC 9126) | Implemented |
| JWT-Secured Authorization Requests — JAR (RFC 9101) | Implemented |
| JWT-Secured Authorization Response Mode — JARM | Implemented |
| Rich Authorization Requests (RFC 9396) | Implemented |
| DPoP (RFC 9449) | Implemented (mTLS sender-constraining deferred) |
| Dynamic Client Registration (RFC 7591/7592) | Implemented, incl. read/update/delete |
| CIBA (OpenID Connect Client-Initiated Backchannel Authentication) | Poll mode |
| TOTP (RFC 6238), WebAuthn / FIDO2 | Implemented |
| JWT / JWS / JWK (RFC 7515–7519) | RS/ES family + EdDSA, per-realm algorithm selection |

---

## OIDC Conformance

Tested against the [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) (release v5.2.4), running in a hermetic TLS environment against a pristine, unpatched suite:

| Plan | Result |
|------|--------|
| Config OP | **PASSED** — 39 conditions, 0 failures, 0 warnings |
| Basic OP | **PASSED** — 36 modules, 1,858 conditions, 0 failures, 0 warnings |
| Form Post OP | **PASSED** — 36 modules, 2,010 conditions, 0 failures, 0 warnings |

Setup and per-module results: `tests/conformance/README.md`, `tests/conformance/COVERAGE.md`; logs are written to the (gitignored) `tests/conformance/results/` directory when the suite runs.

```bash
# Re-run the full conformance suite (requires Docker)
git clone https://gitlab.com/openid/conformance-suite.git tests/conformance/conformance-suite  # once
cd tests/conformance && docker compose up   # or ./run.sh (CI: exit code + teardown)
```

---

## Quickstart

### Option A — Docker (one command, everything included)

```bash
docker compose up
```

This pulls the published image (`issuerd/issuerd:latest`) and starts a single-node Issuerd with PostgreSQL and Redis on `http://localhost:8080`, seeded on first start with the `master` realm (admin `admin` / `admin`) and a demo realm `myrealm` (user `alice` / `changeme`, sample clients `my-app` and `public-app`). No build tools required — only Docker. Pin a specific release with `issuerd/issuerd:<version>` in `docker-compose.yml`; to build from local sources instead, use `docker compose -f docker-compose.yml -f docker-compose.from-source.yml up --build`.

Prebuilt binaries (Linux/Windows, with SBOM and checksums) are attached to each [GitHub Release](https://github.com/issuerd/issuerd/releases).

- **Admin console:** <http://localhost:8080/admin/console>
- **Account console:** <http://localhost:8080/realms/myrealm/account>
- **Discovery:** <http://localhost:8080/realms/myrealm/.well-known/openid-configuration>

Stop with `docker compose down`; wipe the demo data with `docker compose down -v`.

### Option B — local Rust build

Prerequisites: a Rust toolchain (1.95+) and — for the embedded web consoles — Node.js 20+.

```bash
# 1. Build the embedded web client (admin console, account console, login pages)
cd webclientsrc && npm ci && npm run build && cd ..

# 2. Run the server — zero external dependencies (in-memory backend)
cargo run --bin issuerd -- daemon
```

The server listens on `http://localhost:8080` and seeds the same demo content via the checked-in `issuerd.toml`.

> Skipping step 1 still yields a fully functional OIDC/OAuth2 and Admin REST API server; only the browser consoles and login pages stay unembedded.

Useful companion commands:

```bash
# Export the OpenAPI specification
cargo run --bin issuerd -- openapi -o openapi.json

# Generate fully-commented example configs
cargo run --bin issuerd -- example server-config -o my-server.toml
cargo run --bin issuerd -- example provision-config -o my-provision.yaml
```

### More deployment options

```bash
# Contributor integration stack: extra PostgreSQL, Redis, reference Keycloak,
# Bind9, Samba AD DC, OpenLDAP (used by the dual-target and federation tests)
docker compose -f docker-compose.integration.yml up -d

# Two Issuerd nodes behind an nginx load balancer (PostgreSQL + Redis)
docker compose -f docker-compose.cluster.yml up -d --build
# LB endpoint: http://localhost:8088 — see docs/CLUSTERING.md
```

---

## Architecture at a Glance

A Cargo workspace of 9 library crates plus the `issuerd` binary. The dependency graph is a strict DAG: only `issuerd-core` is a universal dependency, and `issuerd-server` is the composition root that wires everything together.

| Crate | Responsibility |
|-------|----------------|
| `issuerd-core` | Shared types, traits, errors, ID types, models — no I/O, no async |
| `issuerd-protocol` | OIDC/OAuth2 request parsing & validation — pure functions |
| `issuerd-auth-flow` | Pluggable authentication flow engine, TOTP, WebAuthn, email codes |
| `issuerd-token` | JWT/JWS/JWK issuance, signing, validation, introspection |
| `issuerd-storage` | `Storage` trait + PostgreSQL (sqlx), in-memory, and JSON-file backends |
| `issuerd-federation` | User federation SPI: LDAP, Kerberos/SPNEGO, user sync |
| `issuerd-admin-api` | REST Admin API (Axum + utoipa/OpenAPI) |
| `issuerd-cluster` | Distributed cache (Redis cluster) & node discovery |
| `issuerd-server` | Composition root: HTTP bootstrap, middleware, TLS, metrics |

Design contracts (stateless validation, testability rule, typestate auth boundaries, horizontal scaling): see `ARCHITECTURE.md`.

---

## Testing & Quality

- **2,690+ automated tests.** Unit tests live next to the code; every public function is testable without network I/O or database via trait-based fakes (`InMemoryStorage`, `InMemoryCache`, mock crypto).

  ```bash
  cargo test --workspace --lib   # unit tests, fast, no I/O
  cargo test --workspace         # + in-process E2E suite (< 30 s, no Docker)
  ```

- **Dual-target protocol parity.** A subset of the E2E suite runs the same assertions against Issuerd and a real Keycloak 24.0 container (`ISSUERD_TEST_TARGET=keycloak|both`) to catch behavioral drift.
- **Real-directory federation tests** against Samba AD DC, OpenLDAP, and Windows Server AD (skip gracefully when unavailable), plus large-scale sync load tests (100k users). A full 100,000-user sync from a live MS AD lab completes in **~30 s** (~3,300 users/s on the `rig/` lab stack with PostgreSQL).
- **CI-enforced hygiene:** `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo fmt --check` must stay green.
- **Fast coverage** with `cargo-llvm-cov`:

  ```bash
  cargo llvm-cov --workspace --lib --summary-only
  ```

---

## Documentation

| File | Purpose |
|------|---------|
| [docs/README.md](docs/README.md) | **Operations documentation set** — installation, configuration, provisioning, deployment, administration, federation, security, monitoring, backup/upgrade, troubleshooting |
| [webclientsrc/openapi.json](webclientsrc/openapi.json) | **Issuerd API** — OpenAPI spec covering the Admin REST API plus the account-console, public protocol, and internal SPA endpoints |
| [CHANGELOG.md](CHANGELOG.md) | Project changelog (currently: initial release) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | High-level design + module contracts |
| [AGENTS.md](AGENTS.md) | Conventions, build/test commands, per-crate notes, compatibility policy |
| [docs/CLUSTERING.md](docs/CLUSTERING.md) | Multi-node deployment guide |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Measured performance & sizing vs Keycloak 26.7 (k6 benchmark stack) |
| [docs/agentic-iam-mcp.md](docs/agentic-iam-mcp.md) | **Agentic IAM** — MCP tool calls secured with DPoP + RFC 8693 token exchange (demo GIF included) |
| [docs/ciba-step-up.md](docs/ciba-step-up.md) | **Human step-up for agents** — CIBA approval flows with DPoP-bound step-up tokens (demo GIF included) |
| [tests/KEYCLOAK_DIFFS.md](tests/KEYCLOAK_DIFFS.md) | Documented divergences from Keycloak behavior |
| [tests/conformance/README.md](tests/conformance/README.md) | OIDC conformance suite harness & results |

---

## Stability & Compatibility

**Backward compatibility is a standing commitment** (Issuerd has not cut numbered releases yet; the policy applies to the public codebase going forward):

- **Database** — the schema evolves exclusively through new, append-only migrations. Existing migration files are never modified, and upgrading from any earlier schema version happens automatically at startup.
- **APIs** — the Admin REST API and the OIDC/OAuth2 protocol surface change additively. Breaking changes require an explicit deprecation window, a documented migration path, and a `CHANGELOG.md` entry.
- **Configuration & provisioning** — new config keys and provision-YAML fields are optional with sensible defaults, so existing deployments keep booting unchanged.

The contributor-facing policy is enforced through `AGENTS.md`.

---

## Project Scope

All OIDC-parity feature areas are implemented. Deliberately out of scope for now: SAML 2.0, fine-grained admin permissions (FGAP), UMA/Authorization Services, Organizations, FAPI 2.0 message signing, CIBA ping/push modes.

---

## Contributing

1. Review the conventions in `AGENTS.md`
2. Create a feature branch: `git checkout -b feat/<feature-name>`
3. Implement with tests first (TDD encouraged)
4. Ensure `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo fmt --check` pass
5. Respect the backward-compatibility policy, keep the discovery document truthful, and keep the admin SPA dynamic (see the enum rule in `AGENTS.md`)

---

## Security

If you discover a security vulnerability in Issuerd, please report it privately.

- **Email:** security@issuerd.org
- **Process:** Please do not open public issues for security bugs. Provide a detailed description and reproduction steps, and allow reasonable time for remediation before public disclosure.

## License

Copyright 2026 Dmitry Andreev <da@issuerd.org> and contributors.

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Trademark

"Issuerd" and the Issuerd logo are unregistered trademarks claimed by the project. The code is Apache-2.0-licensed; the name and logo are not. See [TRADEMARK.md](TRADEMARK.md).
