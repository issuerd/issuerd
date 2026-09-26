# Issuerd — Agent Guide

> This file contains project-specific context for AI coding agents. Read this first before modifying any code.
> All documentation, comments, and design artifacts in this project are written in **English**.

---

## Project Overview

**Issuerd** is a horizontally scalable, modular Identity and Access Management (IAM) server implementing OIDC/OAuth2 protocols. It is written in Rust and inspired by Keycloak, which is used as a baseline reference implementation throughout the codebase.

The project is organized as a Cargo workspace with 9 library crates plus 1 binary crate. Each crate compiles independently and there are **no circular dependencies**.

- **Repository**: https://github.com/issuerd/issuerd
- **License**: Apache-2.0
- **Minimum Rust Version**: 1.95
- **Edition**: 2021

> **Backward Compatibility Policy:** Backward compatibility **is a hard requirement**. Keep it in mind for every change:
>
> - **Database schema:** existing migration files under `crates/issuerd-storage/migrations/` are **immutable** — never edit, rename, or reorder them. Schema and model changes ship as new, sequentially numbered migrations that upgrade any prior schema in place. Prefer expand-and-contract (add new → migrate data → drop old in a later migration) for destructive changes, and keep `InMemoryStorage` / `JsonFileStorage` semantics in sync (JSON snapshots must keep loading across model changes).
> - **Public APIs:** the Admin REST API and the OIDC/OAuth2 protocol surface must stay backward compatible. Prefer additive changes (new optional fields, new endpoints, new enum values with tolerant parsing). Breaking changes require an explicit deprecation window, a documented migration path, and a `CHANGELOG.md` entry.
> - **Config & provisioning:** new config keys and provision YAML fields must be optional with sensible defaults so existing deployments keep booting unchanged.

---

## Workspace Structure

```
issuerd/
├── Cargo.toml               # Workspace root
├── crates/
│   ├── issuerd-core/             # Shared types, traits, errors, ID types, models
│   ├── issuerd-protocol/         # OIDC/OAuth2 protocol parsing & validation (pure functions)
│   ├── issuerd-auth-flow/        # Authentication flow engine (pluggable authenticators)
│   ├── issuerd-token/            # JWT/JWS/JWK creation, signing, validation, introspection
│   ├── issuerd-storage/          # Storage trait + PostgreSQL (sqlx) + InMemoryStorage + JsonFileStorage impl
│   ├── issuerd-federation/       # User federation SPI (LDAP, Kerberos, custom)
│   ├── issuerd-admin-api/        # REST Admin API (Axum + utoipa/OpenAPI)
│   ├── issuerd-cluster/          # Distributed cache (Redis) & node discovery
│   └── issuerd-server/           # Axum HTTP server bootstrap, middleware, TLS, metrics
├── src/main.rs              # CLI binary (daemon + provision + openapi + example + healthcheck commands)
├── tests/integration.rs     # Workspace-level integration tests
├── scripts/
│   ├── setup.sh             # Dev environment setup
│   ├── test.sh              # Test runner wrapper
│   ├── bench.sh             # Benchmark runner
│   ├── federation-up.sh/.ps1 # Start the federation test stack helpers
│   ├── start-issuerd-dev.ps1 # Visible-console daemon start (Windows, see below)
│   ├── with-native-env.cmd  # Native openssl build env wrapper (Windows, see below)
│   ├── kani.sh / flux.sh / mirai.sh # Verification tool runners (Linux/WSL, see below)
│   ├── package-release.sh       # Release archive packaging (CI + local rehearsal, see below)
│   ├── cross-linux-arm64.sh     # Cross-compile the linux/arm64 release binary on x86_64 Ubuntu (no QEMU)
│   ├── publish.py               # crates.io workspace publish (staging + dry-run/real, see below)
│   └── aggregate_cov.py / show_uncovered.py # Coverage aggregation helpers
├── docker-compose.yml       # Local demo stack (pulls issuerd/issuerd:latest; console on :8080)
├── docker-compose.from-source.yml # Override to build the demo image from local sources
├── docker-compose.integration.yml # Integration test stack (Postgres, Redis, Bind9, Keycloak ref)
├── docker-compose.cluster.yml # Two-node cluster demo (nginx LB + Postgres + Redis)
├── cluster/                 # Cluster demo stack config (issuerd.toml, nginx.conf, provision.yaml)
├── dns/bind9/               # Bind9 zone config for the integration stack
├── examples/                # Example server/provision configs (regenerable via `issuerd example`) + local demo stack config (*.demo.*)
├── docs/                    # Operations documentation set (index: docs/README.md) + CLUSTERING.md, PERFORMANCE.md, crate graph
├── themes/                  # Login theme(s) served at /realms/{realm}/theme/{*path}
└── webclientsrc/            # Embedded React/Vite admin + account SPA (optional)
```

### Crate Dependency Rules

- The dependency graph must be a **DAG** — no mutual dependencies between any two crates.
- `issuerd-core` is the universal vocabulary crate (types + SPI traits) — every crate may depend on it.
- Beyond `issuerd-core`, the sanctioned non-core edges (see the Mermaid graph in `ARCHITECTURE.md`):
  `issuerd-auth-flow` → `issuerd-token`, `issuerd-cluster`; `issuerd-federation` → `issuerd-storage`;
  `issuerd-admin-api` → `issuerd-auth-flow`, `issuerd-federation`, `issuerd-token`, `issuerd-storage`, `issuerd-cluster`.
  New cross-crate edges must follow the same down-layer direction and never create a cycle.
- `issuerd-server` is the composition root — it depends on all other crates and wires them together.

---

## Technology Stack

| Layer | Crate / Library |
|-------|----------------|
| Async Runtime | `tokio` (rt-multi-thread) |
| HTTP Server | `axum` + `tower` + `tower-http` |
| Serialization | `serde` + `serde_json` + `serde_yaml` |
| Crypto | `ring`, `jsonwebtoken`, `rustls` |
| Storage | `sqlx` (PostgreSQL, compile-time checked queries) |
| Cache | `redis` (cluster-async, tokio-rustls) |
| Testing | `mockall`, `rstest`, `proptest`, `testcontainers`, `reqwest` |
| Observability | `tracing`, `tracing-subscriber`, `metrics`, `metrics-exporter-prometheus` |
| Config | `figment` (TOML/YAML/JSON + env) |
| OpenAPI | `utoipa` |
| Error Handling | `thiserror` (library errors), `anyhow` (application errors) |

---

## Build & Test Commands

### Essential Commands

```bash
# Build the entire workspace
cargo build --workspace

# Run unit tests only (fast, no I/O)
cargo test --workspace --lib

# Run all tests including integration tests
cargo test --workspace

# Run all tests including ignored benchmarks/spec stubs
cargo test --workspace -- --include-ignored

# Check formatting
cargo fmt -- --check

# Run clippy (treat warnings as errors — CI enforces this)
# --all-targets includes tests/benches so clippy warnings in test code are also caught.
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build docs
cargo doc --workspace --no-deps

# Build the release binary
cargo build --bin issuerd --release

# Run the daemon (after building)
cargo run --bin issuerd -- daemon -c issuerd.toml

# Export the OpenAPI specification
cargo run --bin issuerd -- openapi -o openapi.json

# Run coverage report (requires cargo-tarpaulin)
cargo tarpaulin
```

### Helper Scripts

```bash
# Run tests with modes: unit | integration | ignored | all | fmt | clippy | doc | deny | audit | geiger
./scripts/test.sh [MODE]

# Setup dev environment (installs tools, builds, runs tests + clippy)
./scripts/setup.sh

# Run benchmarks
./scripts/bench.sh
```

### VS Code / rust-analyzer

`.vscode/` is gitignored, so this is a per-machine opt-in: to have rust-analyzer
run the same strict clippy on save that CI enforces, add a local
`.vscode/settings.json`:

```json
{
  "rust-analyzer.checkOnSave": {
    "command": "clippy",
    "extraArgs": ["--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]
  }
}
```

This makes the Problems tab match `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

### Verification Tooling (static analysis & model checking)

Beyond fmt/clippy/test, the repo wires in four extra analysis tools. The GitHub
Actions layout:

- `.github/workflows/ci.yml` (push to `main` + PRs) — the per-commit gates:
  `cargo fmt --all -- --check`, `check --locked --all-targets --all-features`,
  `clippy --locked --all-targets --all-features -- -D warnings`,
  `doc --locked --workspace --no-deps`, `audit`,
  `deny check`, the web client (`npm ci` → `generate-api` → `npm run test` →
  `npm run build`), a `coverage` job (this IS the CI test run — there is no
  separate `cargo test` job: cargo-llvm-cov `--locked --workspace` runs the
  full unit + root integration suite instrumented, then
  `cargo test --doc` covers doctests, which llvm-cov cannot instrument on
  stable; Vitest `--coverage` for the web client; both reduced to shields.io
  endpoint-badge JSONs by `scripts/coverage_badges.py` and pushed to the
  `badges` branch on main — self-hosted, no external coverage service; the
  lcov export and the web client's HTML report are uploaded as workflow
  artifacts), and an `openapi-sync` job that regenerates the spec and diffs
  it against the committed `webclientsrc/openapi.json`.
  Docker-dependent test suites skip gracefully here.
- `.github/workflows/changelog.yml` (PRs) — fails the PR unless it touches
  `CHANGELOG.md` or carries the `no-changelog` label (see "Picking Up Work").
- `.github/workflows/heavy.yml` (nightly at 03:17 UTC + manual
  `workflow_dispatch` + `workflow_call` from release.yml on `v*` tags) — the
  heavy Docker suites: federation vs Samba AD DC + OpenLDAP, the two-node
  cluster E2E, the Keycloak dual-target parity run
  (`ISSUERD_TEST_TARGET=both`), the OIDF conformance suite
  (`tests/conformance/run.sh`; clones the pinned suite tag itself, packs
  `tests/conformance/results/` into one tarball and uploads it as the
  `conformance-evidence` artifact even on failure), and the release binary
  build (embeds the web client; release panics without `webclientsrc/dist`).
- `.github/workflows/release.yml` (push of a `v*` tag) — the release pipeline:
  validates tag ↔ `[workspace.package] version` ↔ CHANGELOG section, then:
  Docker Hub gets per-arch images (`issuerd/issuerd:X.Y.Z-amd64` from the
  canonical Dockerfile; `:X.Y.Z-arm64` packed from the cross-compiled binary
  via `Dockerfile.prebuilt`) merged by the docker-manifest job into the
  multi-arch user tags (`:latest`, `:X.Y.Z`, `:X.Y`); Linux amd64 (extracted
  from the canonical Docker build), Linux arm64 (cross-compiled by
  `scripts/cross-linux-arm64.sh`, no QEMU) and Windows binaries are packaged
  with SBOM + checksums via `scripts/package-release.sh`; the crates-io job
  runs `scripts/publish.py --real` for the whole workspace; the release job
  creates the GitHub Release (notes auto-extracted from CHANGELOG.md,
  build-provenance attestations). The docker/docker-arm64/docker-manifest and
  crates-io jobs are isolated so a registry hiccup never blocks the GitHub
  Release. Publish steps are gated on `env.ACT != 'true'` so the whole
  workflow can be rehearsed locally with nektos/act (see "Cutting a release"
  below).
- `.github/workflows/verification.yml` (push to `main` + PRs) — the extended
  tools below (flux is `continue-on-error` for now; the MIRAI job is disabled —
  hard-blocked upstream, see the tool notes).

| Tool | Purpose | Command | Notes |
|------|---------|---------|-------|
| cargo-audit | RUSTSEC advisory scan of Cargo.lock | `cargo audit` | justified ignores: `.cargo/audit.toml` |
| cargo-deny | advisories + licenses + bans + sources | `cargo deny check` | config: `deny.toml` |
| cargo-geiger | unsafe-code census | `cargo geiger --all-features` | informational report |
| Kani | model checking of proof harnesses | `scripts/kani.sh` | harnesses: `#[cfg(kani)]` module in `issuerd-protocol/src/pkce.rs` — both green |
| Flux | refinement types | `scripts/flux.sh` | crates opt in via `[package.metadata.flux]`; annotations from the `flux-rs` git shim |
| MIRAI | abstract interpretation / panic lint | `scripts/mirai.sh` | annotations from `mirai-annotations` (no-op in normal builds) |

All workspace crates (and the root binary) declare `#![forbid(unsafe_code)]` —
zero `unsafe` by construction, so geiger shows the `:)` badge for every `issuerd-*`
crate; only third-party dependencies contain `unsafe`.

As-run status (Kani 0.68 / CBMC 6.11, cargo-flux c460561, WSL):

- **Kani: 2/2 harnesses verify green** (~25 s solver time). Hard-won harness
  rules, documented in `pkce.rs`: tiny fixed-array `&str` inputs only (never
  `String::from_utf8(Vec)` — symbolic lengths explode loop unwinding), explicit
  `#[kani::unwind]` on every harness (unbounded unwinding never terminates on
  `str::from_utf8`), no symbolic SHA-256, no `RandomState` HashMaps (symbolic
  SipHash keys). Kani also caught a real spec bug during bring-up: the
  plain-method property must include the RFC 7636 43–128 length guard.
- **Flux: green in CI in scoped mode.** The current driver still ICEs on
  ordinary iterator chains in full-crate runs (`flux-infer/src/projections.rs:382`
  on `issuerd-core::roles::expand_composites` — upstream
  [flux-rs/flux#1666](https://github.com/flux-rs/flux/issues/1666) — and
  `flux-infer/src/infer.rs:484` on `reconcile_group_memberships_indexed`; driver
  limitations, not code issues). The `verification.yml` job therefore checks
  only the annotated defs: `cargo flux check -p issuerd-core
  --only-check="def:models::SecondsNonZero"` (everything else is auto-trusted).
  The `SecondsNonZero` refinement annotations stay in place (inert under plain
  rustc); the job stays `continue-on-error` because flux installs from its
  `main` branch. After a flux bump that fixes #1666, widen back to bare
  `cargo flux` (full-crate) via `scripts/flux.sh`.
- **MIRAI: hard-blocked upstream, cannot run at all.** MIRAI pins
  `nightly-2025-01-10` (~rustc 1.86) and bakes it into the `cargo-mirai`
  binary, while this workspace requires rustc >= 1.95 — cargo refuses at
  resolve time (`rustc 1.86.0-nightly is not supported`). The CI job is
  therefore disabled in `verification.yml` (a comment block marks where it
  lived; the old definition is in git history). Re-add it once MIRAI bumps
  its pinned toolchain to >= 1.95.
- Kani/Flux/MIRAI are Linux/macOS-only; on Windows run them in WSL (needs
  `sudo apt-get install -y build-essential pkg-config libssl-dev libkrb5-dev`;
  MIRAI additionally needs `cmake clang`).
- The `kani`/`mirai` cfgs are declared via `[lints.rust] unexpected_cfgs` in the
  crate's `Cargo.toml` — keep the `check-cfg` list in sync when adding new
  cfg-gated verification modules.
- Flux/MIRAI/Kani config keys are build-time only and do not affect the daemon.

### Running the Daemon with a Visible Console Window (Windows)

When an agent starts the `issuerd` executable directly (e.g., `cargo run` or
`./target/debug/issuerd.exe`), the process inherits the agent's console. In
agent environments such as an AI CLI / VS Code extension host, that
console is hidden from the user, so the daemon runs without a visible window on
the desktop.

**Always start the development daemon through Windows Terminal (`wt.exe`)** so
that logs are visible in a real desktop window:

```powershell
# From the repository root, using the helper script
powershell -ExecutionPolicy Bypass -File scripts/start-issuerd-dev.ps1

# Release binary
powershell -ExecutionPolicy Bypass -File scripts/start-issuerd-dev.ps1 `
    -Binary target/release/issuerd.exe -Config issuerd.toml

# Equivalent one-liner (PowerShell)
Start-Process -FilePath "wt.exe" -ArgumentList "cmd", "/k", `
    "cd /d C:\dev\issuerd && target\debug\issuerd.exe daemon -c issuerd.toml"
```

`scripts/start-issuerd-dev.ps1`:
- Resolves the binary and config paths relative to the repository root.
- Locates `wt.exe` (app execution alias or packaged executable).
- Opens a Windows Terminal tab running `cmd /k` so the window stays open and
  errors remain visible.
- Falls back to `Start-Process cmd.exe -WindowStyle Normal` if `wt.exe` is
  missing, but that fallback may not produce a visible window on systems where
  Windows Terminal is not the default terminal.

**What does not work reliably from the agent context:**
- `cargo run --bin issuerd -- daemon -c issuerd.toml` — output is captured
  by the agent; no desktop window.
- `Start-Process -FilePath target/debug/issuerd.exe` — may attach to the
  hidden parent console and show no window.
- `cmd /c start ...` — hangs or fails to start the program when invoked from
  the non-interactive agent shell.

**Tested on:** Windows 11 Pro 25H2 with Windows Terminal 1.24. The visible
window can be verified programmatically by enumerating top-level windows owned
by `WindowsTerminal.exe`; the tab title contains the issuerd command line.

### Manual Local Testing on Windows (In-Memory Provider + TLS)

For manual browser-driven testing on Windows, run the daemon against the
`issuerd.test.internal` domain instead of bare `localhost`:

- `issuerd.test.internal` is aliased to `127.0.0.1` in this machine's hosts
  file (`C:\Windows\System32\drivers\etc\hosts`).
- TLS uses a local self-signed development certificate
  `certs/issuerd.test.internal.crt` / `certs/issuerd.test.internal.key`
  (SAN covers `issuerd.test.internal` and `*.issuerd.test.internal`;
  the `certs/` directory is gitignored — generate the certificate on each
  machine that needs it). These are the same paths used by
  `ServerConfig::generate_example()` and `examples/issuerd.example.toml`.
- The root `issuerd.toml` dev rig uses the in-memory provider (no
  `[storage]` section) and plain HTTP. To run manual tests over HTTPS, add the
  `[tls]` section and switch `issuer_url` to the domain:

  ```toml
  issuer_url = "https://issuerd.test.internal:8080"

  [tls]
  cert_path = "certs/issuerd.test.internal.crt"
  key_path = "certs/issuerd.test.internal.key"
  ```

  Then browse to `https://issuerd.test.internal:8080`. The certificate is
  self-signed, so either trust it in the OS/browser certificate store or
  accept the browser warning.

**Test apps on other domains:** `app1.issuerd.test.internal` and
`app2.issuerd.test.internal` are also hosts-aliased to `127.0.0.1`, and the
wildcard SAN covers them — serve a test SPA over HTTPS with the same cert
(e.g. `npx http-server -S -C certs/issuerd.test.internal.crt -K certs/issuerd.test.internal.key -p 3443`).
Serve over HTTPS, not plain HTTP: a non-`localhost` name over HTTP is not a
browser secure context, so `crypto.subtle` (PKCE S256) is unavailable. Cross-origin
apps also need their origin in `[cors] allowed_origins` and the client
`redirect_uris`/`web_origins`. Hosts substitution is sufficient for domain
separation — origins, cookies, CORS, redirect-URI matching and TLS SAN all key
off the hostname string. Note: hosts has no wildcards, and Docker containers
bypass it (use the compose stack's Bind9 there).

**Mailpit (dev SMTP sink):** `tools/mailpit.exe` (gitignored via `/tools/`).
Run it: SMTP on `127.0.0.1:1025` (no auth/TLS), web UI + REST API on
`http://127.0.0.1:8025` (`GET /api/v1/messages`). This is the manual-verify
target for the email feature (verification and reset-credentials mails).
Quick SMTP probe without any SDK:
`curl.exe --url smtp://127.0.0.1:1025 --mail-from a@b.c --mail-rcpt d@e.f -T msg.eml`.

**Python on this host:** Python 3.14 is installed and available as `python`
(and via the `py` launcher). The `python3` alias on PATH is still a
WindowsApps stub — do not rely on it. For scripting, `python`,
`curl.exe`, Node 24 (global `fetch`), and PowerShell are all available.

### Docker Compose Stacks

The repository ships five compose stacks:

- **`docker-compose.yml`** (root) — the **local demo stack**: `docker compose up` **pulls the published image** `issuerd/issuerd:latest` (no build tools needed — a fresh clone with only Docker installed just downloads it) and starts a single-node Issuerd (project `issuerd-demo`) with PostgreSQL + Redis, the embedded web consoles on `http://localhost:8080/admin/console` (admin/admin), and the demo realm `myrealm` (alice/changeme). Provisioning comes from `examples/provision.demo.yaml` (mounted as `/etc/issuerd/provision.yaml`; server config: `examples/issuerd.demo.toml`) — it must create the master realm explicitly, because the automatic master-realm bootstrap only runs for the in-memory/json backends. This is the quickstart for people evaluating the project. Contributors build from local sources with the `docker-compose.from-source.yml` override: `docker compose -f docker-compose.yml -f docker-compose.from-source.yml up --build`.
- **`docker-compose.integration.yml`** — the **reference implementation test environment** (below).
- **`docker-compose.cluster.yml`** — the two-node cluster demo (see the next section).
- **`tests/conformance/docker-compose.yml`** — the **hermetic OIDC conformance environment** (below).
- **`tests/perf/docker-compose.perf.yml`** — the **isolated k6 performance benchmark stack** (below).

### Docker Compose for Integration Testing

`docker-compose.integration.yml` defines the **reference implementation test environment**.  
It includes a real Keycloak instance so that agents can compare protocol behavior, JSON shapes, and API responses against a proven baseline.

```bash
# Start the full integration test stack
docker compose -f docker-compose.integration.yml up -d

# Services:
#   - postgres:5432           (PostgreSQL 15)
#   - issuerd-postgres:5432 (Dedicated PostgreSQL for the Issuerd daemon, exposed on host 5433)
#   - redis:6379              (Redis 7)
#   - keycloak:8080           (Reference Keycloak 24.0, exposed on host 8081)
#   - bind9:53                (Local DNS on host 5533, static IP 172.30.0.2)
#   - samba-dc:389            (Samba AD DC — LDAP + Kerberos KDC)
#   - openldap:1389           (OpenLDAP generic schema)
```

**Agent notes**:
- Agents are allowed to run `docker` commands (e.g., `docker compose -f docker-compose.integration.yml up -d`, `docker exec`, `docker logs`) when needed for integration testing or reference validation.
- Always prefer **unit tests** that require no Docker. Use the compose stack only for integration tests or when explicitly validating against Keycloak behavior.
- When referencing Keycloak JSON, keep a small sample inline in the test file rather than depending on a running container for pure unit tests.
- The compose stack uses static IPs on the `test` network (`172.30.0.0/16`). `bind9` is pinned to `172.30.0.2` and copies the read-only Windows bind-mount config into `/var/cache/bind` at startup so the `bind` user can read it.
- `samba-dc` persists its generated `smb.conf` and `krb5.conf` in the `samba-data` volume and restores them on every start, so the container survives `docker compose down`/`up` cycles.
- The integration stack pins the explicit compose project name `issuerd` (decoupled from the checkout directory name; renaming from the old implicit project orphans the old volumes — recreate them with `docker compose -f docker-compose.integration.yml up -d` once); the root demo stack uses its own `issuerd-demo` project, so the two never collide.

### Cluster Stack (Multi-Node Demo)

`docker-compose.cluster.yml` (separate project `issuerd-cluster`) runs **two Issuerd nodes behind an nginx LB** sharing PostgreSQL + Redis — see `docs/CLUSTERING.md`.

```bash
# Build (root Dockerfile) and start: postgres + redis + issuerd-1/2 + lb
docker compose -f docker-compose.cluster.yml up -d --build

# LB endpoint: http://localhost:8088 (nodes also exposed on 18081/18082)
# Provisioned: realm demo (demo/demo123), master (admin/admin)

# Docker E2E suite against the running stack (skips unless the env var is set)
ISSUERD_CLUSTER_E2E=1 cargo test --test integration cluster_e2e

docker compose -f docker-compose.cluster.yml down -v
```

Multi-node contract: `cluster.enabled = true` requires PostgreSQL storage and Redis at boot. Signing keys live in the `signing_keys` table and are shared by all nodes (JWKS refresh via storage polling). `issuer_url` must be the LB URL, identical on every node.


### Conformance Stack (Hermetic OIDC Conformance Suite)

`tests/conformance/docker-compose.yml` (separate project `issuerd-conformance`) runs the OpenID Foundation Conformance Suite against Issuerd in a **fully isolated network** (`internal: true` — no internet at runtime), with bind9 as the only DNS (`conformance.test` zone, no forwarders) and TLS everywhere from a local root CA (`pki/gen-certs.sh`). The suite runs **pristine** (unpatched JAR built in-docker from the `conformance-suite/` clone, native Spring Boot HTTPS; the only deviation is the root CA in the JVM truststore at container start).

```bash
# One-time prerequisite: clone the suite (gitignored)
git clone https://gitlab.com/openid/conformance-suite.git tests/conformance/conformance-suite
cd tests/conformance/conformance-suite && git checkout release-v5.2.4

# Run everything (builds images, generates PKI, bootstraps, runs 3 plans, exports reports)
cd tests/conformance && docker compose up        # interactive
./run.sh                                         # CI: exit code + teardown; exports
                                                 # DOCKER_HOST_UID/GID=id -u/g on Linux
                                                 # (GH runner is 1001, not 1000) and
                                                 # dumps stack logs on failure
./run-focus.sh oidcc-refresh-token               # single Basic OP module
```

Results land in `tests/conformance/results/` (gitignored). Full guide: `tests/conformance/README.md`; per-module results: `tests/conformance/COVERAGE.md`. Static IPs on `172.31.0.0/16` — bind9 `.2`, pki-init `.3`, mongo `.10`, suite `.11`, op `.12`, conformance-run `.13`, test-runner `.14`, cdn-shim `.15` (every service is pinned: an exited one-shot releases its address and a dynamic allocation could otherwise squat on a reserved IP); Docker does not publish ports on `internal` networks, so all host interaction goes through `docker compose exec`. bind9 additionally answers the six CDN hostnames the suite web UI references, mapped to the `cdn-shim` nginx container serving the vendored mirror in `tests/conformance/cdn-shim/` (re-vendor with `cdn-shim/fetch.sh`) — all other external names stay REFUSED.

### Performance Benchmark Stack (k6 vs Keycloak)

`tests/perf/docker-compose.perf.yml` (separate project `issuerd-perf`) runs **k6 load scenarios against Issuerd and a reference Keycloak 26.7** under identical Docker CPU/memory limits, in a fully isolated network (`internal: true`, static IPs on `172.34.0.0/24`, no publishing anywhere — unlike `rig/`, which uses frpc). All images must be local before `up`; k6 scripts import only local files and disable usage reporting.

```bash
# One-time: build the benchmark image from HEAD, generate the KC realm import,
# and build the optimized production Keycloak image (kc.sh build → start --optimized)
docker build -t issuerd:perf -f Dockerfile .          # from the repo root
cd tests/perf && python scripts/gen_kc_realm.py
docker compose -f docker-compose.perf.yml build keycloak

./scripts/run.sh up-issuerd medium && ./scripts/run.sh up-kc medium
./scripts/run.sh smoke issuerd && ./scripts/run.sh smoke keycloak   # all PASS first
./scripts/run.sh seed-issuerd 1000 true                     # user0001..user1000 pool (KC gets it from the import)
export RUN_ID=$(date +%Y%m%d-%H%M%S)
./scripts/run.sh matrix issuerd medium && ./scripts/run.sh matrix keycloak medium
python scripts/charts.py results/                       # PNGs → docs/images/perf/, digest → results/digest.json
./scripts/run.sh wipe                                   # full reset (volumes deleted)
```

- Tiers (app-container limits via `ISSUERD_CPUS`/`ISSUERD_MEM`, `KC_CPUS`/`KC_MEM`): small 1 CPU/512 MiB, medium 2/1 GiB, large 4/2 GiB; PostgreSQL fixed at 2 CPU/2 GiB, k6 at 4/2 GiB.
- Scenarios (`tests/perf/k6/scenarios/`): discovery, client_credentials, password_grant (distinct-user pool), userinfo, introspect, auth_code_flow (PKCE), **dpop** (proofs minted in k6 via WebCrypto ES256 — jti single-use, ath on userinfo), **ciba** (bc-auth → approve → poll), admin_users (provisioning rate / seeding). All scenarios run against both targets — Keycloak 26.7 supports DPoP and CIBA by default. CIBA approval differs per server (it is out of spec): issuerd approves via its REST `ext/ciba/approve` with the user's SSO cookie; Keycloak has no such endpoint, so the `ad-simulator` container (`tests/perf/ad-simulator/`, python:3.12-alpine on 172.34.0.14) auto-approves through KC's `ciba-http-auth-channel` SPI + CIBA callback, and the KC poll is paced by a fixed, disclosed 200 ms modeled device-approval latency (the auth session only becomes visible to KC's callback once bc-auth commits — an instant first poll always loses that race and pays the 5 s slow_down interval).
- `run.sh scenario` wraps every run with `stats_sampler.sh` (docker stats → JSONL) and writes k6 summary JSON into `results/<RUN_ID>/`; `run.sh sizes <label>` snapshots DB/table sizes, row counts, log bytes, image sizes into `sizes.txt`.
- Published numbers live in `docs/PERFORMANCE.md` — regenerate them only from real runs of this stack; never hand-edit.
- `up-kc` applies `kcadm update realms/master -s sslRequired=NONE` after boot (the master realm otherwise rejects the admin-cli grant over internal HTTP); Keycloak runs the **optimized production build** + PostgreSQL — `tests/perf/keycloak/Dockerfile` bakes `db=postgres`/health/metrics via `kc.sh build` and the container runs `start --optimized --hostname=http://keycloak:8080` (hostname v2 full-URL form; a bare hostname would force https://…:8443 frontend URLs and break the plain-HTTP rig). Health/metrics are on the KC 25+ management port (:9000), admin bootstrap uses `KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD`, and `up-kc` also starts the CIBA `ad-simulator`.

### Federation Integration Tests (Samba DC + OpenLDAP)

Federation integration tests validate LDAP and Kerberos against real directories.

**Samba DC** (primary target) — `docker compose -f docker-compose.integration.yml up -d samba-dc`
- Provides LDAP on `localhost:389` and Kerberos KDC on `localhost:88`.
- Domain: `TEST.ISSUERD.LOCAL`
- Admin bind DN: `CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local`
- Admin password: `AdminPass123!`
- Test users: `testuser` / `Password123!`, `testuser2` / `Password123!`
- Test group: `developers` (with `testuser` as member)
- Tests live in `tests/integration/federation_samba.rs`.
- Tests skip gracefully at runtime if the container is not reachable.

**Windows Server Active Directory** (tertiary target) — your own AD DS lab
- Requires a reachable Windows Server with AD DS (LDAP on 389, LDAPS on 636 for password writes).
- No lab values are hardcoded: connection details come from the environment via `AdLab` (`tests/harness/mod.rs`):
  - Required: `ISSUERD_TEST_AD_HOST`, `ISSUERD_TEST_AD_BIND_CREDENTIAL`
  - Optional: `ISSUERD_TEST_AD_BASE_DN` / `_USERS_DN` / `_GROUPS_DN` / `_BIND_DN` / `_ADMIN_DN` (defaults mirror the `test.issuerd.local` layout), `ISSUERD_TEST_AD_ADMIN_PASSWORD`, `ISSUERD_TEST_AD_VM_NAME` / `_VM_SNAPSHOT` (Hyper-V reset, load test only)
- Expected fixture content: users `testuser` / `Password123!`, `testuser2` / `Password123!`; group `developers` (with `testuser` as member).
- Tests live in `tests/integration/federation_ad.rs`.
- Tests are marked `#[ignore]` by default and skip when the lab is unconfigured/unreachable; run with `cargo test --test integration federation_ad -- --ignored`.

**OpenLDAP** (secondary target) — `docker compose -f docker-compose.integration.yml up -d openldap`
- Provides LDAP on `localhost:1389`.
- Admin bind DN: `cn=admin,dc=test,dc=issuerd,dc=local`
- Admin password: `admin`
- Tests live in `tests/integration/federation_ldap.rs`.
- Tests are marked `#[ignore]` by default.
- The container starts with an **empty directory** (no seed users by default, memberof+refint overlays preloaded). Seed the test fixtures first: `./scripts/seed-openldap.sh` (idempotent; adds ou=users/ou=groups, testuser/testuser2 with `Password123!`, and the `developers` group with testuser as member).

```bash
# Primary federation tests (skip gracefully if Samba DC is down)
cargo test --test integration federation_samba

# Secondary federation tests (ignored by default)
cargo test --test integration federation_ldap -- --ignored
```

### Large-Scale Federation Load Tests

Load tests create large directory populations (Samba: **20,000 users**; OpenLDAP/AD: **100,000 users**; **1,000 groups** each), synchronize them into Issuerd backed by **PostgreSQL**, and validate login, group changes, user disable, and password changes.

These tests are gated by the `ISSUERD_FEDERATION_LOAD_TEST` environment variable and are **not** run by default.

| Env value | Test file | What it does |
|-----------|-----------|--------------|
| `samba` | `tests/integration/federation_load_samba.rs` | Reset Samba DC container, LDIF-import 20k users + 1k groups, sync, sample logins, group changes, disable, password change |
| `openldap` | `tests/integration/federation_load_openldap.rs` | Reset OpenLDAP container, LDIF-import 100k users + 1k groups, same validation (blocked — image unavailable) |
| `ad` | `tests/integration/federation_load_ad.rs` | Reset the AD lab Hyper-V VM (`ISSUERD_TEST_AD_VM_NAME` / `_VM_SNAPSHOT`), create 100k users + 1k groups via direct LDAP adds, same validation |
| `all` | All of the above | Run sequentially |

```bash
# Prerequisites
docker compose -f docker-compose.integration.yml up -d postgres

# Samba DC load test
set ISSUERD_FEDERATION_LOAD_TEST=samba
cargo test --test integration federation_load_samba

# OpenLDAP load test
set ISSUERD_FEDERATION_LOAD_TEST=openldap
cargo test --test integration federation_load_openldap

# AD load test (Windows + Hyper-V + ISSUERD_TEST_AD_* env vars required)
set ISSUERD_FEDERATION_LOAD_TEST=ad
cargo test --test integration federation_load_ad
```

**Important notes:**
- These tests reset their target environments (docker compose down -v / Hyper-V snapshot restore).
- Samba test: 20k users via chunked LDIF import, passwords for the first 200 users, 5 sample logins (LDAP binds against Samba are slow).
- AD test: 100k users via concurrent LDAP adds (5 tasks), passwords for 300 sample users over LDAPS, 100 sample logins, 50 password changes.
- PostgreSQL must be running and accessible at `postgres://issuerd:issuerd_secret@localhost:5432/issuerd`.
- For AD, LDAPS on the lab host (port 636) is required for password-related tests. If LDAPS is unavailable, password tests are skipped but sync and group tests still run.

**System dependency for Kerberos builds on Unix:**
- Debian/Ubuntu: `libkrb5-dev`
- RHEL/CentOS: `krb5-devel`
- Windows builds disable Kerberos via `cfg(unix)` gating; `KerberosFederationProvider` returns `NotSupported` on Windows.

**System dependency for WebAuthn (openssl) builds:**
`webauthn-rs` hard-depends on OpenSSL via `webauthn-rs-core` (no feature gate). On Unix it links the system OpenSSL as before. On Windows, `issuerd-auth-flow` references `openssl` with the `vendored` feature (target-gated), which builds OpenSSL from source and therefore requires:
- a **native Windows perl** (e.g. Strawberry Perl) on `PATH` — Git Bash's MSYS perl is rejected by OpenSSL's `Configure` ("doesn't produce Windows like paths"), and
- the **MSVC build tools** environment (`vcvars64.bat`, provides `cl`/`nmake`).

This dev host keeps a **portable Strawberry Perl** at `tools/strawberry-perl/` (gitignored via `/tools/`; fetch the `-portable.zip` from https://strawberryperl.com/releases.json and extract it there — no installer, no system changes). Any native perl on `PATH` works too.

Run cargo commands that (re)build `openssl-sys` through `scripts/with-native-env.cmd`, which puts `tools\strawberry-perl\perl\bin` on `PATH` and calls `vcvars64.bat` (override the VS path via the `VCVARS64` env var):

```bash
# From Git Bash — note the //c, MSYS converts a bare /c
cmd.exe //c scripts\with-native-env.cmd cargo test --workspace
```

Plain `cargo build/test` works in any shell too: the committed `.cargo/config.toml` pins `OPENSSL_SRC_PERL` to `tools/strawberry-perl/perl/bin/perl.exe` (a pre-existing env var takes precedence), and cc-rs/openssl-src locate the MSVC tools even without vcvars. Because the build fingerprint tracks the compiler environment, the first build in a different shell flavor (Git Bash vs Developer Prompt vs wrapper) triggers a one-time ~5-minute OpenSSL rebuild — it succeeds instead of failing. If `tools/strawberry-perl` is missing you get `Command 'perl' not found`; extract the portable zip there or use the wrapper. Unix CI/dev machines need none of this.

---

## Code Style Guidelines

### Formatting

Enforced by `rustfmt.toml`:
- `max_width = 100`
- `chain_width = 80`
- `fn_call_width = 80`
- `reorder_imports = true`
- `reorder_modules = true`

### Clippy

Enforced by `clippy.toml`:
- `cognitive-complexity-threshold = 25`
- `type-complexity-threshold = 300`
- `avoid-breaking-exported-api = false`

CI runs: `cargo clippy --locked --all-targets --all-features -- -D warnings`

### Naming & Module Conventions

- ID types are newtype wrappers: `RealmId(String)`, `UserId(String)`, etc.
- Error type is `IssuerdError` (defined in `issuerd-core`). All crates return `Result<T, IssuerdError>`.
- Traits are defined in `issuerd-core` and implemented downstream:
  - `Storage` → `issuerd-storage`
  - `CryptoProvider` → `issuerd-token`
  - `DistributedCache` → `issuerd-cluster`
  - `Authenticator`, `RequiredAction`, `IdentityProvider` → `issuerd-auth-flow` / `issuerd-federation`
- Module re-exports in `lib.rs` use `pub mod` for all public submodules.
- Use `///` for item documentation and `//!` for module-level documentation.

### Error Handling Patterns

- Library crates use `thiserror`:
  ```rust
  #[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
  pub enum IssuerdError {
      #[error("invalid request: {0}")]
      InvalidRequest(String),
      #[error("unauthorized client")]
      UnauthorizedClient,
      // ...
  }
  ```
- `IssuerdError` provides `oauth_error_code()`, `http_status()`, and `to_oauth2_error()` for protocol mapping.
- Application/bootstrap code may use `anyhow` for error propagation.

### Logging Conventions

All logging goes through `tracing` (dependencies' `log`-facade records are bridged in via `tracing-log` at startup).

**Levels**

| Level | Use for | Examples |
|-------|---------|----------|
| ERROR | Unexpected internal failures needing operator action | storage/crypto failure, token issuance failure, SMTP outage, 5xx responses, background-task crash |
| WARN | Handled but security-relevant or degraded | wrong password, invalid/expired token, client-auth failure, brute-force counter write failure, fail-open degradation, provider unreachable, malformed operator config |
| INFO | Lifecycle and significant business events only | startup/shutdown, listen addr, realm/user/client created, key rotated, sync completed (counts), login success |
| DEBUG | Per-request flow decisions, step transitions | mapper evaluation, flow branch choices, per-probe readiness |
| TRACE | Hot-path / per-record dumps | per-user sync rows, LDAP entry dumps |

**Structure** — dynamic values are structured fields (`field = %v`), never interpolated into the message; errors always as `error = %e` (preserve the anyhow/source chain); no `?struct` Debug dumps of maps/models that may contain secrets.

**Secrets — never logged at any level:** passwords, hashes, client secrets, TOTP secrets/codes, email one-time codes, action/reset tokens, access/refresh/ID tokens, authorization codes, DPoP proofs, client assertions, Kerberos/SPNEGO blobs, private keys, cookies/Authorization headers, connection URLs containing passwords. Request spans record only the URL **path** — never the query string, which carries credentials on GET flows.

**Identifiers & PII** — session IDs and credential IDs: DEBUG at most, never in span fields. Usernames: allowed in security WARN events, but must be sanitized with `issuerd_core::utils::sanitize_log_str` (strips control chars → no log-injection). Email addresses: allowed in deliberate mail-lifecycle logs/spans only. Client IPs: not in per-request span fields; allowed as an explicit field on security WARN events.

**Spans** — every `#[instrument]` skip list must cover: `state`, `headers`, `body`/`body_bytes`, `params`/`query`, `Path(...)` args carrying session/credential ids, and `ClientIp`/IP args. `fields(...)` may carry `realm`, `client_id`, `authenticator` — never secrets/PII beyond the policy above. No dead (never-recorded) fields.

---

## Testing Instructions

### Testability Rule (Strict)

> Every public function must be testable without network I/O or database.

Achieved by:
- All storage via `dyn Storage` trait → `InMemoryStorage` in tests
- All crypto via `dyn CryptoProvider` trait → mock implementations in tests
- All cache via `dyn DistributedCache` trait → `InMemoryCache` in tests
- Protocol parsing is pure functions (no traits needed)

### Testing Tools & Patterns

| Tool | Use Case |
|------|----------|
| `mockall` | Mock async traits (`Storage`, `CryptoProvider`, etc.) |
| `rstest` | Parameterized / table-driven tests |
| `proptest` | Property-based tests (serialization roundtrips, ID parsing) |
| `testcontainers` | PostgreSQL / Redis / LDAP integration tests |
| `InMemoryStorage` | HashMap-backed `Storage` for fast unit tests |
| `reqwest` | HTTP client for integration tests against running server |

### Test Organization

- Unit tests live in `#[cfg(test)]` modules at the bottom of the same source file.
- Integration tests live in `tests/integration/` at workspace root, declared via `tests/integration.rs`.
- Unit tests only: `cargo test --workspace --lib` (fast, no I/O).
- `cargo test --workspace` runs unit tests + root integration tests together.
- Run E2E tests only: `cargo test --test integration` (< 30 seconds, no Docker).
- Run ignored benchmarks/spec-conformance stubs: `cargo test --test integration -- --ignored`.

### Dual-Target Integration Tests (Keycloak Compatibility)

A subset of integration tests (`oidc_discovery`, `oauth2_grants`, `token_lifecycle`, `token_validation`) are parameterized to run against both Issuerd (in-process) and a real Keycloak 24.0 container.

| Environment variable | Behaviour |
|----------------------|-----------|
| `ISSUERD_TEST_TARGET=issuerd` (default) | Run only against in-process Issuerd |
| `ISSUERD_TEST_TARGET=keycloak` | Run only against Keycloak on `localhost:8081` |
| `ISSUERD_TEST_TARGET=both` | Run against both targets sequentially |

```bash
# Fast default — no Docker needed
cargo test --test integration

# Against Keycloak (requires `docker compose -f docker-compose.integration.yml up -d` first)
ISSUERD_TEST_TARGET=keycloak cargo test --test integration

# Full conformance — both targets
ISSUERD_TEST_TARGET=both cargo test --test integration
```

**Keycloak setup**:
```bash
docker compose -f docker-compose.integration.yml up -d keycloak
# Wait for http://localhost:8081/health/ready to return 200
```

Keycloak uses an embedded H2 database in dev mode, so no PostgreSQL init is required.

**Differences documented in**: `tests/KEYCLOAK_DIFFS.md`

### Coverage

- **Preferred fast tool:** `cargo-llvm-cov`
  - Install: `cargo install cargo-llvm-cov`
  - Single-crate lib check: `cargo llvm-cov -p <crate> --lib --summary-only`
  - Instant re-report (no test re-run): `cargo llvm-cov report -p <crate> --summary-only`
  - HTML output: `cargo llvm-cov -p <crate> --lib --html`
  - Why it is faster: `-p <crate>` scopes compilation to one crate; `--lib` skips integration tests, binaries, and examples; LLVM instrumentation is faster than tarpaulin's ptrace/dyninst approach.
  - **Workspace per-crate summary:**
    ```bash
    # Run unit tests with instrumentation and show per-file summary
    cargo llvm-cov --workspace --lib --summary-only

    # Export JSON for custom per-crate aggregation
    cargo llvm-cov --workspace --lib --json --summary-only > cov.json

    # Aggregate per-crate numbers (requires Python)
    python scripts/aggregate_cov.py cov.json
    ```
    The JSON output contains per-file coverage data that can be aggregated by crate prefix (e.g. `crates/issuerd-core/src/...`). Note that `--lib` excludes Docker-dependent integration tests, so `postgres.rs`, `redis_cache.rs`, and similar I/O modules will report 0% in this view.
- **Legacy tool:** `cargo-tarpaulin` with LLVM engine.
  - Config: `tarpaulin.toml`
  - Outputs: HTML, XML (Cobertura), LCOV, stdout.
- Target: >90% unit test coverage per crate (enforced once baseline is established).

---

## Crate-Specific Notes

### `issuerd-core` — Foundation

- Contains **only** data types, traits, errors, and utilities. **No I/O, no async runtime dependencies.**
- Key exports: `IssuerdError`, `OAuth2Error`, `RealmId`, `UserId`, `ClientId`, `SessionId`, `KeyId`, `Storage`, `CryptoProvider`, `DistributedCache`, `Authenticator`, `IdentityProvider`, `EventListener`, `TokenService`, `AuthContext`, `Challenge`, `AuthStepResult`, `RequiredAction`, `RequiredActionResult`, `Pagination`, `EventQuery`.
- Typestate exports (`issuerd_core::typestate`): `TypedAuthContext`, `TypedSession`, `TypedFlowResult`, `TypedChallenge`, `AuthState`, `SessionState`, `ChallengeKind`, `ActionState`, `PendingState`, `AuthRequestState`, plus marker types (`AnonymousState`, `AuthenticatedState`, `SessionAnonymous`→`SessionExpired`, `ActionsPending`/`ActionsCleared`, `LoginFormKind`/`OtpFormKind`/`WebAuthnKind`/`RedirectKind`/`CookieKind`). Realm-bound authentication helpers: `RealmBound<T>`, `AccountSessionGuard`, `SafeRedirectTarget`.
- Models: `Realm`, `User`, `Client`, `Role`, `Group`, `Credential`, `UserSession`, `Consent`, `IdentityProviderConfig`, `FlowConfig`, `Event`, `AdminEvent`, `JwkSet`, `Jwk`, `IntrospectionResponse`, `LogoutToken`, etc.
- Client scopes: `client_scope.rs` (`ClientScope`, `ProtocolMapper`, `MapperType`, `ScopeMappings`, `ClaimTarget`, `mapper_config` keys, `builtin_client_scopes`, `DEFAULT_DEFAULT_SCOPES`/`DEFAULT_OPTIONAL_SCOPES`) and `roles.rs` (`expand_composites`, `effective_user_roles`, `effective_group_roles`) hold the mapper/role-resolution vocabulary shared by issuerd-server and issuerd-admin-api.

### `issuerd-protocol` — Pure Functions

- Parse and validate OIDC/OAuth2 request parameters.
- **No async, no DB, no I/O.** Input `HashMap`/JSON, output `Result<T, IssuerdError>`.
- Modules: `authorization`, `token`, `discovery`, `introspection`, `pkce`, `ciba`, `device`, `error`, `utils`.

### `issuerd-auth-flow` — Flow Engine

- State machine of pluggable authentication steps.
- `FlowExecutor` takes a `PluginRegistry` and executes flows.
- `AuthContext` is a plain struct — construct any test scenario directly.
- `PluginRegistry` trait -- resolves authenticators and required actions at runtime.
- **Typestate shell:** `TypedFlowExecutor` wraps `FlowExecutor` and returns `FlowOutput` (typed `Success`/`Challenge`/`Failure`). All internal flow logic remains in Layer 1 (`FlowExecutor`); Layer 2 adds zero-cost compile-time proofs at the boundary.

### `issuerd-token` — JWT Engine

- `TokenManager<C: CryptoProvider>` is generic over crypto backend.
- Token **validation** is synchronous and stateless (cryptographic only).
- Token **issuance** requires `CryptoProvider` but no storage.

### `issuerd-storage` — Storage Adapters

- `PostgresStorage` uses `sqlx` with compile-time checked queries (`query_as!`).
- `InMemoryStorage` uses `DashMap` for thread-safe concurrent access.
- `JsonFileStorage` wraps `InMemoryStorage` with full JSON snapshot persistence on every write; global mutex lock makes it slow and suitable for manual testing only.
- Migrations are handled via `sqlx migrate` or embedded migrations. **Migrations are append-only** — existing files are immutable; ship schema changes as new numbered migrations (see the Backward Compatibility Policy at the top of this file).
- **Batch inserts:** `Storage::bulk_create_users` (default loop impl, overridden in `PostgresStorage` with `INSERT ... SELECT * FROM UNNEST(...)`) is used by `UserSynchronizer` to speed up large-scale federation syncs. **Batch reads:** `get_clients_batch`, `get_client_roles_by_names`, `get_client_scopes_by_names`, `get_client_scopes_by_ids`, `get_groups_batch` (default loop impls, `PostgresStorage` overrides with `= ANY($n)` and input-order restore in Rust) back the claims-assembly fan-out in `issuerd-server/src/claims.rs`; contract: results in input order, unknown ids/names skipped.
- **Signing keys:** the `signing_keys` table (`005_signing_keys.sql`) persists the cluster-wide JWT signing keys (private DER + public JWK). All backends implement `list_signing_keys`/`create_signing_key`; `JsonFileStorage` includes them in its snapshot. **Envelope encryption at rest (opt-in, PostgreSQL only):** migration `017_signing_key_encryption.sql` adds `private_der_enc` + `kek_kid` and nullifies `private_der` (expand; the plaintext column drops in a later contract migration). `PostgresStorage` holds an optional `Arc<dyn KeyEncryptionKeyProvider>` (issuerd-core trait — the KMS/HSM SPI seam; local impl: `Aes256GcmKekProvider` in `src/key_encryption.rs`, AES-256-GCM via `ring`, blob = `0x01 || nonce(12) || ciphertext||tag`) via `connect_with_key_encryption`; reads decrypt transparently (ciphertext-only row + no/unknown KEK = hard error naming kid + kek_kid; both-columns row = ciphertext authoritative), writes encrypt (new keys and every `update_signing_key`), and `reencrypt_signing_keys_with_active_kek` is the boot sweep for legacy plaintext rows and KEK rotation. Decrypted material rides `zeroize::Zeroizing` into `StoredSigningKey` (zeroized on drop). InMemory/JSON backends stay plaintext by design.
- **Client scopes:** migration `011_client_scopes.sql` adds the scope/assignment/role-mapping tables and relaxes role name uniqueness to per-(realm, client, name); `seed.rs` seeds the 8 built-in scopes per realm and default assignments per client (always including `roles`) — idempotent, hooked into `create_realm`/`create_client`, `run_migrations` (backfill), and JSON snapshot load.

### `issuerd-cluster` — Distributed Primitives

- `RedisCache` uses the `redis` crate with cluster-async support.
- `InMemoryCache` for dev/tests.
- Cache key schemas: `session:{realm}:{id}`, `realm:{id}`, `realm-by-name:{name}` (realm-name lookup cache), `sessv:{realm}:{user_id}` (per-user session-validity version counter), `client:{realm}:{client_id}`, `login-failure:{realm}:{username}:{ip}`, `dpop-nonce:{realm}:{nonce}` (opt-in single-use DPoP server nonces, `[dpop.nonce]`), plus the claims read-model keys: `user-claims:{realm}:{user_id}` (user row + groups + direct role-mapping ids), `realm-catalog:{realm}` (all role + client-scope definitions), `client-scopes:{realm}:{uuid}` (default scope assignments), `client-uuid:{realm}:{uuid}` (uuid→identifier reverse map), `claimsepoch:{realm}` (epoch counter tagging every claims entry), and the rendered-response cache keys: `usergen:{realm}:{user_id}` / `clientgen:{realm}:{client_id}` (per-user / per-client claims generation counters), `uinfo-resp:{realm}:{user_id}:{fp}` (rendered userinfo body, re-validated against epoch+usergen+clientgen on every read), `discovery-resp:{realm_name}` (pre-rendered discovery document, validated against a realm-content hash + the server-global keyset generation).
- `DistributedCache::increment` provides atomic counters (Redis `INCR` + conditional `PEXPIRE` Lua script; `DashMap::entry` in-memory) — used by login-failure tracking so brute-force counters aggregate correctly across nodes, and by the `usergen`/`clientgen` claims-generation counters.
- `src/invalidate.rs` holds the best-effort invalidation primitives for the claims read model: `invalidate_user_claims` / `invalidate_client_claims` (bump the matching `usergen`/`clientgen` generation counter FIRST — that is what retires rendered userinfo response entries — then precise-delete the read-model keys) and `bump_claims_epoch` (realm-wide invalidation for definition changes). Writers call them right after the storage mutation commits; failures are logged and swallowed (the entry TTL is the fail-safe bound).

### `issuerd-admin-api` — Management API

- Axum handlers with `utoipa` attributes for OpenAPI generation.
- Admin endpoints require `realm-management` client roles.
- Admin tokens are bound to the path realm (Keycloak model): tokens issued by the `master` realm administer every realm; other tokens only the realm that issued them; realm creation/listing is master-only.
- Client scopes & roles: client-scope CRUD + protocol-mapper sub-resources (client scopes AND clients), client-role CRUD, role-mappings for users/groups (`RoleRepresentation[]` payloads; `available`/`composite` sub-paths), client scope-mappings, scope assignment endpoints that sync the client's scope string lists, realm default scope tables, `service-account-user` (lazy provisioning). `/admin/enums/mapper-types` + `serverinfo.mapper_types` feed the SPA dropdowns.
- Admin depth: editable flows/executions + per-execution authenticator config (`flows.rs`; built-in flows read-only, bound/sub-flow-referenced delete guards, whole-set validation-on-save via `issuerd_auth_flow::validation`), user credentials CRUD (`credentials.rs`; redacted, last-credential guard, `moveAfter` renumbers 1..n), execute-actions-email + impersonation (`user_actions.rs`), groups children/members/move + role-composite sub-resources (`groups.rs`, `composites.rs`), partial import/export + push-revocation stub (`import_export.rs`). `GET/PUT /realms/{realm}/events/config` + `DELETE .../events|admin-events` (a fresh admin event records each wipe) + `GET .../events/count` + `GET .../admin-events/count` (filtered totals back the SPA's server-side pagination); event queries clamp `date_from` to `now - events_expiration_secs` when set. Event representations resolve `user_id` → `username` at query time (fallback: the recorded `username` detail) and expose `session_id`; admin events resolve `auth_username` against `auth_realm_id` (master-realm admins). Admin-event writes are gated per realm in `audit.rs` (`emit_admin_event*`): skipped unless `admin_events_enabled`, representation stripped unless `include_representations` (Issuerd defaults: `events_enabled`/`admin_events_enabled` both ON — Keycloak parity break; `include_representations` OFF; when the realm row is missing or cannot be loaded the event is still recorded but the representation is stripped — fail-closed, a realm with unknown preferences has not opted into storing request bodies). `POST /keys/rotate` + `PUT /keys/{kid}/disable` manage the server-global `signing_keys` table (realm segment is namespace parity only) and invoke `AdminApiState.signing_key_reload` so this node's keystore + JWKS snapshot reload without waiting for the polling tick.
- Uses `AdminApiError` for consistent error responses.

### `issuerd-server` — Bootstrap

- `ServerState` holds `Arc<dyn Storage>`, `Arc<dyn DistributedCache>`, `Arc<dyn CryptoProvider>`, `Arc<dyn TokenService>`, etc.
- Middleware stack (registration order): Trace → CORS → Compression → RequestId → RealmResolution → ProxyIp. Tower executes layers last-registered-first on the request path, so requests actually enter through ProxyIp → RealmResolution → RequestId → Compression → CORS → Trace, and responses unwind in reverse.
- CORS is locked down by default: no cross-origin browser requests are allowed unless origins are listed in `[cors] allowed_origins` (e.g. `["https://app.example.com"]`). The embedded SPA is same-origin and needs no CORS.
- Metrics served at `/metrics` via `metrics-exporter-prometheus`.
- Health endpoints: `/health` (liveness), `/ready` (readiness).
- TLS via `axum_server` with `tokio-rustls`.
- Graceful shutdown on SIGINT/SIGTERM.
- **Realm resolution:** OIDC endpoints (`auth`, `token`, `login`) resolve the realm **by name** (`get_realm_by_name`) before using `realm.id` for storage lookups. Issuer URLs embed the realm **name** (`{issuer_url}/realms/{name}`, Keycloak parity — never the UUID id); `iss` consumers resolve the segment back to the realm via `ServerState::resolve_issuer_realm` (name-only — pre-switch id-spelled tokens are rejected). Realm ids stay UUIDs internally (sessions, events, action tokens, cache keys). `RealmName` validation guarantees a valid name is always a safe single URL path segment (no whitespace, no `/ \ ? # % + & =`). The by-name resolution is cache-aside (`realm-by-name:{name}`, TTL `[cache] read_cache_ttl_secs` — the unified read-cache knob; `0` disables it along with every other read-model cache for pure-DB behavior, JSON-serialized `Realm`; `ServerState::realm_by_name_cached` behind both `resolve_issuer_realm` and `resolve_realm`): admin realm mutations (`update_realm`/`delete_realm`/`update_events_config`) delete the key synchronously, negative results are never cached, cache errors degrade to storage with a WARN, and writes bypassing the admin API (direct DB edits, boot seeding) are bounded by the TTL. Tests that mutate a realm directly in storage after a resolution must delete the key themselves.
- **Session-validity cache:** `src/session_cache.rs` keeps the per-request "does this user session still exist" check off the database for userinfo/introspect and the account API (all three share `routes::oidc::enforce_token_validity`, which also covers RFC 7009 revocation and realm `not_before`; the account API additionally rejects DPoP-bound tokens presented as plain Bearer). `session_snapshot(state, realm_id, sid)` answers from `session:{realm}:{sid}` entries — positive `{"u":user_id,"v":version}` with TTL `[cache] read_cache_ttl_secs` (the unified read-cache TTL, default 60 s; `0` disables every read-model cache for pure-DB behavior) or a 5 s negative marker `{"x":1}` absorbing replay floods of deleted-session tokens. Single-session deletes (logout, admin revoke, SSO-idle cleanup) call `invalidate_session` synchronously; user delete DB-cascades sessions, so `delete_user` bumps the `sessv:{realm}:{user_id}` counter (`bump_user_session_version`) and stale-versioned snapshots miss. All cache errors fall back to storage (fail-closed semantics unchanged).
- **Axum 0.8 note:** Route parameters use `{param}` syntax (e.g., `/realms/{realm}/users/{id}`). Catch-all routes use `/{*path}`. Sub-routers with different state types must be mounted with `.nest_service(path, router)` after the sub-router's state is erased via `.with_state(state)`.
- **Typestate boundaries:** OIDC auth and login handlers use `TypedAuthContext`, `TypedFlowExecutor`, and `FlowOutput` to enforce compile-time proof of authentication state. `PendingAuthData` carries a `_typestate_tag` field for cache serialization.
- **Clustering:** signing keys are loaded from (and generated into) shared storage at boot (`bootstrap_crypto_provider`; a fresh empty `signing_keys` table is seeded with the active EdDSA + RS256 initial pair — EdDSA is the signing default, RS256 is the OIDC Core §15.1 mandatory-to-implement key discovery must advertise), so all nodes sign with the same active key and validate peer tokens; with PostgreSQL storage a background task polls the key set every `cluster.jwks_refresh_interval_secs` and reloads the keystore + JWKS snapshot on change. Admin-triggered rotation/disable additionally fires `ServerState::signing_key_reload` (built in `from_components` while the concrete `RingCryptoProvider` is still in reach; spawns the same list→`reload_keys`→`refresh_jwks` sequence) for immediate same-node reload. `ServerState::from_components(config, storage, cache)` builds state from injected shared components (used by multi-node tests). `[cluster] enabled = true` fails boot without PostgreSQL + Redis. `/ready` probes both storage and cache. Both reload paths also bump `ServerState.keyset_generation` (in-memory `AtomicU64`), which validates the pre-rendered discovery cache (`src/discovery_cache.rs`): `discovery-resp:{realm_name}` entries carry a 16-byte header (realm-content hash + keyset generation) prepended to the serialized document, so realm edits and key rotations take effect on the next request.
- **Claims assembly:** token/userinfo claim content is decided in `src/claims.rs` — `build_claims_overlay` resolves granted scope names to client scopes (plus default-assigned scopes for access tokens) and evaluates their protocol mappers; `issuerd-token` only signs what it is given. Token-endpoint ID tokens get NO overlay (OIDC Core §5.4); userinfo and pure-implicit ID tokens do. All gathering goes through the **claims read-model cache** (`src/claims_cache.rs`, `ClaimsReader`): a warm-cache userinfo costs zero storage queries. Five epoch-tagged key shapes hold the read model — `user-claims:{realm}:{user_id}` (user row, group rows, direct realm/client role-mapping ids), `realm-catalog:{realm}` (every role + client scope; name→object resolution happens in Rust), `client:{realm}:{client_id}`, `client-scopes:{realm}:{uuid}` (default scope assignments), `client-uuid:{realm}:{uuid}` (role-owner display ids). Every entry stores the realm's `claimsepoch` it was written at; a mismatch is a miss (refetch, rewrite). Single-entity mutations delete their keys precisely (`issuerd_cluster::invalidate::invalidate_user_claims`: user update/delete, per-user role mappings, group membership — wired in issuerd-admin-api `users.rs` and issuerd-server `account.rs`/`broker.rs`/`required_actions.rs`/`reset_credentials.rs`; `invalidate_client_claims`: client update/delete/secret-rotation, client-local mapper CRUD, scope assignments, scope-mappings — wired in issuerd-admin-api `clients.rs`/`client_scopes.rs`/`scope_mappings.rs` and issuerd-server `client_registration.rs`, rename-safe via the OLD identifier). Definition changes that fan out to many entries bump the epoch (`bump_claims_epoch`): role/client-role CRUD, composites, group CRUD + group role mappings, client-scope CRUD + scope-mapper CRUD, partial import, federation sync runs. Realm default scope tables are deliberately NOT wired (they only seed new clients). Partially-degraded loads (a failed sub-read) are served but never cached; cache errors fall back to storage with a WARN; negative results are never cached; writes that miss both invalidation paths are bounded by the TTL. Tests that mutate users/clients/roles/scopes/groups directly in storage after a cached read must call the matching `issuerd_cluster::invalidate::*` helper themselves. Above the read model, `src/userinfo_cache.rs` caches the fully rendered userinfo body (`uinfo-resp:{realm}:{user_id}:{fp}`; `fp` = client id + sorted scopes + hashes of the token's `claims`/`authorization_details`; the client id is passed alongside, never parsed out of `fp`, because client identifiers may contain `|`) with a 24-byte `epoch|usergen|clientgen` header re-validated against the live counters on every read — a hit skips the read model, mapper evaluation, and rendering entirely. All token-validity gates (signature, expiry, revocation, realm `not_before`, user-session existence) run per request BEFORE this cache is consulted, so logout/revocation stay immediate; the `invalidate_*` generation bumps retire its entries.
- **OpenAPI assembly (`src/openapi.rs`):** `full_openapi()` merges the admin document with the issuerd-server-owned endpoints — the account-console API (`routes/account.rs`, utoipa-annotated), the public protocol helpers (`login/context`, the token endpoint), and the internal SPA auth API (`/api/v1/auth/logout`) — so the CLI export and Swagger UI serve one complete spec.
- **Signing-key encryption wiring:** `from_config` builds the optional KEK provider from `[crypto.key_encryption]` (`CryptoSettings::build_kek_provider` in `src/config.rs` — invalid section = boot abort) and passes it to `PostgresStorage::connect_with_key_encryption`, then runs the `reencrypt_signing_keys_with_active_kek` sweep between migrations and the keystore load (wrong KEK = boot failure). Without the section, PostgreSQL deployments get a startup WARN that signing keys are stored in plaintext; with a non-PostgreSQL backend the section is ignored (WARN — PostgreSQL-only feature).

---

## Security Considerations

1. **Constant-time comparison** for secrets and tokens — use the `subtle` crate where applicable.
2. **Password hashing** — Argon2id via `argon2` crate; PBKDF2 for imported hashes.
3. **Token validation is stateless** — access tokens are self-contained JWTs. No DB lookup required for validation.
4. **Rate limiting** — per-IP and per-user login failure tracking via `issuerd-cluster`.
5. **Input validation** — strict parsing in `issuerd-protocol`; reject unknown parameters where required by spec.
6. **Audit logging** — all admin mutations and authentication events are logged immutably via `Event` / `AdminEvent`.
7. **Key rotation** — coordinated via storage polling or Raft consensus; JWKS cached in-memory per node.
8. **Signing keys at rest** — optional envelope encryption (`[crypto.key_encryption]`, AES-256-GCM, KEK from config/env, never the DB; see the issuerd-storage notes). Decrypted key material and retired keys are zeroized on drop (`zeroize` crate: `StoredSigningKey`, keystore `SigningKey`, transient decrypt buffers); residual copies inside `ring`/`jsonwebtoken` per sign call are documented in `key_encryption.rs`.
9. **Code scanning** — GitHub CodeQL default setup (languages: actions, JS/TS, Python, Rust) with `.github/codeql/codeql-config.yml` merged in via the `github-codeql-config-file` repository property (org-level custom property — an org admin must define it in the org schema before the repo value sticks). The config excludes the test trees (`tests/**`, `webclientsrc/src/test/**`, `*.test.ts(x)`): they are full of intentional fixture credentials that otherwise drown the alert queue in `hard-coded-cryptographic-value` false positives. Alerts from inline `#[cfg(test)]` modules (cannot be path-excluded) are dismissed as *used in tests*; anything in production paths (`crates/`, `src/`, `webclientsrc/src`, `webclientsrc/public`) must be treated as real until proven otherwise.

---

## Development Workflow

### Picking Up Work

1. Review the conventions in this file (build commands, crate rules, implemented features below).
2. Create a feature branch: `git checkout -b feat/<feature-name>`.
3. Implement with tests first (TDD is encouraged).
4. Ensure `cargo test --workspace` and `cargo clippy --workspace --all-features -- -D warnings` pass.
5. Add a `CHANGELOG.md` entry under `## [Unreleased]` (Keep a Changelog format — see the header of that file). The `changelog.yml` PR gate fails otherwise; label the PR `no-changelog` for changes with no user-visible impact (CI, docs, pure refactorings).

### Publishing to crates.io

All 10 crates share the workspace version and are published in dependency order. The release workflow's `crates-io` job does this automatically on every `v*` tag (real publish; dry-run under act rehearsal); locally:

```bash
python scripts/publish.py                    # dry-run rehearsal (default, no upload)
python scripts/publish.py --real --skip-root # real publish of the 9 library crates
python scripts/publish.py --real             # real publish incl. the root binary
```

`--skip-root` omits the root `issuerd` binary crate; `--from CRATE` resumes at a given library crate; crates already live on crates.io are skipped on retry. (CARGO_REGISTRY_TOKEN/CRATES_TOKEN or cargo login required for `--real`.)

The script stages a copy of the workspace for two reasons. First, `issuerd-core` carries a **git dependency** on the `flux-rs` shim (crates.io rejects git deps): the staged copy strips that dep and the `#[flux_rs::...]` attribute lines — the compiled code is identical (the shim expands to nothing under plain rustc). Second, staging copies the built web client (`webclientsrc/dist`) into `crates/issuerd-server/webclient-dist/` (a gitignored packaging artifact): `issuerd-server`'s `build.rs` resolves the web client from that crate-local directory first and falls back to `../../webclientsrc/dist` in the dev workspace, so a crates.io build of the packaged crate embeds the SPA and `cargo install issuerd` (release profile) does not hit the `DIST_MISSING` panic. Staging fails early if `webclientsrc/dist` is missing or empty — run `npm run build` in `webclientsrc/` first.

Dry-run fully rehearses every crate whose `issuerd-*` deps are already live on crates.io (packaged + verify-built); ahead of the first publish only `issuerd-core` can be rehearsed, because `cargo package`/`publish` strips path deps and re-resolves them against the registry — so `--real` publishes in order and, after each upload, polls the sparse index until the new version is actually visible (`--index-timeout`, default 600 s; the index lags the upload by a minute or more and the next crate's resolution 404s without it — a fixed sleep raced this and failed the v0.1.3 run), plus a fixed `--pause` (default 30 s) as new-crate rate-limit grace.

### Cutting a Release (GitHub + Docker Hub + crates.io)

`.github/workflows/release.yml` runs on every pushed `v*` tag:

1. **validate** — the tag (`v0.1.2`) must equal `[workspace.package] version` (`0.1.2`) and CHANGELOG.md must have a dated `## [0.1.2] - …` section; release notes are extracted from that section.
2. **heavy** — calls `heavy.yml` as a reusable workflow (`workflow_call`): the full heavy suites (federation, cluster E2E, Keycloak parity, OIDF conformance) run inside the release run against the exact tagged commit. The GitHub Release job waits for it; the Docker/crates.io publish jobs deliberately do not (isolation — the nightly heavy runs are the early warning, and crates.io uploads are irreversible either way).
3. **docker** (linux/amd64) — builds the canonical root Dockerfile and pushes `issuerd/issuerd:X.Y.Z-amd64` to Docker Hub. Needs repo secrets `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`; this job is isolated so a missing secret never blocks the GitHub Release.
4. **linux-binary** (amd64) — builds the same Dockerfile and extracts `/usr/local/bin/issuerd`, so the archive ships the exact binary the amd64 image ships. Runtime deps (documented in the release notes): glibc ≥ 2.35, OpenSSL 3, `libgssapi-krb5-2`.
5. **linux-arm64** — `scripts/cross-linux-arm64.sh` cross-compiles `aarch64-unknown-linux-gnu` on the x86_64 runner (ubuntu-22.04, dpkg multiarch sysroot from ports.ubuntu.com — no ARM runner, no QEMU build), smoke-runs the binary under `qemu-aarch64-static`, and packages the tarball. The same glibc 2.35 / OpenSSL 3.0 baseline as amd64 keeps the release-notes requirements identical.
6. **docker-arm64** — packs the exact cross-compiled binary (plus the arm64 Kerberos libs staged by the cross script) into the distroless runtime via `Dockerfile.prebuilt` — a COPY-only build, so no arm64 code executes anywhere — and pushes `issuerd/issuerd:X.Y.Z-arm64`.
7. **docker-manifest** — merges the two per-arch images into the user-facing multi-arch manifest list (`docker buildx imagetools create`): one tag, `:latest` / `:X.Y.Z` / `:X.Y`, serves both architectures (`docker pull` resolves the host arch). Per-arch tags keep no embedded SBOM/provenance attestations — attested pushes turn a tag into an OCI index, and indexes cannot be nested into the manifest list.
8. **crates-io** — builds the web client (publish staging embeds it), installs `libkrb5-dev` (the staged `issuerd-federation` verify-build compiles `libgssapi-sys`, whose build script needs the MIT Kerberos dev package), and runs `scripts/publish.py --real` (needs the `CARGO_REGISTRY_TOKEN` repo secret; isolated, resumable via `--from`).
9. **windows-binary** — `windows-latest` runner (Strawberry Perl for the vendored openssl build, web client first), self-contained zip.
10. **release** — needs the packaging jobs AND `heavy` green (skipped only under act); downloads only the `*-dist` + `release-notes` + `conformance-evidence` artifacts (never "all": docker/build-push-action auto-uploads `*.dockerbuild` build-record artifacts that download-artifact cannot fetch — suppressed at the source via `DOCKER_BUILD_RECORD_UPLOAD: false` on both docker jobs), renames the evidence tarball to `issuerd_X.Y.Z_conformance-evidence.tar.gz`, `SHA256SUMS.txt` (covers the evidence bundle too), build-provenance attestations, GitHub Release (`make_latest`).

Each archive (`issuerd_0.1.2_linux_amd64.tar.gz`, `issuerd_0.1.2_linux_arm64.tar.gz`, `issuerd_0.1.2_windows_amd64.zip`) contains the binary, LICENSE + NOTICE, README + CHANGELOG, `examples/` starter configs, and a CycloneDX SBOM (also attached standalone) — assembled by `scripts/package-release.sh`, which is the single source of truth for packaging (CI and local rehearsal both call it). The conformance evidence bundle is NOT part of any archive: like the standalone SBOMs, it is attached to the GitHub Release as one separate asset (`issuerd_X.Y.Z_conformance-evidence.tar.gz`).

**Release procedure:** bump `[workspace.package] version` (and the `issuerd-*` dependency pins in the same file) → rename `## [Unreleased]` to `## [X.Y.Z] - <date>` in CHANGELOG.md (fresh empty `Unreleased` above) → regenerate the OpenAPI spec (`cargo run --bin issuerd -- openapi -o webclientsrc/openapi.json` — `info.version` embeds the package version, so the committed spec goes stale on every bump and the `openapi-sync` CI job fails otherwise) → sync `Cargo.lock` (`cargo metadata --format-version 1 --quiet > /dev/null`) → commit → `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag push publishes everything: GitHub Release, the multi-arch Docker image, and the crates.io workspace. It also runs the full heavy suites (`heavy.yml` via `workflow_call`) — expect the run to take as long as the conformance suite (~1–2 h); the GitHub Release waits for them and attaches the packed conformance evidence, while the Docker/crates.io publishes proceed in parallel without waiting.

**Local rehearsal** (nothing is published; publish steps auto-skip under act via `env.ACT != 'true'`, the `heavy` reusable-workflow call is skipped via `vars.ACT` — job-level `if` has no `env` context on GitHub, so `.act/run-release.sh` passes `--var ACT=true` — and the `windows-binary` job, with no Windows containers under act, is rehearsed natively on a Windows host):

```bash
../.act/run-release.sh                 # act run: validate, docker amd64 build, linux amd64 + arm64
                                       # cross/packaging, arm64 image build, crates.io dry-run
../.act/rehearse-arm64.sh              # standalone arm64 path: cross-compile in an ubuntu:22.04
                                       # container (same script as CI) + tarball + arm64 image
../.act/rehearse-manifest.sh           # multi-arch manifest merge against a throwaway local
                                       # registry (the exact imagetools command CI runs)
# Windows packaging rehearsal (host): build the web client + release binary, then
bash scripts/package-release.sh windows 0.1.2 target/release/issuerd.exe /tmp/dist
```

### Key Files for Agents

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace members and shared dependencies |
| `ARCHITECTURE.md` | High-level design + module contracts + crate dependency graph (Mermaid) |
| `docs/README.md` | Operations documentation index (installation → troubleshooting) |
| `docs/CLUSTERING.md` | Multi-node deployment guide |
| `rig/research/specs-summary.md` | OIDC/OAuth2 spec clause mappings (local lab rig) |
| `docker-compose.yml` | Local demo stack (Issuerd + PostgreSQL + Redis, web consoles on :8080) |
| `docker-compose.integration.yml` | Integration test infrastructure |

---

### Web Client — Dynamic Enum Rule

The Issuerd admin SPA (`webclientsrc/`) **must be fully dynamic**: every dropdown, select box, and enum-driven label in the UI bootstraps its values from the backend at runtime.

**Principles:**
1. **Never hardcode enum values** in frontend source code (e.g., no `['openid-connect', 'saml']` arrays in components).
2. Use the **`useServerInfo()`** hook (`GET /admin/serverinfo`) to populate dropdown options. This returns all enum lists in one call.
3. Form **default values** (e.g., `ssl_required: 'external'`) are acceptable as JavaScript string literals, but the `<select>` options must still come from `serverInfo.ssl_required`.
4. If a dropdown value does not exist in `ServerInfoRepresentation`, the enum endpoint does not exist yet. **Add it to the backend first** (`issuerd-admin-api/src/enums.rs` → `dto.rs` → `routes.rs`), regenerate `webclientsrc/openapi.json`, regenerate the SDK, then wire it in the UI.
5. The canonical source for enum lists is the backend (`issuerd-admin-api/src/enums.rs` → `dto.rs` → `routes.rs`), exposed via `GET /admin/enums/*` and `GET /admin/serverinfo`.

**Description visibility rule:** `EnumValueRepresentation` returned by the backend includes a `description` field for every enum value. This **must be surfaced in the UI** — do not drop it. Suitable placements:
- **FormSelect dropdown items**: render `description` as a subtitle line under the primary label.
- **Native `<select>` `<option>` elements**: use the `title` attribute so the browser shows the description as a native tooltip on hover.
- **Badge / label tooltips**: when rendering enum values as read-only badges or table cells, use the description map to provide `title` tooltips or adjacent info icons.

**Why this matters:** The backend evolves rapidly (new federation providers, new algorithms, new event types). Hardcoding values in the frontend creates drift and forces coordinated deployments. Dynamic bootstrapping lets the backend add new values without touching the SPA. Descriptions are part of the API contract — they explain what each value means to the admin user and must not be silently discarded.

---

### Implemented Features

One-line as-built summaries of the major feature areas. Behavior divergences from Keycloak are documented in `tests/KEYCLOAK_DIFFS.md`; conformance evidence lives in `tests/conformance/README.md` + `tests/conformance/COVERAGE.md` (Config OP, Basic OP, Form Post OP — all 0 failures and 0 warnings, suite release-v5.2.4, hermetic pristine harness; raw run logs land in the gitignored `tests/conformance/results/`).

- **Core platform** — `issuerd-core` types/errors/models/traits; pure OIDC/OAuth2 parsing in `issuerd-protocol`; JWT issuance/validation, key rotation, introspection in `issuerd-token`; flow engine with pluggable authenticators and required actions in `issuerd-auth-flow`.
- **Storage** — `PostgresStorage` (sqlx), `InMemoryStorage`, `JsonFileStorage`, schema migrations under `crates/issuerd-storage/migrations/`.
- **Admin API** — reference-compatible REST API with OpenAPI generation, `realm-management` role authorization.
- **Distributed primitives** — `DistributedCache` (Redis + InMemory), CAS, pub/sub, node discovery, cache key schemas (`issuerd-cluster/src/keys.rs`).
- **Server & binary** — CLI (`daemon`/`provision`/`openapi`/`example`/`healthcheck`), figment config, middleware stack, OIDC endpoints, embedded same-origin SPA, TLS, graceful shutdown.
- **Integration testing** — `TestHarness` (`tests/harness/`), E2E suites under `tests/integration/`, dual-target runs vs Keycloak.
- **User federation** — LDAP/Kerberos providers, user sync, SPNEGO endpoint; Samba/OpenLDAP/MS-AD test rigs. **LDAP group sync** (Keycloak group-ldap-mapper style): when the IdP config carries `groupsDn` (plus optional `groupNameLdapAttribute`/`memberOfLdapAttribute`/`groupsInclude` allowlist), the `GroupMapper` extracts group CNs from user `memberOf` DNs under that subtree (RFC 4514 escape-aware) into `FederatedUser.groups: Option<Vec<String>>` — `None` means "provider does not report groups" and leaves memberships untouched, `Some` is authoritative. `UserSynchronizer` and first-login import reconcile via `issuerd_core::roles::reconcile_group_memberships_indexed` (case-insensitive `GroupIndex` shared per sync run; groups found/created with the `ldap_sync` marker attribute, pre-existing groups adopted, only marker-carrying memberships ever removed, find-or-create races fall back to the existing row, group role mappings never touched). Provision YAML groups accept `realm_roles`/`client_roles` (groups are applied after clients so client-role mappings resolve). **Password write-through**: with `editMode: WRITABLE`/`UNSYNCED` every password-set path (account change-password with directory-verified current password, `UPDATE_PASSWORD` required action, reset-credentials email flow, admin reset-password) writes the new password to the directory via `write_through_federated_password` (`issuerd-auth-flow/src/built_in.rs`) instead of a local credential and deletes stale local password credentials; `READONLY` fails with a 400-level error. ROPC (`grant_type=password`) and device verification (`auth/device-verify`) share the same account-authentication helpers (`verify_user_password` + `enforce_oob_second_factor` in `issuerd-server/src/routes/oidc.rs`): federated users are validated against the directory with browser-flow parity (rejection is final; provider error/dead link falls back to local), OTP-enrolled users must present a valid `totp` code (Keycloak direct-grant parity, replay watermark persisted), WebAuthn-only accounts are rejected (the ceremony cannot run out-of-band), and pending required actions reject both grants. `noTlsVerify: "true"` (insecure, lab only) skips TLS cert verification on `ldaps://`/StartTLS; AD `unicodePwd` writes still require LDAPS/StartTLS. Note Samba AD DC accepts the previous password for a grace period after a change.
- **Typestate auth boundaries** — `TypedAuthContext`, `TypedSession`, `TypedFlowResult`, realm-bound guards.
- **Truthful discovery & hardening** — exact capability advertisement, locked-down CORS, authorization-endpoint redirect safety; OIDC conformance suite green.
- **Multi-node clustering** — storage-backed shared signing keys, JWKS polling, atomic counters, `docker-compose.cluster.yml`, `docs/CLUSTERING.md`.
- **Email & account security** — `EmailSender`/SMTP with per-realm overrides, Outlook-compatible mail templates, required-action enforcement, password policy + history, per-realm brute force, attack-detection endpoints.
- **User self-service** — registration, reset-credentials action tokens, remember-me, SSO idle enforcement, account console mutations (profile, password, consents).
- **MFA** — TOTP end-to-end (RFC 6238, `issuerd-auth-flow/src/totp.rs`), conditional OTP in the browser flow, CONFIGURE_TOTP enrollment with QR; WebAuthn/passkey second factor (`issuerd-auth-flow/src/webauthn.rs`).
- **Passwordless email-code login** — `auth-email-code` browser authenticator (`issuerd-auth-flow/src/email_code.rs`) enabled per realm via the `email_code_login` attribute: the login page switches to email + "Send code", mails a 6-digit single-use code (localized template `email/login-code.*`, resend + attempt caps), and the SPA hides the password field based on the login-context `email_code_login` flag. In these realms the "no password credential ⇒ UPDATE_PASSWORD" auto-rule stays silent (explicit assignment still wins), and `UPDATE_PROFILE` keeps `email_verified` when the address is resubmitted unchanged.
- **Identity brokering** — `/broker/{alias}/login|endpoint`, external OIDC + social IdP presets, first-broker-login pages, account linking via action tokens, IdP mappers, `kc_idp_hint`.
- **Client scopes & protocol mappers** — scope model + 8 built-ins, 9 mapper types, claims assembly (`issuerd-server/src/claims.rs`), client roles in tokens, composite roles, admin + SPA surfaces.
- **Consent, logout channels, theming, i18n** — consent screen with stored-grant coverage, back/front-channel logout, real `id_token_hint` validation, `[themes] dir` + login CSS contract, realm i18n (login + email localization).
- **Admin API depth** — editable flows/executions, credentials CRUD, execute-actions-email, impersonation, groups children/members/move, role composites, events config, key rotation/disable, partial import/export, `not_before`, client adapter-config download (`clients/{id}/installation/providers/{provider_id}`: `keycloak-oidc-keycloak-json` + `generic-oidc-json`, providers listed in serverinfo `client_installations`; SPA "Download Config" dialog on the client edit page).
- **Advanced OAuth** — PAR (RFC 9126); JWT client auth (`private_key_jwt`/`client_secret_jwt`); token exchange + impersonation (RFC 8693; opt-in strict audience policy via the realm attribute `require_requester_in_subject_aud` with a same-named requesting-client override — the requester must then appear in the subject token's `aud`, default off); offline tokens; per-realm signing algorithms (ES512 via `p521`; server default EdDSA for new deployments — a fresh boot persists an active EdDSA + RS256 key pair so discovery advertises the OIDC Core §15.1 mandatory RS256 — with RS256 remaining an explicit per-realm compatibility choice); DPoP (RFC 9449; mTLS deferred; optional server-provided single-use nonces via `[dpop.nonce] mode = "supported" | "required"` with `DPoP-Nonce` headers + `use_dpop_nonce` challenges, default `disabled`); JAR + JARM + form_post; RAR (RFC 9396); dynamic client registration (RFC 7591/7592); CIBA (poll mode, `ext/ciba/auth` + `ext/ciba/approve`, DPoP-bound step-up tokens); pairwise subjects (OIDC Core §8). Agent-facing guides with recorded demos: `docs/agentic-iam-mcp.md`, `docs/ciba-step-up.md`.

*Features are documented here as implemented capabilities, not phases. Keep this file in sync with any changes to build commands, crate structure, testing strategy, frontend conventions, or development workflow.*
