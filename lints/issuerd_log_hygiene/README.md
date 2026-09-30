# issuerd_log_hygiene

Dylint lint library enforcing the Issuerd tracing log-hygiene policy
(AGENTS.md, "Logging Conventions"). Four syntax-only lints in one
pre-expansion early pass — no name resolution, no `clippy_utils`; the pinned
nightly (`rust-toolchain.toml`) is the only API dependency. All four lints are
deny-by-default (they gate CI).

| Lint | Rule |
|------|------|
| `tracing_error_debug` | `error`/`err` fields must use the `%` (Display) sigil, not `?` (Debug) — any level. |
| `secret_field_in_log` | No secret-named field (`password`, `secret`, `token`, `code`, `cookie`, `totp`, `dpop`, ...; exact or `<name>_*` prefix) in any event or in `#[instrument(fields(...))]`. The `_hash`/`_len`/`_count`/`_type`/`_id` suffixes are exempt (`token_type` is legal). |
| `session_id_in_log` | `session_id`/`sid` fields only at DEBUG/TRACE; never in span fields. |
| `instrument_skip_sensitive` | Every sensitive parameter of an `#[instrument]` function (`state`, `headers`, `body`, `body_bytes`, `params`, `query`, `ip`, `client_ip`, `peer_ip`, `*_token`, `*_secret`, `*_password`, `*_code`, `*_assertion`, `*_key` — except `*_pub_key`/`*public_key`) must be in `skip(...)`/`skip_all`. |

Event macros are recognized by the last path segment (`trace!`/`debug!`/
`info!`/`warn!`/`error!` — the workspace logs exclusively through `tracing`),
the attribute by the last segment `instrument`. A false positive is silenced
with a scoped `#[allow(issuerd_log_hygiene::<lint>)]` — treat that as a code
smell and prefer fixing the call site (or the lint).

## Running

```bash
# From the workspace root (discovers lints/ via [workspace.metadata.dylint]):
./scripts/dylint.sh --workspace        # i.e. cargo dylint --all -- --workspace

# The library's own ui tests (compiletest fixtures in ui/):
cd lints/issuerd_log_hygiene && cargo test
```

Prereqs: `cargo install --locked cargo-dylint dylint-link`. cargo-dylint
builds the matching driver into `~/.dylint_drivers` on first use.

The ui-test `.stderr` fixtures are updated by hand: run `cargo test`, then
copy each `Actual stderr saved to /tmp/<name>.stage-id.stderr` over
`ui/<name>.stderr` (dylint_testing's compiletest has no bless flag wired up).

## Updating the pinned toolchain

The lint library and the workspace check both run under the toolchain pinned
in `rust-toolchain.toml`; bumping it means:

1. Install the new dated nightly with `cargo`, `rustc-dev`, `rust-src`,
   `llvm-tools-preview`, and update `channel` in `rust-toolchain.toml`.
2. `cargo test` here (rustc-internal APIs drift; fix compile errors, refresh
   the ui fixtures) and `scripts/dylint.sh --workspace` from the root.
3. Update the `rustup toolchain install` line in the `dylint` job of
   `.github/workflows/verification.yml`.

**Constraint:** the pin must be a nightly that still accepts the unstable
`--env-set` flag — dylint's driver passes it unconditionally when a library
is loaded (trailofbits/dylint#2010), and rustc removed the flag in
rust-lang/rust#161831 (merged 2026-08-31), so nightlies from ~2026-09-01
onward fail every lint run with `error: Unrecognized option: 'env-set'`
(upstream: trailofbits/dylint#2078). `nightly-2026-08-20` is the toolchain
dylint 6.1.0's own template and examples pin. Re-check upstream before
bumping past 2026-08-31.
