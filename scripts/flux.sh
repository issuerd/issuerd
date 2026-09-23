#!/usr/bin/env bash
# Run Flux refinement-type checking. Flux checks only crates that opt in via
# `[package.metadata.flux] enabled = true` (currently crates/issuerd-core, whose
# `SecondsNonZero` carries the reference annotations).
#
# Note: a bare full-crate `cargo flux` currently ICEs on ordinary iterator
# chains (upstream flux-rs/flux#1666, projections.rs:382, plus infer.rs:484),
# so CI (verification.yml) checks only the annotated defs:
#   ./scripts/flux.sh check -p issuerd-core --only-check="def:models::SecondsNonZero"
#
# Flux runs on Linux/macOS only — on Windows use WSL. Prereqs:
#   curl -fsSL https://raw.githubusercontent.com/flux-rs/flux/main/install.sh | bash
# (installs z3 + liquid-fixpoint + the flux/cargo-flux binaries into
# ~/.cargo/bin; needs the nightly toolchain pinned by flux's rust-toolchain.toml,
# which rustup installs automatically)
set -euo pipefail
cd "$(dirname "$0")/.."

exec cargo flux "$@"
