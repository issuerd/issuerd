#!/usr/bin/env bash
# Run Kani model checking on the pure protocol crate (proof harnesses are the
# `#[cfg(kani)]` module in crates/issuerd-protocol/src/pkce.rs).
#
# Kani runs on Linux/macOS only — on Windows use WSL. Prereqs:
#   cargo install --locked kani-verifier
#   cargo kani setup        # downloads the Kani toolchain into ~/.kani
set -euo pipefail
cd "$(dirname "$0")/.."

# The unoptimized verification model exceeds the CI runner's memory budget.
# Optimize the model without disabling assertions, memory checks, or unwinding.
export CARGO_PROFILE_DEV_OPT_LEVEL="${CARGO_PROFILE_DEV_OPT_LEVEL:-3}"

exec cargo kani -p issuerd-protocol "$@"
