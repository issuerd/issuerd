#!/usr/bin/env bash
# Run the Dylint log-hygiene lints (lints/issuerd_log_hygiene) against the
# workspace. The lint library builds with its own pinned nightly
# (lints/issuerd_log_hygiene/rust-toolchain.toml); cargo-dylint builds the
# matching driver into ~/.dylint_drivers on first use.
#
# Prereqs:
#   cargo install --locked cargo-dylint dylint-link
set -euo pipefail
cd "$(dirname "$0")/.."

exec cargo dylint --all -- "$@"
