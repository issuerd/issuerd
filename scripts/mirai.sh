#!/usr/bin/env bash
# Run MIRAI (abstract interpretation / panic linting) over the pure crates.
#
# MIRAI runs on Linux/macOS only — on Windows use WSL. Prereqs:
#   sudo apt-get install -y cmake clang
#   git clone https://github.com/endorlabs/MIRAI.git
#   cd MIRAI && cargo install --locked --path ./checker
# (the checker repo's rust-toolchain.toml pins the matching nightly; rustup
# installs it automatically)
#
# MIRAI_FLAGS tunes the strictness:
#   default  = fewest false positives (CI default)
#   verify   = also report potential false positives
#   library  = require explicit preconditions
#   paranoid = flag every possible issue
set -euo pipefail
cd "$(dirname "$0")/.."

export MIRAI_FLAGS="${MIRAI_FLAGS:---diag=default}"
exec cargo mirai -p issuerd-protocol -p issuerd-core "$@"
