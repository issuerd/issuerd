#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Keycloak Rust Setup Script <=="
echo ""

# Check Rust toolchain
echo "Checking Rust toolchain..."
rustup show active-toolchain || { echo "Rust not installed. Install via https://rustup.rs"; exit 1; }

# Install useful tools
echo "Installing dev tools..."
cargo install cargo-nextest 2>/dev/null || true
cargo install cargo-deny 2>/dev/null || true
cargo install cargo-audit 2>/dev/null || true
cargo install cargo-depgraph 2>/dev/null || true

# Build workspace
echo "Building workspace..."
cargo build --workspace

# Run tests
echo "Running tests..."
cargo test --workspace

# Run linting
echo "Running clippy..."
cargo clippy --workspace --all-features -- -D warnings

echo ""
echo "Setup complete!"
