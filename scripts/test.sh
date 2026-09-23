#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-all}"

case "$MODE" in
  unit)
    echo "Running unit tests only..."
    cargo test --workspace --lib
    ;;
  integration)
    echo "Running integration tests..."
    cargo test --test integration
    ;;
  ignored)
    echo "Running ignored tests (benchmarks + spec conformance stubs)..."
    cargo test --test integration -- --ignored
    ;;
  all)
    echo "Running all tests..."
    cargo test --workspace -- --include-ignored
    ;;
  fmt)
    echo "Checking formatting..."
    cargo fmt --all -- --check
    ;;
  clippy)
    echo "Running clippy..."
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    ;;
  doc)
    echo "Building docs..."
    cargo doc --workspace --no-deps
    ;;
  deny)
    echo "Running cargo-deny..."
    cargo deny check
    ;;
  audit)
    echo "Running cargo-audit..."
    cargo audit
    ;;
  geiger)
    echo "Running cargo-geiger (unsafe code report)..."
    cargo geiger --all-features
    ;;
  *)
    echo "Usage: $0 [unit|integration|ignored|all|fmt|clippy|doc|deny|audit|geiger]"
    exit 1
    ;;
esac
