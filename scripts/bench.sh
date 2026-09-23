#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Running benchmarks..."
cargo bench --workspace

echo ""
echo "Benchmarks complete. Results in target/criterion/"
