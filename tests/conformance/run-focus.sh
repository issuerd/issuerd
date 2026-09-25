#!/usr/bin/env bash
# Runs a single module of the Basic OP plan against the hermetic stack.
# Usage: ./run-focus.sh [module-name]   (default: oidcc-prompt-none-logged-in)
# Starts the infrastructure (without the full conformance-run) if needed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="${1:-oidcc-prompt-none-logged-in}"
RESULTS_DIR="$SCRIPT_DIR/results"

mkdir -p "$RESULTS_DIR"

compose() {
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" "$@"
}

if [[ -z "$(compose ps -q test-runner 2>/dev/null)" ]]; then
    echo "=== Stack not running; starting infrastructure ==="
    compose up -d --wait bind9 mongodb pki-init conformance-server issuerd-op test-runner
    compose exec -T test-runner env \
        ISSUERD_URL="https://op.conformance.test:8443" \
        ISSUERD_CACERT="/pki/ca.crt" \
        bash /usr/local/bin/issuerd-bootstrap
else
    echo "=== Stack already running ==="
fi

echo "=== Running focused module: $MODULE ==="
compose exec -T test-runner mkdir -p /results/export-json
# NB: focused runs use the empty expected-skips file — the upstream runner
# treats expected-skips entries for modules that did not run as an error.
compose exec -T test-runner python3 /upstream-scripts/run-test-plan.py \
  --expected-failures-file /conformance-suite-configs/issuerd-expected-failures.json \
  --expected-skips-file /conformance-suite-configs/issuerd-expected-skips-config.json \
  --export-dir /results/export-json \
  "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]:$MODULE" \
  /conformance-suite-configs/issuerd-basic-op.json \
  2>&1 | tee "$RESULTS_DIR/focus-output.log"

echo "Results in $RESULTS_DIR"
