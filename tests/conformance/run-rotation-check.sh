#!/usr/bin/env bash
# Standalone evidence run for oidcc-server-rotate-keys (the Dynamic plan's
# manual-step module — the pristine runner force-starts it without rotating,
# so in-plan it is listed as an expected failure). This script drives the
# module through the suite's REST API and interposes a REAL key rotation via
# the issuerd admin API between the module's configure (JWKS snapshot) and
# start (JWKS re-fetch + new/old kid validation).
#
# Usage: ./run-rotation-check.sh
# Starts the infrastructure (without the full conformance-run) if needed,
# bootstraps, then runs the rotation check inside the network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

echo "=== Running the rotation check ==="
compose exec -T test-runner python3 /harness-scripts/rotate-check.py
echo "Rotation evidence OK"
