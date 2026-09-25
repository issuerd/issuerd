#!/usr/bin/env bash
# One-command conformance run with exit-code propagation (CI-friendly):
# builds missing images, starts the stack, streams the conformance-run
# logs, waits for it to finish, tears everything down, exits with its code.
#
# For interactive use prefer plain:  docker compose up
# (from tests/conformance/; results land in tests/conformance/results/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$SCRIPT_DIR/conformance-suite/scripts" ]]; then
    echo "ERROR: conformance suite sources not found at tests/conformance/conformance-suite"
    echo "Clone them first (currently validated against release-v5.2.4):"
    echo "  git clone https://gitlab.com/openid/conformance-suite.git tests/conformance/conformance-suite"
    echo "  cd tests/conformance/conformance-suite && git checkout release-v5.2.4"
    exit 1
fi

cd "$SCRIPT_DIR"
mkdir -p results pki

# The runner containers write to the bind-mounted ./pki and ./results as the
# host user (compose user: ${DOCKER_HOST_UID:-1000}:${DOCKER_HOST_GID:-1000}).
# On Linux the bind mount preserves host ownership, so pass the real ids —
# the GitHub Actions runner is 1001, and any local user past the first one is
# not 1000 either. Docker Desktop (Windows/macOS) maps ownership permissively;
# there the 1000 default is the value that works.
if [[ "$(uname -s)" == "Linux" ]]; then
    export DOCKER_HOST_UID="${DOCKER_HOST_UID:-$(id -u)}"
    export DOCKER_HOST_GID="${DOCKER_HOST_GID:-$(id -g)}"
fi

cleanup() {
    local code=$?
    # On failure, dump the stack logs before teardown — one-shot services
    # (pki-init, bootstrap) leave no other trace once the containers are gone.
    if [[ $code -ne 0 ]]; then
        echo "=== docker compose logs (tail, exit $code) ==="
        docker compose logs --no-color --tail 300 2>/dev/null || true
    fi
    docker compose down --volumes 2>/dev/null || true
}
trap cleanup EXIT

docker compose up -d --wait --build

# Stream the one-shot run's logs until it exits, then propagate its code.
docker compose logs --follow conformance-run &
LOGS_PID=$!
EXIT_CODE=$(docker wait issuerd-conformance-run)
wait "$LOGS_PID" 2>/dev/null || true

echo "conformance-run exited with code $EXIT_CODE"
exit "$EXIT_CODE"
