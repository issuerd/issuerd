#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
EXAMPLE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
COMPOSE=(docker compose -f "$EXAMPLE_DIR/docker-compose.yml")

cleanup() {
  status=$?
  trap - EXIT INT TERM
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${COMPOSE[@]}" up --build -d postgres redis issuerd setup
timeout 300 "${COMPOSE[@]}" wait setup
setup_id=$("${COMPOSE[@]}" ps -a -q setup)
if [[ -z "$setup_id" ]]; then
  echo "Compose setup container is missing" >&2
  exit 1
fi
setup_exit=$(docker inspect --format '{{.State.ExitCode}}' "$setup_id")
"${COMPOSE[@]}" logs setup
if [[ "$setup_exit" != "0" ]]; then
  echo "Compose setup failed with exit code $setup_exit" >&2
  exit 1
fi

timeout 180 "${COMPOSE[@]}" run --rm --no-deps client
