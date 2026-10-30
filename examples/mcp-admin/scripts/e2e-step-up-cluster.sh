#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
EXAMPLE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME="$EXAMPLE_DIR/.runtime"
COMPOSE=(docker compose -f "$EXAMPLE_DIR/docker-compose.step-up.yml")
EVIDENCE="$RUNTIME/cluster-step-up-acceptance.json"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" != "0" ]]; then
    "${COMPOSE[@]}" logs --tail=100 issuerd-1 issuerd-2 issuerd-3 gateway >&2 || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$RUNTIME"
"${COMPOSE[@]}" up --build -d postgres redis issuerd-1 issuerd-2 issuerd-3 gateway setup
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

timeout 180 "${COMPOSE[@]}" run --rm --no-deps step-up-client | tee "$EVIDENCE"
node -e '
const fs = require("node:fs");
const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!report.ok || report.resources.length !== 3 || !report.strict.replayReconciled) process.exit(1);
const nodes = report.multiNode;
if (nodes.initial !== "1" || nodes.approval !== "2" || nodes.poll !== "3" || nodes.execution !== "1" || nodes.cibaReplay !== "3") process.exit(1);
console.log(JSON.stringify({ok: true, evidence: process.argv[1], multiNode: nodes, execution: report.strict.execution}));
' "$EVIDENCE"
