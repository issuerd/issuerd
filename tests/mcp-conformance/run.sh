#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
HARNESS="$SCRIPT_DIR/conformance"
RESULTS="$SCRIPT_DIR/results"
mkdir -p "$RESULTS"

if [[ ! -d "$HARNESS/src" ]]; then
  git clone https://github.com/modelcontextprotocol/conformance.git "$HARNESS"
fi
git -C "$HARNESS" checkout --detach c37eec8
cp "$SCRIPT_DIR/upstream-package-lock.json" "$HARNESS/package-lock.json"

daemon_pid=""
proxy_pid=""
authorization_pid=""
scenario_pid=""
cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "$scenario_pid" "$authorization_pid" "$proxy_pid" "$daemon_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$scenario_pid" "$authorization_pid" "$proxy_pid" "$daemon_pid"; do
    if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
  done
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$HARNESS"
npm ci
npm run build
cd "$SCRIPT_DIR"
npm ci
npx playwright install chromium
cd "$ROOT/examples/mcp-admin/client"
npm ci
npm run build
cd "$ROOT"

cargo run --bin issuerd -- daemon -c tests/mcp-conformance/issuerd.conformance.toml >"$RESULTS/issuerd.log" 2>&1 &
daemon_pid=$!
for attempt in {1..120}; do
  if curl -fsS http://127.0.0.1:18089/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:18089/ready >/dev/null
ISSUERD_BASE_URL=http://127.0.0.1:18089 node examples/mcp-admin/client/dist/src/setup.js >"$RESULTS/setup.json"

export ISSUERD_BASE_URL=http://127.0.0.1:18089/realms/mcp-demo
export MCP_RESOURCE=http://127.0.0.1:18092/realms/mcp-demo/mcp
export ACCESS_TOKEN="$(node tests/mcp-conformance/mint-token.mjs)"
node tests/mcp-conformance/auth-proxy.mjs >"$RESULTS/proxy.log" 2>&1 &
proxy_pid=$!
export ISSUERD_ISSUER=http://127.0.0.1:18092/realms/mcp-demo
for attempt in {1..60}; do
  if curl -fsS "$ISSUERD_ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$ISSUERD_ISSUER/.well-known/openid-configuration" >/dev/null

node --test tests/mcp-conformance/authorization-lifecycle.test.mjs

CONFORMANCE_BIN="$HARNESS/dist/index.js" CONFORMANCE_RESULTS="$RESULTS/authorization" \
  node tests/mcp-conformance/authorization.mjs &
authorization_pid=$!
wait "$authorization_pid"
authorization_pid=""

for scenario in \
  server-initialize \
  tools-list \
  resources-list \
  completion-complete \
  dns-rebinding-protection; do
  "$HARNESS/dist/index.js" server \
    --url "$ISSUERD_ISSUER/mcp" \
    --scenario "$scenario" \
    -o "$RESULTS/$scenario" &
  scenario_pid=$!
  wait "$scenario_pid"
  scenario_pid=""
done
