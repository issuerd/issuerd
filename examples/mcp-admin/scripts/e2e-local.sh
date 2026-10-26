#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
EXAMPLE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
ROOT=$(cd -- "$EXAMPLE_DIR/../.." && pwd)
CLIENT="$EXAMPLE_DIR/client"
RUNTIME="$EXAMPLE_DIR/.runtime"
BASE_URL="http://127.0.0.1:18089"
ISSUER="$BASE_URL/realms/mcp-demo"
DAEMON_PID=""

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$RUNTIME"
cargo build --bin issuerd --manifest-path "$ROOT/Cargo.toml"
npm ci --prefix "$CLIENT"
npm run build --prefix "$CLIENT"

"$ROOT/target/debug/issuerd" daemon -c "$EXAMPLE_DIR/issuerd.mcp-admin.toml" \
  >"$RUNTIME/daemon.log" 2>&1 &
DAEMON_PID=$!

ready=0
for _ in {1..120}; do
  if node -e 'fetch(process.argv[1]).then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))' \
    "$BASE_URL/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "Issuerd exited before readiness; see $RUNTIME/daemon.log" >&2
    exit 1
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "Issuerd did not become ready within 120 seconds" >&2
  exit 1
fi

export ISSUERD_BASE_URL="$BASE_URL"
export REALM="mcp-demo"
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
export MCP_CLIENT_ID="mcp-admin-native"
export MCP_USERNAME="mcp-admin"
export MCP_PASSWORD="${MCP_PASSWORD:-Password123!}"

node "$CLIENT/dist/src/setup.js" | tee "$RUNTIME/setup.json"
node "$CLIENT/dist/src/cli.js" \
  --issuer "$ISSUER" \
  --client-id "$MCP_CLIENT_ID" \
  --username "$MCP_USERNAME" \
  --mode script \
  --era auto | tee "$RUNTIME/acceptance.json"

node -e '
const fs = require("node:fs");
const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (!report.ok || report.eras.length !== 2) process.exit(1);
for (const era of report.eras) {
  if (era.tools.length !== 5 || Object.keys(era.calls).length !== 5) process.exit(1);
}
console.log(JSON.stringify({ok: true, evidence: process.argv[1], eras: report.eras.map(era => era.negotiatedEra)}));
' "$RUNTIME/acceptance.json"
