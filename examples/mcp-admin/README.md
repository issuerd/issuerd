# External MCP acceptance clients

These are external TypeScript acceptance clients for the Issuerd MCP endpoint.
They use exactly `@modelcontextprotocol/client` **2.4.0**. There is no
LLM/provider integration, VS Code configuration, pre-minted token path, or
first-party DPoP cryptography.

The public native client uses authorization code + PKCE S256,
`token_endpoint_auth_method=none`, scope `openid mcp:read`, and the exact
canonical `{issuer}/mcp` resource at authorization and token redemption. The
confidential client adds `client_secret_basic`, `mcp:write`, ordinary writes,
resource reads, operation-bound CIBA, and exact-result reconciliation. Each
profile's `OAuthClientProvider.dpop()` returns one SDK `DpopSession`; the SDK
creates non-extractable ES256 keys and handles token proofs, per-request
`htm`/`htu`/`ath`/`jti`, and nonce retry. Registration, discovery, PKCE, state,
and tokens are keyed by the validated issuer in memory. Nothing is persisted
and no token, proof, key, cookie, secret, or Authorization header is printed.

## Prerequisites

- Node.js 24.17.0 and npm 11.13.0 (the lockfile is committed).
- For the local daemon run: the Rust toolchain required by the repository.
- For the optional Compose run: Docker with Compose v2.

All passwords and client secrets below are disposable **lab-only defaults**, not
private tokens. `ADMIN_PASSWORD=admin` provisions the master administrator;
`MCP_PASSWORD=Password123!` is used for demo users; `MCP_CLIENT_SECRET=
mcp-step-up-secret` is the confidential fixture secret. Override them through
the environment for another lab. Do not reuse any value elsewhere. The CLI never
reads a `.env` file.

## npm checks

```bash
cd examples/mcp-admin/client
npm ci
npm run build
npm run typecheck
npm test
```

The unit suite covers exact RFC 9207 issuer and state validation on success and
error callbacks, redirect validation and the native loopback-port exception,
and issuer separation for registration/discovery/PKCE/state/token storage.

## Real local acceptance run

From the repository root:

```bash
./examples/mcp-admin/scripts/e2e-local.sh
```

The finite script builds the daemon and client, starts Issuerd on
`127.0.0.1:18089` with in-memory storage, waits for `/ready`, runs idempotent
setup, runs the real CLI, and kills the daemon through an EXIT/INT/TERM trap.
`issuerd.mcp-admin.toml` enables MCP and required nonces but does not set
`require_dpop`, so the production default `require_dpop=true` remains in force.
Logs and JSON evidence are written to the ignored `.runtime/` directory.

Setup uses the setup-only admin token to create:

- realm `mcp-demo`;
- enabled public native `mcp-admin-native` with optional `mcp:read` and the
  registered redirect `http://127.0.0.1:8080/callback`;
- confidential native `mcp-admin-confidential` with `client_secret_basic`, the
  same redirect, and optional `mcp:read`, `mcp:write`, and `mcp:step_up`;
- `mcp-admin` with `view-realm`, `view-users`, `manage-users`, and `view-clients`
  (`manage-users` is required for attack detection, ordinary user writes, and
  strict user deletion);
- additional user `mcp-observer`, disposable deletion target
  `mcp-step-up-target`, and client `mcp-reporting` fixtures;
- group `mcp-acceptance` with `mcp-observer` as a member, realm roles used by
  role list/get acceptance, and `mcp-acceptance-idp` with a lab-only credential
  that acceptance proves is omitted from MCP output.

The actual redirect uses an ephemeral `127.0.0.1` listener port. The server must
accept it through the native loopback-port exception; all other redirect
components stay exact. Scripted login performs the authorize GET, preserves its
flow cookie, and form-POSTs to `/api/v1/auth/login`. It never uses the password
grant for the MCP token. The resulting real 303 callback supplies `code`,
`state`, and `iss`. A separate `prompt=none` request produces and validates a
real `login_required` error callback.

Expected `acceptance.json` evidence:

- public native code + PKCE S256 and `DPoP` token type;
- exact canonical resource on every token request and public auth method
  `none` on each request;
- token and resource proof counts, DPoP scheme counts, and nonce
  challenge/retry counts (successful requests have the server-enforced proof
  claims; the client does not decode or print them);
- RFC 9207 issuer/state/redirect matches for both success and error responses;
- a legacy `initialize` + `notifications/initialized` connection and, in
  `auto`, SDK auto-negotiation of modern `server/discover`;
- all 23 tools in both eras, with IDs for user, client, group, role, and IdP
  detail calls discovered from the corresponding search/list results;
- SDK `AjvJsonSchemaValidator` checks, exact structured/text mirror checks,
  and 25 modern wire results with `resultType:"complete"` in the pristine
  rig, plus any additional paginated lookup results needed in populated realms
  (the SDK itself strips this discriminator from its neutral result objects).

Expected `step-up-acceptance.json` evidence:

- confidential code + PKCE S256 and `client_secret_basic` profile metadata;
- three redacted resource reads and a completed ordinary `users_update`;
- an exact `users_delete` operation ID, fresh authentication and CSRF evidence,
  single-purpose DPoP scope, no refresh token, and a bounded expiry;
- rejected unrelated-tool and changed-argument calls;
- one completed deletion with an identical exact-replay result, and
  `invalid_grant` when the consumed CIBA request is polled again.

The report contains no token, proof, cookie, CSRF value, client secret, or
approval identifier. User and operation IDs are non-secret fixture metadata.

## Interactive CLI

Start the daemon in one terminal:

```bash
cargo run --bin issuerd -- daemon -c examples/mcp-admin/issuerd.mcp-admin.toml
```

In another terminal:

```bash
cd examples/mcp-admin/client
npm ci && npm run build
ISSUERD_BASE_URL=http://127.0.0.1:18089 node dist/src/setup.js
ISSUERD_ISSUER=http://127.0.0.1:18089/realms/mcp-demo \
  node dist/src/cli.js --mode interactive --era auto
```

A JSON `authorization_required` event on stderr contains the browser URL. The
callback listener is HTTP on `127.0.0.1` with an ephemeral port. `--era legacy`
and `--era modern` select one era; default `--era auto` runs both.

The confidential profile uses scripted fresh logins for reproducible lab
approval. Run it after the same setup:

```bash
ISSUERD_ISSUER=http://127.0.0.1:18089/realms/mcp-demo \
  node dist/src/step-up.js
```

## PostgreSQL + Redis Compose rig

From the repository root:

```bash
./examples/mcp-admin/scripts/e2e-compose.sh
```

The finite runner builds Issuerd from this branch, starts PostgreSQL and Redis
with healthchecks, provisions only the master realm, waits for and checks the
one-shot idempotent setup, then runs both one-shot clients with
`docker compose run --rm --no-deps`. Its exit code is the runner result; an
EXIT/INT/TERM trap removes the project and volumes. Do not use
`--exit-code-from client` here: it implies `--abort-on-container-exit`, which
would stop the stack when the successful setup one-shot finishes. The Compose
project is `issuerd-mcp-admin`.

Setup and clients share `network_mode: service:issuerd`. This lets the official
SDK use its plain-HTTP loopback exception at `127.0.0.1:8080`; endpoint/TLS
validation is not disabled and DPoP `htu` keeps the same canonical spelling as
the configured issuer. The daemon is also published on host loopback port
18090 for inspection, but that host-mapped port is not the issuer used by the
containerized acceptance flow.

`issuerd.compose.toml` likewise enables required nonces and leaves
`require_dpop` at its default `true`. Redis uses `noeviction` for replay,
revocation, and flow state. The example-only `[mcp.step_up]` gate is enabled;
production defaults remain unchanged.

## Three-node exact-operation rig

```bash
./examples/mcp-admin/scripts/e2e-step-up-cluster.sh
```

This separate Compose project starts three Issuerd nodes with cluster mode,
PostgreSQL, Redis, and an nginx gateway. Every node uses the same canonical
`http://127.0.0.1:8080` issuer and shared signing keys. A test-only routing
header selects the upstream without changing the URL, Host, resource indicator,
or DPoP proof target; the gateway's response header proves the selected node.

The confidential client requires initial issuance on node 1, fresh approval on
node 2, CIBA polling on node 3, and exact execution/replay on node 1. It also
verifies consumed-request replay on node 3. Evidence is written to
`.runtime/cluster-step-up-acceptance.json`. The runner removes its containers,
network, and volumes on exit and dumps node/gateway logs on failure.
