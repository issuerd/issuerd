# Read-only MCP server

Issuerd exposes a realm-scoped Model Context Protocol (MCP) server for external
agent-native administration. The current increment is deliberately read-only:
23 curated tools, no built-in chat, no LLM provider, and no token passthrough
to another API.

## Enable and configure

The surface is disabled by default. Enable it only after provisioning an agent
client and reviewing the DPoP profile on every cluster node:

```toml
[mcp]
enabled = true
require_dpop = true
invocation_rate_limit_per_minute = 60
allowed_origins = []

[mcp.step_up]
enabled = false
```

- `enabled` mounts `POST /realms/{realm}/mcp` and the protected-resource
  metadata routes. A disabled endpoint returns the same 404 as an unknown one.
- `require_dpop=true` is the secure default. `false` is an explicit Bearer
  compatibility choice for clients such as `rmcp` or MCP Inspector; it is not
  an automatic fallback and will not relax strict operation-bound approval in
  a later write increment.
- `invocation_rate_limit_per_minute` is a distributed fixed-window limit per
  realm, authorizing client (`azp`), and internal user. Zero rejects every
  invocation rather than disabling the limit. Excess returns 429 with
  `Retry-After`; limiter storage failure returns 503.
- `allowed_origins` contains exact HTTP(S) origins. Empty rejects every present
  `Origin` but permits non-browser requests without that header. Default ports
  are normalized; credentials, paths, queries, fragments, wildcards, and
  `Origin: null` are rejected.
- `[mcp.step_up]` is a separate rollout gate for future operation-bound writes.
  It does not enable generic CIBA resource issuance or a scope-only approval
  flow. Keep it false for the read-only increment.

Host validation uses the configured `issuer_url` authority. An omitted Host
port is interpreted using the issuer's scheme and must match the configured
port; omitted non-default ports are rejected. Default-port authorities and
valid case-insensitive `Content-Type` or repeated `Accept` representations are
canonicalized before `rmcp` dispatch. Host, Origin, and media checks run before
request-body and OAuth processing, so late SDK rejection cannot consume a proof
or invocation allowance.

## Tools and authorization

| Tool | Required scope | Accepted realm roles (any one) | Result |
|---|---|---|---|
| `realm_get` | `mcp:read` | `view-realm`, `manage-realm` | Curated realm configuration |
| `users_search` | `mcp:read` | `view-users`, `manage-users` | Exact username, exact email, or substring search |
| `users_get` | `mcp:read` | `view-users`, `manage-users` | User by canonical internal UUID, direct realm roles and groups |
| `users_get_groups` | `mcp:read` | `view-users`, `manage-users` | Curated direct group memberships |
| `users_get_role_mappings` | `mcp:read` | `view-users`, `manage-users` | Direct, available, and effective realm/client role mappings |
| `users_get_sessions` | `mcp:read` | `view-users`, `manage-users` | Active sessions with curated Admin fields |
| `users_get_credentials` | `mcp:read` | `view-users`, `manage-users` | Scalar credential metadata without payloads |
| `attack_detection_status` | `mcp:read` | `manage-users` | Aggregated login failures and lockout state |
| `clients_list` | `mcp:read` | `view-clients`, `manage-clients` | Paginated clients or exact public `clientId` |
| `clients_get` | `mcp:read` | `view-clients`, `manage-clients` | Client by internal UUID, without secret configuration |
| `groups_list` | `mcp:read` | `view-realm`, `manage-realm` | Paginated group IDs, names, paths, and parent IDs |
| `groups_get` | `mcp:read` | `view-realm`, `manage-realm` | Group by canonical internal UUID, without attributes |
| `groups_members` | `mcp:read` | `view-users`, `manage-users` | Paginated curated members of an existing group |
| `roles_list` | `mcp:read` | `view-realm`, `manage-realm` | Paginated realm roles, excluding client roles before pagination |
| `roles_get` | `mcp:read` | `view-realm`, `manage-realm` | Role by name with Admin lookup precedence and container metadata |
| `serverinfo_get` | `mcp:read` | `view-realm`, `manage-realm` | Dynamic server capabilities and enum metadata |
| `events_search` | `mcp:read` | `view-realm`, `manage-realm` | Filtered user/admin events with retention clamps and totals |
| `sessions_list` | `mcp:read` | `view-realm`, `manage-realm` | Paginated realm sessions and total count |
| `keys_list` | `mcp:read` | `view-realm`, `manage-realm` | Public signing-key metadata only |
| `client_scopes_list` | `mcp:read` | `view-clients`, `manage-clients` | Scopes with safe mapper and claim-target summaries |
| `idp_list` | `mcp:read` | `view-realm`, `manage-realm` | Identity providers with sensitive configuration omitted |
| `idp_get` | `mcp:read` | `view-realm`, `manage-realm` | Identity provider by alias with sensitive configuration omitted |
| `flows_list` | `mcp:read` | `view-realm`, `manage-realm` | Flows and stages without authenticator configuration |

Assign `mcp:read` explicitly as an **optional** client scope. It is not implied
by `mcp:write` or `mcp:step_up`, and it is not accepted as a default scope or
through anonymous dynamic registration. MCP does not require the Admin API's
`admin_api_access` client attribute, but the user's corresponding realm roles
are still mandatory.

`tools/list` is filtered by the caller's actual scope and roles; every
`tools/call` repeats the same checks. Unknown and under-authorized well-formed
calls also consume invocation allowance. A no-`id` `tools/call` notification is
rejected as malformed before authentication and consumes no allowance. Exact
filters take precedence over pagination. Defaults are `first=0`, `max=20`, with
`max <= 100` and bounded input strings. Malformed user, client, or group UUID
input is an input error, not a storage failure. Role names are required and
bounded. Unknown groups and users are not found rather than empty detail pages.
Every user-detail read validates and canonicalizes its internal user UUID and
requires an existing user. Session reads retain the Admin API's bounded
100-record page. Role mappings separate direct assignments from available and
effective roles; effective roles include group inheritance and composite
expansion. `groups_list` retains storage name ordering across pages. Member
pagination is validated before group lookup, and `roles_list` uses bounded
on-demand storage batches rather than unconditionally loading the complete role
catalog.

Outputs use curated DTOs rather than raw storage models. Arbitrary realm,
user, client, group, and role attribute maps, client secrets, raw credential
material, `secretData`/`credentialData` payloads, SMTP passwords, pairwise
sector keys, and protocol-mapper configuration are not returned. Credential
metadata contains only id, type, optional label, creation time, priority, and
the derived temporary flag. Session output omits redirect/state and other
client-session internals. Directory text can still contain indirect prompt
injection: output redaction is not a substitute for least privilege and
external-client approval UX.

## Resource-specific token profile

The endpoint accepts only interactive, same-realm authorization-code/refresh
tokens with all of the following:

1. a valid, unrevoked token with a live persisted user session;
2. an enabled internal user and an enabled client named by `azp`;
3. an issuer realm identical to the target realm (no master/cross-realm
   widening and no UUID alias);
4. the exact canonical resource `{issuer_url}/realms/{realm}/mcp` both in the
   trusted access-token `resource` claim and in at least one `aud` entry.

The trusted claim distinguishes the RFC 8707 grant from an Audience mapper
that merely adds the same string to `aud`. Older tokens without it, tokens
from direct-access-token response types, password/client-credentials grants,
and marker-client audiences are not MCP onboarding workarounds. Cross-realm
administration and unattended M2M require separate policy work.

MCP resource authorization requests, including SPNEGO entry points, use
`response_type=code` and PKCE S256 for both public and confidential clients.
Wildcard redirects are rejected. Exact matching is required except for the
native loopback-port exception on `127.0.0.1` and `[::1]`; `localhost` is not
that exception. At code redemption `redirect_uri` may be omitted, but is
compared exactly when present. Introducing an allowlisted resource only at
redemption still requires the code to carry a valid S256 challenge. The stored
code redirect is revalidated under the same MCP profile for introduced,
inherited, and legacy resource grants, so a resource-less wildcard flow cannot
be upgraded at redemption.

Refresh tokens carry the granted resource and may only restate it or omit it
to inherit; they cannot widen it. The refresh-derived access token receives
the same resource provenance.

## DPoP and Bearer compatibility

With `require_dpop=true`, use `Authorization: DPoP <token>` and exactly one
valid proof on every POST. The proof is checked for:

- the token's `cnf.jkt` key binding and the access-token hash (`ath`);
- `htm=POST` and the canonical MCP `htu` or an RFC 3986-equivalent form (for
  example an explicit default port or normalized unreserved percent encoding;
  query, fragment, userinfo, backslash, control/whitespace, and UUID aliases
  are rejected);
- signature algorithm, `iat`, and single-use `jti` in the distributed replay
  cache;
- the server nonce when nonce mode is enabled.

Duplicate proof headers, replays, wrong keys/HTU/ATH, DPoP-bound tokens sent as
Bearer, and unbound tokens sent with the DPoP scheme are rejected. Nonce
validation happens before atomic nonce consumption, so an invalid signature
cannot burn another request's nonce. `supported` nonce mode is treated as
`required` at MCP; `disabled` remains disabled. Post-proof success and error
responses carry the fresh nonce when applicable and are uncacheable. If a
mandatory fresh nonce cannot be generated or persisted during a challenge or
after proof validation, the request returns 503 before preflight or tool
execution instead of succeeding without one.

With `require_dpop=false`, genuinely unbound Bearer tokens are accepted for
read-only interoperability. Both downgrade directions still fail. Strict
future operation-bound approval will always require DPoP regardless of this
compatibility setting.

## Discovery and challenge behavior

Protected-resource metadata is available at:

```text
GET /.well-known/oauth-protected-resource/{issuer-path}/realms/{realm}/mcp
```

The bare `/.well-known/oauth-protected-resource` route is an explicit master
alias, not origin metadata. The document advertises only `mcp:read` as the
minimal basic scope, the actual DPoP requirement and algorithms, and
`bearer_methods_supported=["header"]` only in explicit compatibility mode.

Initial discovery returns 401 without an OAuth error body. Strict mode sends a
DPoP challenge with `resource_metadata`, `algs`, and `scope="mcp:read"`;
compatibility appends separate Bearer and DPoP challenges. Actual scope misses
return 403 `insufficient_scope` with the exact operation scopes. Missing realm
roles return a plain 403. Invalid tokens/proofs use their distinct
`invalid_token`, `invalid_dpop_proof`, and `use_dpop_nonce` challenges.

## MCP transport

The endpoint is stateless Streamable HTTP over `http` 1.x/Tower. There is no
MCP protocol session, cluster affinity, `Mcp-Session-Id`, or `Last-Event-ID`
resumption. GET and DELETE return 405. Bodies are limited to 4 MiB and
recursive duplicate JSON keys are rejected before authentication.

| Revision | Lifecycle and result behavior |
|---|---|
| `2025-06-18`, `2025-11-25` | `initialize` + `notifications/initialized`; legacy results omit modern cache/result discriminators |
| `2026-07-28` | `server/discover`, required request `_meta` and routing headers, `resultType:"complete"`, private zero-TTL list/discovery hints |

Exactly those three versions are supported on non-initialize paths. Legacy
initialize retains specification version negotiation; stateless operation does
not add a cross-request initialized-session store. Modern missing required
`_meta` returns HTTP 400 `-32602`; header/body mismatches return `-32020`;
unsupported versions return `-32022`; unknown modern methods return HTTP 404
`-32601`. `listChanged` is not advertised.

Successful tool calls include structured output matching the advertised
`outputSchema` and a serialized JSON text mirror. Input, not-found, downstream,
and business failures use `isError:true`; unknown tools and malformed JSON-RPC
messages are protocol errors. JSON responses are used for terminal results;
the test matrix also covers SSE from an SSE-configured service.

## External TypeScript client and rigs

`examples/mcp-admin/` contains the pinned official TypeScript SDK 2.4.0 client
and two finite acceptance rigs. The public native client uses pre-registration,
PKCE S256, exact resource indicators, non-extractable ES256 keys from one SDK
`DpopSession`, and no client secret. It checks RFC 9207 `iss` and `state` on
successful and error authorization responses and never prints tokens, proofs,
keys, cookies, or Authorization headers.

```bash
cd examples/mcp-admin/client
npm ci
npm run build
npm run typecheck
npm test
```

Run the real in-memory daemon scenario from the repository root:

```bash
./examples/mcp-admin/scripts/e2e-local.sh
```

Run the branch-built daemon with PostgreSQL and Redis:

```bash
./examples/mcp-admin/scripts/e2e-compose.sh
```

Both scripts complete authorization-code issuance and all 23 tools in legacy
and modern modes. The Compose script removes its own project and volumes on
exit. See [`examples/mcp-admin/README.md`](../examples/mcp-admin/README.md) for
interactive commands, lab-only credentials, and the evidence schema.

The nightly `heavy.yml` workflow runs the same npm checks and both rigs.
Ordinary `cargo test` does not require npm.

## Other clients and current limits

`rmcp` 3.7 is used for Rust legacy/modern and explicit Bearer interoperability
checks. MCP Inspector 2.12 may be useful for Bearer-only debugging, but is not
DPoP or step-up evidence. VS Code configuration is intentionally absent until
its complete DPoP flow can be verified.

Current boundaries:

- no writes, account-self-service family, resources/prompts, cross-realm master
  operations, unattended M2M, or built-in chat;
- no generic CIBA `resource` or `operation_id` acceptance and no ordinary
  `mcp:step_up` issuance;
- no secret rotation, raw credentials, TOTP seeds/QR codes, bulk export,
  impersonation, or audit deletion;
- strict operation-bound approval, when implemented, will use a fresh
  server-rendered ceremony, a single-purpose token without refresh, and a
  durable exact-operation grant — not a reusable CIBA scope token.

## Verification

The relevant local gates are:

```bash
cargo test --test integration mcp::
cargo test -p issuerd-mcp
cargo test -p issuerd-server routes::mcp::tests
```

The full increment additionally passes the workspace Rust gates and the npm
and real-client runs above. Test evidence is not a claim of FAPI, PSD2/RTS, or
OIDF MCP certification.
