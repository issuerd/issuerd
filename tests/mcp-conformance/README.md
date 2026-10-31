# MCP conformance investigation and selected CI rig

This directory evaluates the official
[`modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance)
harness against Issuerd. It is an additional engineering signal, not an OIDF or
OIDF-MCP certification claim. The complete 2025-11-25 and 2026-07-28 requirement
sets are not being claimed.

## Selected strategy

Use two lanes against the real Issuerd daemon:

1. **Authorization server:** run all three `authorization` scenarios directly:
   metadata, authorization-code grant, and DPoP. The harness supports a static
   client, PKCE, an exact RFC 8707 resource, and DPoP. Playwright automates only
   the interactive login.
2. **Core MCP server:** run a small initial scenario allowlist through a local
   streaming Bearer-injection proxy. The official `server` runner has no static
   token option, while Issuerd requires an exact-resource token. The proxy adds
   that token but preserves request bodies, response streams, methods, and the
   `Host` header. It does not disable token, resource, audience, or Origin
   validation on the daemon.

The daemon listens on `127.0.0.1:18089`. The proxy listens on `127.0.0.1:18092`
and is also the externally configured issuer URL. A real authorization-code +
PKCE flow mints the proxy token for
`http://127.0.0.1:18092/realms/mcp-demo/mcp`. The earlier
`/api/v1/auth/admin-token` fixture is unsuitable because it does not carry that
exact resource claim.

No container is required for this first rig. The existing CI Rust/Node
toolchains run the finite `run.sh` script, which starts and cleans up the daemon
and proxy. This avoids Docker-in-Docker and browser-callback complexity. A
future hermetic Compose variant can place the same three processes on one
network without publishing ports.

The test-only TOML uses Bearer compatibility for the core lane and an exact
loopback Origin allowlist for DNS-rebinding coverage. Production defaults and
strict DPoP behavior are unchanged. The authorization lane independently proves
DPoP token binding.

## Initial CI scenario set

| Scenario | Probe result |
|----------|--------------|
| `authorization-server-metadata-endpoint` | 1 passed; CIMD warning because Client ID Metadata Documents are not implemented |
| `authorization-code-grant` | 1 passed, 0 failed |
| `dpop` | 3 passed, 0 failed |
| `server-initialize` | 2 passed, 0 failed |
| `tools-list` | 3 passed, 0 failed |
| `resources-list` | 2 passed, 0 failed |
| `completion-complete` | 2 passed, 0 failed |
| `dns-rebinding-protection` | 2 passed, 0 failed |

These are explicit selected scenarios, not a frozen requirement-set pass rate.
Do not add a broad expected-failures baseline to turn them into a conformance
claim.

## Findings outside the initial gate

- `server-stateless` passed 20/25 checks. Three checks need the diagnostic tools
  `test_missing_capability`, `test_streaming_elicitation`, and
  `test_logging_tool`; one additional check is a prompts-capability mismatch.
- `resources-read-text` requires a `test://static-text` fixture, not an Issuerd
  realm resource.
- Other tool/resource scenarios require specialized everything-server fixtures,
  prompts, subscriptions, or streaming capabilities that are deliberately not in
  the current product scope.

The initial CI gate therefore covers initialization, tool and resource listing,
completion, Host/Origin protection, metadata, authorization-code + PKCE, and
DPoP. Existing Issuerd suites remain responsible for strict operation-bound
CIBA, role policy, secret redaction, and multi-node transaction behavior.
Expanding this set should be driven by real product capabilities, not by adding
production-only fixture tools merely to raise a score.

## Run locally

The official clone is ignored by git. Pin its commit and install the harness:

```bash
git clone https://github.com/modelcontextprotocol/conformance.git \
  tests/mcp-conformance/conformance
cd tests/mcp-conformance/conformance
git checkout c37eec8
npm ci
npm run build
cd ../..
```

Then run the finite rig from the repository root:

```bash
./tests/mcp-conformance/run.sh
```

The script clones the pinned harness if it is missing, installs the reviewed
`upstream-package-lock.json` override (production dependency audit clean),
builds the official harness and Issuerd clients, provisions the realm, starts
the daemon and proxy, runs all selected scenarios, and cleans up both processes. Results go to ignored `tests/mcp-conformance/results/` and local
logs to `.runtime/`. Tokens and proxy authorization headers are never written to
tracked files or printed by the proxy. The pinned browser dependency is
`playwright` 1.63.0, installed by `npm ci` in this directory.

## CI integration point

Add `./tests/mcp-conformance/run.sh` to the existing heavy workflow after the
current MCP acceptance rigs. Keep it independent of the OIDC conformance matrix
and do not introduce an expected-failures baseline or an OIDF-MCP certification
claim. The cloned harness and its commit, the scenario allowlist, and generated
evidence should remain reviewable.
