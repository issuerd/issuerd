# Examples

Starter configs and runnable demos. Everything here is optional material for
evaluating Issuerd; nothing in this directory is required to build or run the
server.

## Runnable examples

| Directory | What it is |
|---|---|
| [agentic-mcp/](agentic-mcp/) | **Agentic IAM demo, end to end**: a support-chat agent whose MCP tool calls carry RFC 8693-exchanged, DPoP-bound tokens, with CIBA human step-up for refunds and PostgreSQL RLS at the data layer. `docker compose up -d`, then http://localhost:5108 (alice / changeme). See [agentic-mcp/README.md](agentic-mcp/README.md). |

## Configuration files

| File | Purpose |
|---|---|
| `issuerd.example.toml` | Fully commented server configuration reference. Regenerate with `cargo run --bin issuerd -- example config`. |
| `provision.example.yaml` | Fully populated provisioning reference (realm, roles, groups, clients, users, IdP, flows). Regenerate with `cargo run --bin issuerd -- example provision-config`. |
| `issuerd.demo.toml` + `provision.demo.yaml` | Server config and realm content for the **root demo stack** (`docker compose up` in the repository root): master (admin/admin) + myrealm (alice/changeme), console clients, sample clients. |
| `issuerd.agent-test.toml` | Minimal local daemon config used by agent-driven/manual test runs (plain HTTP on port 18080, in-memory storage). |
| `provision.federation.yaml` | Provisioning for the **federation test environment** (Samba AD DC / OpenLDAP / Kerberos against the integration compose stack). See `docs/user-federation.md`. |
