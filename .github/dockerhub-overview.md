# issuerd/issuerd

Fast, Keycloak-compatible IAM with DPoP and CIBA — OpenID Certified OIDC/OAuth2 in Rust, shipped as a single distroless binary and horizontally scalable.

OpenID Certified across 11 OP profiles: 10 on v0.1.17 plus RP-Initiated Logout on v0.1.19. These version-specific entries do not certify v0.2.x. Every release ships fresh self-hosted conformance evidence. The realm-scoped MCP server exposes 71 curated tools with exact-operation approval for strict actions.

## Public demo

Explore [demo.issuerd.org](https://demo.issuerd.org): admin and account consoles, OIDC/OAuth2 flows, federation, DPoP, CIBA, and MCP administration with a read-only observer or an operator using exact-operation approval. The hosted playground contains synthetic data only, is best-effort, and may be reset. Do not enter real passwords or sensitive data.

## Quickstart

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/issuerd.toml:/etc/issuerd/issuerd.toml:ro" \
  issuerd/issuerd:latest
```

The image expects a config at `/etc/issuerd/issuerd.toml` — print a fully-commented example with:

```bash
docker run --rm issuerd/issuerd:latest example server-config
```

For a ready-made demo (PostgreSQL + Redis + seeded realm, admin console on `http://localhost:8080/admin/console`, admin/admin) use the compose stack from the GitHub repo — `docker compose up`, no build tools needed.

## Tags

- `latest` — newest stable release (multi-arch: linux/amd64 + linux/arm64)
- `X.Y.Z`, `X.Y` — pinned release lines, same multi-arch manifest
- `X.Y.Z-amd64` / `X.Y.Z-arm64` — per-architecture tags for explicit pinning

Healthchecks: the distroless image ships no shell/curl — use the binary itself: `issuerd healthcheck --url http://localhost:8080`.

## Links

- Public demo: https://demo.issuerd.org
- GitHub (source, issues, conformance evidence bundles): https://github.com/issuerd/issuerd
- Documentation: https://issuerd.org (deployment, clustering, federation, security)
- License: Apache-2.0
