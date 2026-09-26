# issuerd/issuerd

Fast, Keycloak-compatible Identity & Access Management in Rust — conformance-tested OIDC/OAuth2 (Basic OP, Form Post OP, Config OP, 0 failures and 0 warnings), DPoP and CIBA out of the box, shipped as a single distroless binary, horizontally scalable.

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

- GitHub (source, issues, conformance evidence bundles): https://github.com/issuerd/issuerd
- Documentation: https://issuerd.org (deployment, clustering, federation, security)
- License: Apache-2.0
