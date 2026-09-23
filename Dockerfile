# Canonical production image for Issuerd.
#
# Multi-stage build:
#   1. builder — Node (embedded admin SPA) + Rust release binary
#   2. runtime — Google distroless (glibc + libssl3 + ca-certs, no shell, no
#      package manager, non-root) plus the handful of shared libs the binary
#      actually links (see ldd notes in stage 2)
#
# The default builder image (Microsoft Playwright image, which bundles Node)
# is chosen so the build also works in networks where Docker Hub is restricted.
# Both stages are overridable:
#
#   docker build --build-arg BUILDER_IMAGE=mcr.microsoft.com/playwright:v1.59.1-jammy \
#                --build-arg RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot \
#                -t issuerd:local .
#
# (RUNTIME_IMAGE must be a glibc distroless variant; pick the `:nonroot` tag —
# it carries the non-root user this image runs as.)
#
# The web client is embedded at compile time (include_dir! in issuerd-server), so the
# runtime image contains only the binary plus its shared-library dependencies.

ARG BUILDER_IMAGE=mcr.microsoft.com/playwright:v1.59.1-jammy
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot

# -----------------------------------------------------------------------------
# Stage 1: build environment (Node + Rust).
# -----------------------------------------------------------------------------
FROM ${BUILDER_IMAGE} AS builder

ENV DEBIAN_FRONTEND=noninteractive

# System build dependencies (libkrb5 for the Kerberos federation provider,
# libclang for bindgen) and the pinned Rust toolchain. sqlx is a pure-Rust
# PostgreSQL driver — no libpq needed at build time or runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential libssl-dev pkg-config \
        libkrb5-dev libclang-dev clang \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain 1.95.0 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Workspace manifests and source.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY src/ ./src/
COPY build.rs ./

# Build the embedded web client first — the release build embeds
# webclientsrc/dist via include_dir!. The SDK under webclientsrc/generated is
# gitignored and excluded via .dockerignore, so it is always regenerated here
# from the committed openapi.json (never reuse the developer's local copy).
COPY webclientsrc/ ./webclientsrc/
RUN cd webclientsrc && npm ci && npm run generate-api && npm run build

# Release binary. cargo-auditable embeds the Cargo dependency tree into the
# binary so SBOM scanners (syft) can see the Rust crates in image-only scans.
RUN cargo install cargo-auditable --locked \
    && cargo auditable build --bin issuerd --release --locked

# -----------------------------------------------------------------------------
# Stage 2: minimal runtime image (distroless).
# -----------------------------------------------------------------------------
# `ldd` on the release binary shows it links only libc/libm/libgcc_s,
# OpenSSL 3 (WebAuthn) and the Kerberos GSS-API chain (LDAP federation).
# distroless/cc covers glibc + libssl3 + ca-certificates; the krb5 chain is
# copied from the builder. Version compatibility: the builder (Ubuntu 22.04)
# has glibc 2.35 / OpenSSL 3.0 and distroless debian13 has glibc 2.41 /
# OpenSSL 3.5 — symbol-versioned and forward compatible.
FROM ${RUNTIME_IMAGE} AS runtime

COPY --from=builder /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkrb5.so.3* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libk5crypto.so.3* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcom_err.so.2* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkrb5support.so.0* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkeyutils.so.1* /usr/lib/x86_64-linux-gnu/

COPY --from=builder /build/target/release/issuerd /usr/local/bin/issuerd

# The :nonroot distroless tag already runs as uid 65532 (no useradd exists
# in distroless — there is no shell or package manager by design).
EXPOSE 8080

ENTRYPOINT ["issuerd"]
CMD ["daemon", "-c", "/etc/issuerd/issuerd.toml"]
