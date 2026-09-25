#!/usr/bin/env bash
# Cross-build the issuerd release binary for linux/arm64 (aarch64-unknown-linux-gnu)
# on an x86_64 Ubuntu host — no ARM hardware and no QEMU required.
#
#   scripts/cross-linux-arm64.sh <out-dir>
#
# Produces in <out-dir>:
#   issuerd                                  the aarch64 release binary
#   rootfs/usr/lib/aarch64-linux-gnu/…       the Kerberos/GSS-API shared libs the
#                                            binary links (for Dockerfile.prebuilt)
#
# The same script runs in the release workflow (ubuntu-22.04 runner), under
# act, and in a local Ubuntu 22.04 container (.act/rehearse-arm64.sh), so the
# arm64 artifact is reproducible everywhere. ubuntu-22.04 gives glibc 2.35 /
# OpenSSL 3.0 — the same baseline as the canonical amd64 Docker build.
#
# Idempotent: safe to re-run in a persistent container/VM (installs are skipped
# when already present).
set -euo pipefail

OUT_DIR="$(mkdir -p "${1:?usage: cross-linux-arm64.sh <out-dir>}" && cd "$1" && pwd)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=aarch64-unknown-linux-gnu
TRIPLET=aarch64-linux-gnu
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.95.0}"   # pinned, same as the canonical Dockerfile
NODE_VERSION="${NODE_VERSION:-24.17.0}"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO=sudo

# --- 1. Embedded web client (release build panics without webclientsrc/dist) --
if [ ! -d "$ROOT/webclientsrc/dist" ] || [ -z "$(ls -A "$ROOT/webclientsrc/dist" 2>/dev/null)" ]; then
  if ! command -v node >/dev/null 2>&1; then
    echo "== installing Node.js v$NODE_VERSION (none on PATH)"
    curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.gz" \
      | $SUDO tar -xz -C /opt
    export PATH="/opt/node-v$NODE_VERSION-linux-x64/bin:$PATH"
  fi
  node --version
  (cd "$ROOT/webclientsrc" && npm ci && npm run generate-api && npm run build)
else
  echo "== webclientsrc/dist already built — skipping web client"
fi

# --- 2. arm64 sysroot via dpkg multiarch --------------------------------------
# Ubuntu's default mirrors (archive.ubuntu.com / azure) carry amd64 only; arm64
# packages live on ports.ubuntu.com. Restrict the existing sources to amd64 and
# add ports for arm64 — apt-get update fails for the foreign arch otherwise.
if ! dpkg --print-foreign-architectures | grep -qx arm64; then
  echo "== enabling arm64 multiarch"
  $SUDO dpkg --add-architecture arm64
fi
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  # deb822 format (Ubuntu 24.04+)
  if ! grep -q '^Architectures:' /etc/apt/sources.list.d/ubuntu.sources; then
    $SUDO sed -i 's/^URIs:/Architectures: amd64\nURIs:/' /etc/apt/sources.list.d/ubuntu.sources
  fi
  if [ ! -f /etc/apt/sources.list.d/arm64-ports.sources ]; then
    echo "== adding ports.ubuntu.com arm64 sources (deb822)"
    printf 'Types: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports/\nSuites: %s %s-updates %s-security\nComponents: main restricted universe multiverse\nArchitectures: arm64\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n' \
      "$CODENAME" "$CODENAME" "$CODENAME" | $SUDO tee /etc/apt/sources.list.d/arm64-ports.sources >/dev/null
  fi
else
  # legacy one-line format (Ubuntu 22.04)
  if ! grep -q 'arch=amd64' /etc/apt/sources.list; then
    $SUDO sed -i -E 's/^deb (http)/deb [arch=amd64] \1/' /etc/apt/sources.list
    for f in /etc/apt/sources.list.d/*.list; do
      [ -f "$f" ] && ! grep -q 'arch=' "$f" && $SUDO sed -i -E 's/^deb (http)/deb [arch=amd64] \1/' "$f"
    done
  fi
  if [ ! -f /etc/apt/sources.list.d/arm64-ports.list ]; then
    echo "== adding ports.ubuntu.com arm64 sources"
    for suite in "$CODENAME" "$CODENAME-updates" "$CODENAME-security"; do
      echo "deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports $suite main restricted universe multiverse"
    done | $SUDO tee /etc/apt/sources.list.d/arm64-ports.list >/dev/null
  fi
fi
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
  "gcc-$TRIPLET" "g++-$TRIPLET" pkg-config clang libclang-dev file \
  libssl-dev:arm64 libkrb5-dev:arm64

# --- 3. Rust target ------------------------------------------------------------
if ! rustup target list --installed --toolchain "$RUST_TOOLCHAIN" 2>/dev/null | grep -qx "$TARGET"; then
  echo "== installing rust target $TARGET (toolchain $RUST_TOOLCHAIN)"
  rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
  rustup target add "$TARGET" --toolchain "$RUST_TOOLCHAIN"
fi
if ! command -v cargo-auditable >/dev/null 2>&1; then
  echo "== installing cargo-auditable"
  cargo "+$RUST_TOOLCHAIN" install cargo-auditable --locked
fi

# --- 4. Cross-build -------------------------------------------------------------
# libgssapi-sys ignores its pkg-config probe when HOST != TARGET and falls back
# to a flat library search that cannot see Debian's multiarch dirs
# (/usr/lib/aarch64-linux-gnu), so force the MIT implementation and hand it a
# staging prefix with the expected <prefix>/{include,lib} layout.
GSSAPI_PREFIX=/opt/gssapi-arm64
$SUDO mkdir -p "$GSSAPI_PREFIX/lib"
$SUDO ln -sfn /usr/include "$GSSAPI_PREFIX/include"
$SUDO ln -sf /usr/lib/$TRIPLET/libgssapi_krb5.so* "$GSSAPI_PREFIX/lib/"
export LIBGSSAPI_IMPL=mit
export LIBGSSAPI_PREFIX=$GSSAPI_PREFIX

# Same as the canonical image: cargo-auditable embeds the dependency tree so
# SBOM scanners see every crate in a binary-only scan.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$TRIPLET-gcc"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH="/usr/lib/$TRIPLET/pkgconfig"
echo "== building issuerd for $TARGET"
(cd "$ROOT" && cargo "+$RUST_TOOLCHAIN" auditable build --locked --release --bin issuerd --target "$TARGET")

# --- 5. Collect the binary + its Kerberos runtime libs ---------------------------
BINARY="$ROOT/target/$TARGET/release/issuerd"
[ -f "$BINARY" ] || BINARY="${CARGO_TARGET_DIR:-/nonexistent}/$TARGET/release/issuerd"
file "$BINARY" | grep -q 'ELF 64-bit.*aarch64' || { echo "error: $BINARY is not an aarch64 ELF" >&2; exit 1; }

mkdir -p "$OUT_DIR/rootfs/usr/lib/$TRIPLET"
cp "$BINARY" "$OUT_DIR/issuerd"
# The same krb5 chain the canonical Dockerfile copies from its builder stage,
# here from the arm64 sysroot. distroless/cc supplies glibc + libssl3 + ca-certs.
for lib in libgssapi_krb5.so.2 libkrb5.so.3 libk5crypto.so.3 libcom_err.so.2 libkrb5support.so.0 libkeyutils.so.1; do
  cp -L "/usr/lib/$TRIPLET/$lib"* "$OUT_DIR/rootfs/usr/lib/$TRIPLET/"
done

# Smoke-run only when an aarch64 emulator is around (GitHub runners install
# qemu-user-static in the workflow; local hosts without ARM support skip this).
# No -L sysroot needed: multiarch libc6:arm64 puts the loader at the standard
# /lib/ld-linux-aarch64.so.1 path.
QEMU="$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)"
if [ -n "$QEMU" ]; then
  "$QEMU" "$OUT_DIR/issuerd" --version
else
  echo "== qemu-aarch64 not available — skipping arm64 smoke-run (binary verified as aarch64 ELF)"
fi

echo "== arm64 build staged in $OUT_DIR"
ls -l "$OUT_DIR/issuerd" "$OUT_DIR/rootfs/usr/lib/$TRIPLET/"
