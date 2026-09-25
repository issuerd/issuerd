#!/usr/bin/env bash
# Package an issuerd release archive for one platform.
#
#   scripts/package-release.sh <linux|linux-arm64|windows> <version> <binary-path> <out-dir>
#
# Produces in <out-dir>:
#   issuerd_<version>_<platform>.tar.gz   (linux → linux_amd64, linux-arm64 → linux_arm64)
#   issuerd_<version>_<platform>.zip      (windows → windows_amd64)
#   issuerd_<version>_<platform>.sbom.cyclonedx.json
#
# Archive contents: the binary, LICENSE, NOTICE, README.md, CHANGELOG.md,
# example configs under examples/, and the SBOM (also shipped standalone).
#
# Used by .github/workflows/release.yml and by the local release rehearsal
# (.act/run-release.sh), so both produce byte-comparable packaging.
set -euo pipefail

OS="${1:?usage: package-release.sh <linux|linux-arm64|windows> <version> <binary-path> <out-dir>}"
VERSION="${2:?missing version (e.g. 0.1.1)}"
BINARY="${3:?missing path to the built issuerd binary}"
OUT_DIR="${4:?missing output directory}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$OS" in
  linux)       BIN_NAME=issuerd;     ARCHIVE_EXT=tar.gz; PLATFORM=linux_amd64 ;;
  linux-arm64) BIN_NAME=issuerd;     ARCHIVE_EXT=tar.gz; PLATFORM=linux_arm64 ;;
  windows)     BIN_NAME=issuerd.exe; ARCHIVE_EXT=zip;    PLATFORM=windows_amd64 ;;
  *) echo "error: unknown OS '$OS' (linux|linux-arm64|windows)" >&2; exit 2 ;;
esac
[ -f "$BINARY" ] || { echo "error: binary not found: $BINARY" >&2; exit 2; }

BASE="issuerd_${VERSION}_${PLATFORM}"
STAGE="$OUT_DIR/$BASE"
rm -rf "$STAGE"
mkdir -p "$STAGE/examples"

cp "$BINARY" "$STAGE/$BIN_NAME"
chmod +x "$STAGE/$BIN_NAME"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$STAGE/"
cp "$ROOT/examples/issuerd.example.toml" "$ROOT/examples/provision.example.yaml" "$STAGE/examples/"

# CycloneDX SBOM from the compiled binary (cargo-auditable embeds the Rust
# dependency tree, so a binary-only scan still sees every crate).
SBOM="$OUT_DIR/$BASE.sbom.cyclonedx.json"
if command -v syft >/dev/null 2>&1; then
  syft "$BINARY" -o "cyclonedx-json=$SBOM"
  cp "$SBOM" "$STAGE/sbom.cyclonedx.json"
else
  echo "warning: syft not on PATH — archive will contain no SBOM" >&2
fi

ARCHIVE="$OUT_DIR/$BASE.$ARCHIVE_EXT"
rm -f "$ARCHIVE"
if [ "$ARCHIVE_EXT" = tar.gz ]; then
  tar -C "$OUT_DIR" -czf "$ARCHIVE" "$BASE"
elif tar --version 2>/dev/null | grep -qi bsdtar; then
  # bsdtar infers zip from the suffix (GitHub runner system tar).
  tar -C "$OUT_DIR" -a -cf "$ARCHIVE" "$BASE"
elif command -v zip >/dev/null 2>&1; then
  (cd "$OUT_DIR" && zip -qr "$BASE.zip" "$BASE")
else
  # GNU tar (Git Bash) cannot write zip — fall back to PowerShell.
  powershell.exe -NoProfile -Command \
    "Compress-Archive -Path '$(cygpath -w "$STAGE")' -DestinationPath '$(cygpath -w "$ARCHIVE")' -CompressionLevel Optimal"
fi

rm -rf "$STAGE"
cd "$OUT_DIR"
FILES=("$BASE.$ARCHIVE_EXT")
[ -f "$BASE.sbom.cyclonedx.json" ] && FILES+=("$BASE.sbom.cyclonedx.json")
sha256sum "${FILES[@]}"
echo "packaged: $ARCHIVE"
