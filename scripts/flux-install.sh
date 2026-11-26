#!/usr/bin/env bash
# Vendored installer for the CI "cargo flux" job (verification.yml).
#
# Adapted from flux-rs/flux install.sh @ 9fe62fab (upstream file SHA-256
# 40331a9b530926347005ffd55c72dd723f126d20c405aed8303e94040eb32809), with one
# deliberate change: upstream resolves the *latest* Z3 release through the
# anonymous api.github.com endpoint at install time, which intermittently
# returns 403 (rate limit) on shared CI runners. Here the Z3 release is pinned
# and downloaded by direct release-asset URL — no GitHub API, no auth, no
# rate-limit surface. Bump Z3_TAG deliberately after checking the asset names
# of the new release (they carry glibc/os version suffixes).
set -euo pipefail
BIN="$HOME/.cargo/bin"; mkdir -p "$BIN"

Z3_TAG="z3-5.3.3"
Z3_VERSION="5.3.3"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) Z3_ASSET="x64-glibc-2.39"; FP=fixpoint-x86_64-linux-gnu.tar.gz ;;
  Darwin-arm64) Z3_ASSET="arm64-osx-13.3"; FP=fixpoint-aarch64-apple-darwin.tar.gz ;;
  *) echo "no prebuilt z3+fixpoint for this platform" >&2; exit 1 ;;
esac

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# z3 (pinned release, direct asset URL — never touches api.github.com)
curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
  "https://github.com/Z3Prover/z3/releases/download/${Z3_TAG}/${Z3_TAG}-${Z3_ASSET}.zip" \
  -o "$tmp/z3.zip"
unzip -qo "$tmp/z3.zip" -d "$tmp"
install -m755 "$tmp"/z3-*/bin/z3 "$BIN/z3"
"$BIN/z3" --version | grep -q "Z3 version ${Z3_VERSION}"

# fixpoint (nightly prebuilt, pinned URL)
curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
  "https://github.com/ucsd-progsys/liquid-fixpoint/releases/download/nightly/$FP" \
  | tar xz -C "$BIN"
chmod +x "$BIN/fixpoint"

# flux (from source, main — the job is continue-on-error upstream-drift)
git clone --depth 1 https://github.com/flux-rs/flux "$tmp/flux"
( cd "$tmp/flux" && cargo xtask install )

echo "done: $("$BIN/z3" --version); fixpoint+flux in $BIN"
