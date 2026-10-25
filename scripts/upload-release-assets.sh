#!/usr/bin/env bash
# Idempotently upload every release asset and publish the release only when the
# complete set is present. Existing assets are never deleted or rewritten.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:?usage: $0 <tag> [notes-file]}"
NOTES_FILE="${2:-release-notes/release-notes.md}"
export GH_TOKEN="${GH_TOKEN:?GH_TOKEN is required}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

shopt -s nullglob
assets=()
for dir in linux-dist linux-glibc228-dist linux-arm64-dist windows-dist windows-arm64-dist macos-dist macos-amd64-dist; do
  for file in "$dir"/*; do
    if [[ -f "$file" ]]; then
      assets+=("$file")
    fi
  done
done
for file in issuerd_*_conformance-evidence.tar.gz* SHA256SUMS.txt*; do
  if [[ -f "$file" ]]; then
    assets+=("$file")
  fi
done

if [[ "${ACT:-}" != true && "${#assets[@]}" -ne 48 ]]; then
  echo "::error::Expected 48 release assets, found ${#assets[@]}"
  exit 1
fi
if [[ "${#assets[@]}" -eq 0 ]]; then
  echo "::error::No release assets found"
  exit 1
fi

asset_exists() {
  local name="$1"
  gh release view "$TAG" --repo "$REPO" --json assets \
    --jq ".assets[] | select(.name == \"$name\") | .name" | grep -Fxq "$name"
}

wait_for_asset() {
  local name="$1"
  for attempt in 1 2 3 4 5; do
    if asset_exists "$name"; then
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

if gh release view "$TAG" --repo "$REPO" --json id >/dev/null 2>&1; then
  gh release edit "$TAG" --repo "$REPO" --notes-file "$NOTES_FILE"
else
  gh release create "$TAG" --repo "$REPO" --draft --title "$TAG" \
    --notes-file "$NOTES_FILE" --verify-tag
fi

upload_url=$(gh release view "$TAG" --repo "$REPO" --json uploadUrl --jq '.uploadUrl')
release_id=${upload_url##*/releases/}
release_id=${release_id%%/assets*}
if [[ ! "$release_id" =~ ^[0-9]+$ ]]; then
  echo "::error::Could not determine the numeric release id for $TAG"
  exit 1
fi

for file in "${assets[@]}"; do
  name=${file##*/}
  if asset_exists "$name"; then
    echo "Asset already exists, skipping: $name"
    continue
  fi

  uploaded=false
  for attempt in 1 2 3; do
    if gh release upload "$TAG" --repo "$REPO" --clobber "$file"; then
      uploaded=true
      break
    fi
    if wait_for_asset "$name"; then
      uploaded=true
      break
    fi
    sleep "$attempt"
  done
  if [[ "$uploaded" != true ]]; then
    echo "::error::Failed to upload release asset after retries: $name"
    exit 1
  fi
done

for file in "${assets[@]}"; do
  name=${file##*/}
  if ! wait_for_asset "$name"; then
    echo "::error::Release asset is missing after upload: $name"
    exit 1
  fi
done

gh api --method PATCH "repos/$REPO/releases/$release_id" \
  -F draft=false -F make_latest=true
