#!/usr/bin/env bash
# Vendors the CDN assets referenced by the pristine conformance suite's web UI
# (static-legacy/*.html) into cdn-shim/<host>/<path>, mirroring the origin URL
# layout. The cdn-shim container serves this directory over HTTPS inside the
# hermetic network, so the suite's HtmlUnit browser gets 200s instead of
# UnknownHostException noise. Suite sources stay untouched.
#
# Usage:  ./fetch.sh   (requires internet access)
# Output: cdn-shim/<host>/...  (committed)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# Modern browser UA so fonts.googleapis.com answers woff2 css.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# <url> <local path relative to cdn-shim/>
ASSETS=(
  # cdn.jsdelivr.net
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css"
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/fonts/bootstrap-icons.woff2 cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/fonts/bootstrap-icons.woff2"
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/fonts/bootstrap-icons.woff cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/fonts/bootstrap-icons.woff"
  "https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js"
  "https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js"
  # cdnjs.cloudflare.com
  "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"
  "https://cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.0/clipboard.min.js cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.0/clipboard.min.js"
  "https://cdnjs.cloudflare.com/ajax/libs/chroma-js/1.3.7/chroma.min.js cdnjs.cloudflare.com/ajax/libs/chroma-js/1.3.7/chroma.min.js"
  "https://cdnjs.cloudflare.com/ajax/libs/prettify/r298/prettify.css cdnjs.cloudflare.com/ajax/libs/prettify/r298/prettify.css"
  "https://cdnjs.cloudflare.com/ajax/libs/prettify/r298/prettify.js cdnjs.cloudflare.com/ajax/libs/prettify/r298/prettify.js"
  "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"
  "https://cdnjs.cloudflare.com/ajax/libs/randomcolor/0.5.2/randomColor.js cdnjs.cloudflare.com/ajax/libs/randomcolor/0.5.2/randomColor.js"
  # cdn.datatables.net
  "https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css"
  "https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"
  "https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"
  "https://cdn.datatables.net/1.13.2/css/dataTables.bootstrap5.min.css cdn.datatables.net/1.13.2/css/dataTables.bootstrap5.min.css"
  # fonts.googleapis.com (css served verbatim; its woff2 refs stay absolute
  # on fonts.gstatic.com, which the shim also answers)
  "https://fonts.googleapis.com/css?family=PT+Sans fonts.googleapis.com/css"
  "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap fonts.googleapis.com/css2"
  # fonts.gstatic.com woff2 referenced by the two css payloads above
  "https://fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0-ExdGM.woff2 fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0-ExdGM.woff2"
  "https://fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0KExQ.woff2 fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0KExQ.woff2"
  "https://fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0aExdGM.woff2 fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0aExdGM.woff2"
  "https://fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0yExdGM.woff2 fonts.gstatic.com/s/ptsans/v18/jizaRExUiTo99u79D0yExdGM.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx3cwhsk.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx3cwhsk.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx7cwhsk.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx7cwhsk.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxDcwg.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxDcwg.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxPcwhsk.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxPcwhsk.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxTcwhsk.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPxTcwhsk.woff2"
  "https://fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx_cwhsk.woff2 fonts.gstatic.com/s/jetbrainsmono/v24/tDbv2o-flEEny0FZhsfKu5WU4zr3E_BX0PnT8RD8yKwBNntkaToggR7BYRbKPx_cwhsk.woff2"
  # oss.maxcdn.com (IE shims from conditional comments). The origin is defunct
  # (answers "Hello World!!" stubs), so the real files come from cdnjs but are
  # vendored under the oss.maxcdn.com paths the suite pages request.
  "https://cdnjs.cloudflare.com/ajax/libs/html5shiv/3.7.3/html5shiv.min.js oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"
  "https://cdnjs.cloudflare.com/ajax/libs/respond.js/1.4.2/respond.min.js oss.maxcdn.com/respond/1.4.2/respond.min.js"
)

for entry in "${ASSETS[@]}"; do
  url="${entry%% *}"
  dest="${entry#* }"
  mkdir -p "$(dirname "$dest")"
  curl -sf -A "$UA" -o "$dest" "$url"
  printf '%8d  %s\n' "$(stat -c %s "$dest" 2>/dev/null || stat -f %z "$dest")" "$dest"
done

echo "Vendored ${#ASSETS[@]} assets into $(pwd)"
