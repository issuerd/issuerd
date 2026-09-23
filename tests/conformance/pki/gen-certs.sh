#!/usr/bin/env bash
# Generates the local PKI for the hermetic conformance environment:
#   ca.crt/ca.key           - "Issuerd Conformance Root CA" (the only trust anchor)
#   op.crt/op.key           - Issuerd OP server cert  (SAN: op.conformance.test, localhost, 127.0.0.1)
#   suite.crt/suite.key     - conformance suite cert    (SAN: suite.conformance.test, localhost, 127.0.0.1)
#   suite-keystore.p12      - suite cert + chain as PKCS12 for Spring Boot (password: conformance)
#   cdn.crt/cdn.key         - cdn-shim cert (SAN: the CDN hostnames the suite web
#                             UI references — cdn.jsdelivr.net, cdnjs.cloudflare.com,
#                             cdn.datatables.net, fonts.googleapis.com,
#                             fonts.gstatic.com, oss.maxcdn.com)
#
# All generated files are gitignored; only this script is committed.
# Idempotent: does nothing when everything already exists. FORCE=1 regenerates.
set -euo pipefail

PKI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PKI_DIR"

DAYS=3650
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-conformance}"

if [[ "${FORCE:-0}" != "1" && -f ca.crt && -f ca.key && -f op.crt && -f op.key \
      && -f suite.crt && -f suite.key && -f suite-keystore.p12 \
      && -f cdn.crt && -f cdn.key ]]; then
    echo "PKI already present in $PKI_DIR (FORCE=1 to regenerate)"
    exit 0
fi

echo "=== Generating root CA ==="
openssl req -x509 -newkey rsa:4096 -nodes -days "$DAYS" \
    -subj "/CN=Issuerd Conformance Root CA/O=Issuerd" \
    -keyout ca.key -out ca.crt

issue_cert() {
    local name="$1" cn="$2" san="$3"
    echo "=== Issuing $name certificate (CN=$cn, SAN=$san) ==="
    openssl req -newkey rsa:2048 -nodes \
        -subj "/CN=$cn/O=Issuerd" \
        -keyout "$name.key" -out "$name.csr"
    openssl x509 -req -in "$name.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial -days "$DAYS" \
        -extfile <(printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$san") \
        -out "$name.crt"
    rm -f "$name.csr"
}

issue_cert op    op.conformance.test    "DNS:op.conformance.test,DNS:localhost,IP:127.0.0.1"
issue_cert suite suite.conformance.test "DNS:suite.conformance.test,DNS:localhost,IP:127.0.0.1"
issue_cert cdn   cdn.jsdelivr.net       "DNS:cdn.jsdelivr.net,DNS:cdnjs.cloudflare.com,DNS:cdn.datatables.net,DNS:fonts.googleapis.com,DNS:fonts.gstatic.com,DNS:oss.maxcdn.com"

echo "=== Building Spring Boot PKCS12 keystore ==="
openssl pkcs12 -export \
    -in suite.crt -inkey suite.key -certfile ca.crt \
    -name suite -out suite-keystore.p12 \
    -passout "pass:$KEYSTORE_PASSWORD"

# ca.key stays private on the host; leaf keys/certs are mounted into the
# containers (the OP container runs as a non-root user, so they must be
# world-readable). All of this is throwaway, gitignored test key material.
chmod 600 ca.key
chmod 644 op.key op.crt suite.key suite.crt cdn.key cdn.crt suite-keystore.p12 ca.crt

echo "=== PKI ready in $PKI_DIR ==="
openssl x509 -in ca.crt -noout -subject -dates
