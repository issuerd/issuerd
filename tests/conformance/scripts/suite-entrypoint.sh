#!/usr/bin/env bash
# Conformance suite container entrypoint.
#
# The single allowed deviation from a stock suite deployment: import the
# local conformance root CA into the JVM truststore, so HtmlUnit trusts
# the Issuerd OP and the suite's own HTTPS callback endpoint. Done at
# container start (idempotent) so the image build stays PKI-free.
set -e

CACERTS="$JAVA_HOME/lib/security/cacerts"
if ! keytool -list -trustcacerts -keystore "$CACERTS" -storepass changeit \
        -alias issuerd-conformance-root >/dev/null 2>&1; then
    echo "suite-entrypoint: importing local root CA into JVM truststore"
    keytool -import -trustcacerts -keystore "$CACERTS" -storepass changeit \
        -alias issuerd-conformance-root -file /pki/ca.crt -noprompt
fi

# Native HTTPS via standard Spring Boot server.ssl.* configuration; the
# PKCS12 keystore is bind-mounted from tests/conformance/pki.
exec java \
    -Djdk.tls.maxHandshakeMessageSize=65536 \
    -Dfintechlabs.devmode=true \
    -Dfintechlabs.startredir=false \
    -Dfintechlabs.base_url="${BASE_URL}" \
    -Dfintechlabs.base_mtls_url="${BASE_MTLS_URL}" \
    -Dspring.mongodb.uri="mongodb://${MONGODB_HOST}:27017/test_suite" \
    -Dserver.port=8443 \
    -Dserver.ssl.key-store=/pki/suite-keystore.p12 \
    -Dserver.ssl.key-store-password="${KEYSTORE_PASSWORD}" \
    -Dserver.ssl.key-store-type=PKCS12 \
    ${JAVA_EXTRA_ARGS:-} \
    -jar /server/fapi-test-suite.jar
