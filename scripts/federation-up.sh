#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Starting Issuerd Federation Stack <=="
echo ""

# Start infrastructure services
docker compose -f docker-compose.integration.yml up -d issuerd-postgres samba-dc openldap redis

# Wait for PostgreSQL
echo -n "Waiting for PostgreSQL..."
until docker exec issuerd-postgres pg_isready -U issuerd -d issuerd >/dev/null 2>&1; do
    echo -n "."
    sleep 1
done
echo " ready"

# Wait for Samba DC (and keytab generation)
echo -n "Waiting for Samba DC..."
until docker exec issuerd-samba-dc ldapsearch -x -H ldap://localhost -D 'CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local' -w 'AdminPass123!' -b 'DC=test,DC=issuerd,DC=local' '(sAMAccountName=testuser)' >/dev/null 2>&1; do
    echo -n "."
    sleep 2
done
echo " ready"

# Wait for OpenLDAP (probe server readiness; no seed users exist by default —
# run ./scripts/seed-openldap.sh to add the federation_ldap test fixtures)
echo -n "Waiting for OpenLDAP..."
attempts=0
until docker exec issuerd-openldap ldapsearch -x -H ldap://localhost -D 'cn=admin,dc=test,dc=issuerd,dc=local' -w 'admin' -b 'dc=test,dc=issuerd,dc=local' '(objectClass=*)' >/dev/null 2>&1; do
    echo -n "."
    sleep 2
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
        echo " FAILED"
        echo "ERROR: OpenLDAP did not become ready in time" >&2
        exit 1
    fi
done
echo " ready"

# Check for keytab
if [ -f "tests/fixtures/samba-dc/shared/issuerd.keytab" ]; then
    echo "Kerberos keytab found"
else
    echo ""
    echo "WARNING: Kerberos keytab not found yet. It may still be generating."
    echo "  If using the kerberos realm, ensure tests/fixtures/samba-dc/shared/issuerd.keytab exists before starting Issuerd."
fi

echo ""
echo "Infrastructure is up. Start Issuerd with:"
echo "  cp examples/issuerd.example.toml issuerd.toml   # first run only; set provision = \"examples/provision.federation.yaml\""
echo "  cargo run --release --bin issuerd -- daemon -c issuerd.toml"
echo ""
echo "Admin UI:     https://issuerd.test.internal"
echo "Admin user:   admin / admin"
echo "Realms:       master, ad, samba, openldap, kerberos"
echo ""
echo "To wipe PostgreSQL data and re-provision from scratch:"
echo "  docker compose -f docker-compose.integration.yml down && docker volume rm issuerd_issuerd_postgres_data"
echo "  ./scripts/federation-up.sh"
echo "  cargo run --release --bin issuerd -- daemon -c issuerd.toml"
