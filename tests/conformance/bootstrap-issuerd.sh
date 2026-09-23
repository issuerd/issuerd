#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${ISSUERD_URL:-https://localhost:9443}"
CACERT="${ISSUERD_CACERT:-$SCRIPT_DIR/pki/ca.crt}"

CURL=(curl -sf --cacert "$CACERT")

# Resolve a working Python interpreter. On Windows, the Microsoft Store app
# execution aliases for `python3`/`python` exist on PATH but fail when run;
# the `py` launcher works. Probe with a real command, not just presence.
PYTHON=""
for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done
if [[ -z "$PYTHON" ]]; then
    echo "ERROR: no working Python interpreter found (tried python3, python, py)"
    exit 1
fi

echo "=== Waiting for Issuerd at $BASE_URL ==="
for i in {1..60}; do
    if "${CURL[@]}" "$BASE_URL/health/ready" >/dev/null 2>&1; then
        echo "Issuerd is ready"
        break
    fi
    if [[ $i -eq 60 ]]; then
        echo "ERROR: Issuerd did not become ready in time"
        exit 1
    fi
    sleep 1
done

echo "=== Obtaining admin token ==="
ADMIN_TOKEN=$("${CURL[@]}" "$BASE_URL/api/v1/auth/admin-token" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"realm":"master","username":"admin","password":"admin"}' | \
    "$PYTHON" -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

echo "=== Deleting existing realm 'conformance' ==="
"${CURL[@]}" "$BASE_URL/admin/realms/conformance" \
    -X DELETE \
    -H "Authorization: Bearer $ADMIN_TOKEN" || true

echo "=== Creating realm 'conformance' ==="
"${CURL[@]}" "$BASE_URL/admin/realms" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{
        "id": "conformance",
        "realm": "conformance",
        "enabled": true,
        "displayName": "Conformance Test Realm"
    }'

echo "=== Creating client 'conformance-client' ==="
"${CURL[@]}" "$BASE_URL/admin/realms/conformance/clients" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{
        "client_id": "conformance-client",
        "name": "conformance-client",
        "enabled": true,
        "protocol": "openid-connect",
        "public_client": false,
        "secret": "conformance-secret",
        "redirect_uris": [
            "https://suite.conformance.test:8443/test/a/issuerd/callback"
        ],
        "default_scopes": ["openid", "profile", "email", "offline_access", "address", "phone"],
        "optional_scopes": [],
        "standard_flow_enabled": true,
        "implicit_flow_enabled": true,
        "direct_access_grants_enabled": true,
        "service_accounts_enabled": true
    }' || { echo "Client may already exist, continuing..."; }

echo "=== Creating client 'conformance-client-2' ==="
"${CURL[@]}" "$BASE_URL/admin/realms/conformance/clients" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{
        "client_id": "conformance-client-2",
        "name": "conformance-client-2",
        "enabled": true,
        "protocol": "openid-connect",
        "public_client": false,
        "secret": "conformance-secret-2",
        "redirect_uris": [
            "https://suite.conformance.test:8443/test/a/issuerd/callback"
        ],
        "default_scopes": ["openid", "profile", "email", "offline_access", "address", "phone"],
        "optional_scopes": [],
        "standard_flow_enabled": true,
        "implicit_flow_enabled": true,
        "direct_access_grants_enabled": true,
        "service_accounts_enabled": true
    }' || { echo "Client may already exist, continuing..."; }

echo "=== Creating user 'conformance-user' ==="
"${CURL[@]}" "$BASE_URL/admin/realms/conformance/users" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{
        "username": "conformance-user",
        "enabled": true,
        "email": "conformance@example.com",
        "email_verified": true,
        "first_name": "Conformance",
        "last_name": "Test",
        "attributes": {
            "address_formatted": ["123 Main St, Springfield, IL 62701, USA"],
            "address_street": ["123 Main St"],
            "address_locality": ["Springfield"],
            "address_region": ["IL"],
            "address_postal_code": ["62701"],
            "address_country": ["USA"],
            "phone_number": ["+1-555-123-4567"],
            "phone_number_verified": ["true"],
            "middle_name": ["A"],
            "nickname": ["conformo"],
            "profile": ["https://example.com/conformance-user"],
            "picture": ["https://example.com/conformance-user.png"],
            "website": ["https://example.com"],
            "gender": ["male"],
            "birthdate": ["1990-01-01"],
            "zoneinfo": ["America/Chicago"],
            "locale": ["en-US"]
        }
    }' || { echo "User may already exist, continuing..."; }

echo "=== Setting user password ==="
USER_ID=$("${CURL[@]}" "$BASE_URL/admin/realms/conformance/users?username=conformance-user" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | \
    "$PYTHON" -c "import sys, json; print(json.load(sys.stdin)[0]['id'])")

"${CURL[@]}" "$BASE_URL/admin/realms/conformance/users/$USER_ID/reset-password" \
    -X PUT \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{
        "type": "password",
        "value": "conformance-password",
        "temporary": false
    }' || { echo "Failed to set password, continuing..."; }

echo "=== Bootstrap complete ==="
