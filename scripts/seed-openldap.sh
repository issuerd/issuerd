#!/usr/bin/env bash
# Seeds the OpenLDAP integration container with the fixture data the
# federation_ldap tests expect (no seed users exist by default — see the
# note in docker-compose.integration.yml):
#   docker compose -f docker-compose.integration.yml up -d openldap
#   ./scripts/seed-openldap.sh
#   cargo test --test integration federation_ldap -- --ignored
#
# Fixture content mirrors the Samba/AD fixtures: users testuser/testuser2
# (Password123!), group developers with testuser as member. The container
# image already loads the memberof+refint overlays (groupOfUniqueNames /
# uniqueMember / memberOf), so adding the group is enough to populate
# memberOf on the user entries. Idempotent: existing entries are skipped.
set -euo pipefail

CONTAINER="${1:-issuerd-openldap}"
BIND_DN="cn=admin,dc=test,dc=issuerd,dc=local"
BIND_PW="admin"
BASE="dc=test,dc=issuerd,dc=local"

have_entry() {
  docker exec "$CONTAINER" ldapsearch -x -H ldap://localhost \
    -D "$BIND_DN" -w "$BIND_PW" -b "$1" -s base "(objectClass=*)" dn \
    2>/dev/null | grep -q "^dn:"
}

add_ldif() {
  # $1 = probe DN (skipped when it already exists), stdin = LDIF
  local probe="$1"
  if have_entry "$probe"; then
    echo "SKIP  $probe (exists)"
    return 0
  fi
  docker exec -i "$CONTAINER" ldapadd -x -H ldap://localhost \
    -D "$BIND_DN" -w "$BIND_PW"
  echo "ADDED $probe"
}

echo "==> Seeding OpenLDAP fixture data into $CONTAINER"

add_ldif "ou=users,$BASE" <<'EOF'
dn: ou=users,dc=test,dc=issuerd,dc=local
objectClass: organizationalUnit
ou: users
EOF

add_ldif "ou=groups,$BASE" <<'EOF'
dn: ou=groups,dc=test,dc=issuerd,dc=local
objectClass: organizationalUnit
ou: groups
EOF

add_ldif "uid=testuser,ou=users,$BASE" <<'EOF'
dn: uid=testuser,ou=users,dc=test,dc=issuerd,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: testuser
cn: Test User
sn: User
givenName: Test
mail: testuser@test.issuerd.local
userPassword: Password123!
EOF

add_ldif "uid=testuser2,ou=users,$BASE" <<'EOF'
dn: uid=testuser2,ou=users,dc=test,dc=issuerd,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: testuser2
cn: Test User2
sn: User2
givenName: Test
mail: testuser2@test.issuerd.local
userPassword: Password123!
EOF

# groupOfUniqueNames + uniqueMember: the memberOf overlay derives the
# memberOf attribute on uid=testuser from this entry.
add_ldif "cn=developers,ou=groups,$BASE" <<'EOF'
dn: cn=developers,ou=groups,dc=test,dc=issuerd,dc=local
objectClass: groupOfUniqueNames
objectClass: top
cn: developers
uniqueMember: uid=testuser,ou=users,dc=test,dc=issuerd,dc=local
EOF

echo "Done. Verify with:"
echo "  docker exec $CONTAINER ldapsearch -x -H ldap://localhost -D '$BIND_DN' -w '$BIND_PW' -b '$BASE' '(uid=testuser)' memberOf"
