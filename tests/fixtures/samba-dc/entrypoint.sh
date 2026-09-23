#!/bin/bash
set -e

REALM="TEST.ISSUERD.LOCAL"
DOMAIN="ISSUERD"
ADMIN_PASSWORD="AdminPass123!"

PROV_FLAG="/var/lib/samba/private/provisioned.ok"
PROV_SMB="/var/lib/samba/private/smb.conf"
PROV_KRB5="/var/lib/samba/private/krb5.conf"

# Provision the domain if we do not have a persisted configuration.
if [ ! -f "$PROV_FLAG" ]; then
    echo "[samba-dc] Provisioning domain ${REALM}..."
    rm -f /etc/samba/smb.conf
    rm -rf /var/lib/samba/private/* /var/lib/samba/sysvol /var/lib/samba/*.ldb \
        /var/lib/samba/*.tdb /var/lib/samba/*.dat 2>/dev/null || true

    samba-tool domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm="${REALM}" \
        --domain="${DOMAIN}" \
        --adminpass="${ADMIN_PASSWORD}"

    # Copy the generated KDC config into the system location.
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    # Enable TLS in Samba configuration (must be in [global], not a [tls] share).
    sed -i '/^\[global\]$/a \\t tls enabled = yes\n\t tls keyfile = /var/lib/samba/private/tls/key.pem\n\t tls certfile = /var/lib/samba/private/tls/cert.pem\n\t ldap server require strong auth = no' /etc/samba/smb.conf

    # Create test users.
    samba-tool user create testuser Password123! || true
    samba-tool user create testuser2 Password123! || true

    # Populate additional AD attributes (givenName, sn, mail) via ldbmodify.
    cat > /tmp/testuser-attrs.ldif << 'EOF'
dn: CN=testuser,CN=Users,DC=test,DC=issuerd,DC=local
changetype: modify
replace: givenName
givenName: Test
-
replace: sn
sn: User
-
replace: mail
mail: testuser@test.issuerd.local
EOF
    ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/testuser-attrs.ldif || true

    cat > /tmp/testuser2-attrs.ldif << 'EOF'
dn: CN=testuser2,CN=Users,DC=test,DC=issuerd,DC=local
changetype: modify
replace: givenName
givenName: Test2
-
replace: sn
sn: User2
-
replace: mail
mail: testuser2@test.issuerd.local
EOF
    ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/testuser2-attrs.ldif || true

    # Create a test group and add testuser as a member.
    samba-tool group add developers || true
    samba-tool group addmembers developers testuser || true

    # Create a service account for the Issuerd HTTP SPN and export a keytab.
    samba-tool user create issuerd-spn SPNPass123! || true
    samba-tool spn add HTTP/issuerd.test.issuerd.local issuerd-spn || true
    samba-tool domain exportkeytab /shared/issuerd.keytab \
        --principal=HTTP/issuerd.test.issuerd.local || true

    # Persist the generated configuration so it survives container restarts.
    cp /etc/samba/smb.conf "$PROV_SMB"
    cp /etc/krb5.conf "$PROV_KRB5"
    touch "$PROV_FLAG"

    echo "[samba-dc] Provisioning complete."
fi

# Restore the persisted configuration on every start.
cp "$PROV_SMB" /etc/samba/smb.conf
cp "$PROV_KRB5" /etc/krb5.conf

# Start Samba in foreground mode with debug level 3 so errors are visible.
echo "[samba-dc] Starting Samba..."
exec samba -F -d 3
