# Samba Active Directory Domain Controller
# Provides LDAP + Kerberos KDC for Issuerd federation integration tests.
#
# Build:
#   docker build -t issuerd/samba-dc tests/fixtures/samba-dc
# Run:
#   docker run -d --privileged -p 389:389 -p 636:636 -p 88:88 -p 88:88/udp \
#     -p 464:464 -p 464:464/udp issuerd/samba-dc

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV REALM=TEST.ISSUERD.LOCAL
ENV DOMAIN=ISSUERD
ENV ADMIN_PASSWORD=AdminPass123!

RUN apt-get update && apt-get install -y \
    samba \
    krb5-user \
    winbind \
    ldap-utils \
    ldb-tools \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Generate a self-signed TLS certificate for LDAPS / StartTLS.
# Samba requires ca.pem to exist even for self-signed certs.
RUN mkdir -p /var/lib/samba/private/tls && \
    openssl req -newkey rsa:2048 -nodes \
        -keyout /var/lib/samba/private/tls/key.pem \
        -x509 -days 365 \
        -out /var/lib/samba/private/tls/cert.pem \
        -subj "/CN=localhost" && \
    cp /var/lib/samba/private/tls/cert.pem /var/lib/samba/private/tls/ca.pem && \
    chmod 600 /var/lib/samba/private/tls/key.pem

# Create a mount point for sharing the keytab with the host.
RUN mkdir -p /shared
VOLUME ["/shared"]

# Expose the standard Samba AD DC ports.
EXPOSE 53 53/udp 88 88/udp 135 139 389 445 464 464/udp 636 1024 3268 3269

# Provision and start via a runtime script so that setsysvolacl runs inside
# the privileged container instead of during unprivileged docker build.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
