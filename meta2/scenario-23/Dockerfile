FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install PostgreSQL with SSL support.
# Ubuntu 8.04 ships OpenSSL 0.9.8g which enables the SSLv3 protocol (POODLE,
# CVE-2014-3566). python-openssl (pyOpenSSL) lets the verifier negotiate a real
# SSLv3 handshake against the live database after the PostgreSQL SSLRequest.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib openssl python-openssl && \
    apt-get clean

# Enable SSL and listen on all interfaces.
RUN sed -i "s/^#*ssl[[:space:]]*=.*/ssl = on/" /etc/postgresql/8.3/main/postgresql.conf && \
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/8.3/main/postgresql.conf

# Generate self-signed certificate for PostgreSQL
RUN openssl req -new -x509 -days 365 -nodes -text \
    -out /etc/postgresql/8.3/main/server.crt \
    -keyout /etc/postgresql/8.3/main/server.key \
    -subj "/C=US/ST=State/L=City/O=Org/CN=postgres" && \
    chmod 600 /etc/postgresql/8.3/main/server.key && \
    chown postgres:postgres /etc/postgresql/8.3/main/server.*

# Old OpenSSL 0.9.8g negotiates SSLv3 by default (CVE-2014-3566 POODLE).
# PostgreSQL 8.3 has no ssl_min_protocol_version, and on 0.9.8g SSLv3 and TLSv1
# share cipher suites, so the achievable remediation is disabling SSL.

EXPOSE 5432

# .preserve-cmd: boot the PostgreSQL postmaster (as the postgres user) in the
# BACKGROUND so a real SSLv3-capable server is already listening, then keep
# PID 1 as `sleep infinity`. The postmaster caches `ssl` at startup ("change
# requires restart"), so editing postgresql.conf without a restart leaves the
# live server exploitable — which is exactly what the notrestart case checks.
CMD ["/bin/bash", "-c", "su postgres -c '/usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf' & exec sleep infinity"]
