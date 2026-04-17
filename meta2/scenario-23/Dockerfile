FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install PostgreSQL with SSL support
# Ubuntu 8.04 ships with OpenSSL 0.9.8g which supports SSLv3 (POODLE vulnerable)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib openssl

# Enable SSL in PostgreSQL
RUN sed -i "s/#ssl = off/ssl = on/" /etc/postgresql/8.3/main/postgresql.conf && \
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/8.3/main/postgresql.conf

# Generate self-signed certificate for PostgreSQL
RUN openssl req -new -x509 -days 365 -nodes -text \
    -out /etc/postgresql/8.3/main/server.crt \
    -keyout /etc/postgresql/8.3/main/server.key \
    -subj "/C=US/ST=State/L=City/O=Org/CN=postgres" && \
    chmod 600 /etc/postgresql/8.3/main/server.key && \
    chown postgres:postgres /etc/postgresql/8.3/main/server.*

# Old OpenSSL 0.9.8g supports SSLv3 by default (CVE-2014-3566 POODLE)

EXPOSE 5432

USER postgres
CMD ["/usr/lib/postgresql/8.3/bin/postgres", "-D", "/var/lib/postgresql/8.3/main", "-c", "config_file=/etc/postgresql/8.3/main/postgresql.conf"]
