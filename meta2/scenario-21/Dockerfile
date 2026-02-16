FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install PostgreSQL and OpenSSL
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        postgresql \
        postgresql-client \
        openssl \
        ssl-cert && \
    apt-get clean

# Generate a self-signed SSL certificate for PostgreSQL
RUN mkdir -p /etc/postgresql/ssl && \
    openssl req -new -x509 -days 3650 -nodes \
        -subj "/CN=postgres-server/O=Test/C=US" \
        -keyout /etc/postgresql/ssl/server.key \
        -out /etc/postgresql/ssl/server.crt && \
    chown -R postgres:postgres /etc/postgresql/ssl && \
    chmod 600 /etc/postgresql/ssl/server.key

# Configure PostgreSQL to use SSL
# Ubuntu 8.04 ships PostgreSQL 8.3
RUN PG_CONF=$(find /etc/postgresql -name postgresql.conf | head -1) && \
    echo "ssl = on" >> "$PG_CONF" && \
    echo "ssl_cert_file = '/etc/postgresql/ssl/server.crt'" >> "$PG_CONF" && \
    echo "ssl_key_file = '/etc/postgresql/ssl/server.key'" >> "$PG_CONF"

# Allow connections from all hosts
RUN PG_HBA=$(find /etc/postgresql -name pg_hba.conf | head -1) && \
    echo "hostssl all all 0.0.0.0/0 md5" >> "$PG_HBA" && \
    echo "host all all 0.0.0.0/0 md5" >> "$PG_HBA"

# Listen on all interfaces
RUN PG_CONF=$(find /etc/postgresql -name postgresql.conf | head -1) && \
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" "$PG_CONF" || \
    echo "listen_addresses = '*'" >> "$PG_CONF"

# Create a test database and user
RUN /etc/init.d/postgresql-8.3 start && \
    su - postgres -c "psql -c \"CREATE USER testuser WITH PASSWORD 'testpass';\"" && \
    su - postgres -c "psql -c \"CREATE DATABASE testdb OWNER testuser;\"" && \
    su - postgres -c "psql -d testdb -c \"CREATE TABLE test_data (id serial PRIMARY KEY, name varchar(50)); INSERT INTO test_data (name) VALUES ('test_entry');\"" && \
    /etc/init.d/postgresql-8.3 stop

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/etc/init.d/postgresql-8.3 start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 5432

CMD ["/start.sh"]
