FROM ubuntu:25.10
# Scenario 14: PostgreSQL listen_addresses = '*' unprotected
# CWE-668: Exposure of Resource to Wrong Sphere
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure PostgreSQL to listen on all interfaces
RUN PG_CONF=$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1) && \
    if [ -n "$PG_CONF" ]; then \
    sed -i "s/^#listen_addresses.*/listen_addresses = '*'/" "$PG_CONF" && \
    sed -i "s/^listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"; \
    fi

# Create a test database
USER postgres
RUN pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start 2>/dev/null; \
    sleep 2 && \
    psql -c "CREATE DATABASE testdb;" 2>/dev/null; \
    psql -d testdb -c "CREATE TABLE items (id SERIAL PRIMARY KEY, name VARCHAR(100)); INSERT INTO items (name) VALUES ('test');" 2>/dev/null; \
    pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') stop 2>/dev/null || true
USER root

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 5432
CMD ["su", "-c", "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start --foreground", "postgres"]
