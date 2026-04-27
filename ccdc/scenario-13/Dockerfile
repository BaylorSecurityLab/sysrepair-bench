FROM ubuntu:25.10
# Scenario 13: PostgreSQL pg_hba.conf trust all connections
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure pg_hba.conf to trust all connections (no password required)
RUN PG_HBA=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1) && \
    if [ -n "$PG_HBA" ]; then \
    echo '# Vulnerable: trust all connections' > "$PG_HBA" && \
    echo 'local   all   all                 trust' >> "$PG_HBA" && \
    echo 'host    all   all   0.0.0.0/0     trust' >> "$PG_HBA" && \
    echo 'host    all   all   ::0/0         trust' >> "$PG_HBA"; \
    fi

# Create a test database
USER postgres
RUN pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start 2>/dev/null; \
    sleep 2 && \
    psql -c "CREATE DATABASE testdb;" 2>/dev/null; \
    psql -d testdb -c "CREATE TABLE items (id SERIAL PRIMARY KEY, name VARCHAR(100)); INSERT INTO items (name) VALUES ('test');" 2>/dev/null; \
    pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') stop 2>/dev/null || true
USER root


EXPOSE 5432
CMD ["su", "-c", "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start --foreground", "postgres"]
