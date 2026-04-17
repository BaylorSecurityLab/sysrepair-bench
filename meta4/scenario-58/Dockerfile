FROM --platform=linux/amd64 debian:bookworm-slim

# PowerDNS Authoritative Server 4.8 with HTTP API enabled and empty api-key.
# Any unauthenticated client can manage all DNS zones via the REST API.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pdns-server pdns-backend-sqlite3 \
        sqlite3 dnsutils curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Create database directory
RUN mkdir -p /var/lib/powerdns

# Initialise SQLite backend schema
RUN sqlite3 /var/lib/powerdns/pdns.sqlite3 "
CREATE TABLE domains (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INTEGER DEFAULT NULL,
  type                  VARCHAR(6) NOT NULL,
  notified_serial       INTEGER DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               VARCHAR(65535) DEFAULT NULL,
  catalog               VARCHAR(255) DEFAULT NULL
);
CREATE UNIQUE INDEX name_index ON domains(name);
CREATE TABLE records (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INTEGER DEFAULT NULL,
  prio                  INTEGER DEFAULT NULL,
  disabled              BOOLEAN DEFAULT 0,
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 1
);
CREATE INDEX records_lookup_idx ON records(name, type);
CREATE INDEX records_lookup_id_idx ON records(domain_id, disabled);
CREATE INDEX records_order_idx ON records(domain_id, ordername);
CREATE TABLE supermasters (
  ip                    VARCHAR(64) NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) NOT NULL,
  PRIMARY KEY(ip, nameserver)
);
CREATE TABLE comments (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INTEGER NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL
);
CREATE TABLE domainmetadata (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);
CREATE TABLE cryptokeys (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INTEGER NOT NULL,
  active                BOOL,
  published             BOOL DEFAULT 1,
  content               TEXT
);
CREATE TABLE tsigkeys (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255)
);
"

# Seed local.test zone
RUN sqlite3 /var/lib/powerdns/pdns.sqlite3 "
INSERT INTO domains (name, type) VALUES ('local.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl)
  VALUES (1, 'local.test', 'SOA', 'ns1.local.test. admin.local.test. 2024010101 3600 900 604800 300', 300);
INSERT INTO records (domain_id, name, type, content, ttl)
  VALUES (1, 'local.test', 'NS', 'ns1.local.test.', 300);
INSERT INTO records (domain_id, name, type, content, ttl)
  VALUES (1, 'local.test', 'A', '10.0.0.1', 300);
INSERT INTO records (domain_id, name, type, content, ttl)
  VALUES (1, 'ns1.local.test', 'A', '10.0.0.1', 300);
INSERT INTO records (domain_id, name, type, content, ttl)
  VALUES (1, 'app.local.test', 'A', '10.0.0.2', 300);
"

# Vulnerable pdns.conf — API enabled with empty key
RUN cat > /etc/powerdns/pdns.conf <<'EOF'
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3

local-address=0.0.0.0
local-port=53

# HTTP API — vulnerable: empty api-key allows unauthenticated access
api=yes
api-key=
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0,::/0

loglevel=4
EOF

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 53/tcp 53/udp 8081/tcp

CMD ["pdns_server", "--daemon=no"]
