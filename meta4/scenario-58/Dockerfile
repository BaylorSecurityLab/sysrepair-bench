FROM --platform=linux/amd64 debian:bookworm-slim

# PowerDNS Authoritative Server (bookworm ships 4.7.x) with the HTTP API
# enabled and a WEAK, well-known api-key ("powerdns"). Any attacker who guesses
# this trivial default can manage all DNS zones via the REST API.
#
# NOTE: an *empty* api-key does NOT open the API on this version - PowerDNS then
# returns 401 to every request (API locked). The genuine, behaviourally
# reproducible misconfiguration is a weak/guessable key, seeded below.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pdns-server pdns-backend-sqlite3 \
        sqlite3 dnsutils curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Create database directory
RUN mkdir -p /var/lib/powerdns

# Initialise SQLite backend schema
RUN sqlite3 /var/lib/powerdns/pdns.sqlite3 < /dev/stdin <<'EOSQL'
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
EOSQL

# Seed local.test zone
RUN sqlite3 /var/lib/powerdns/pdns.sqlite3 < /dev/stdin <<'EOSQL'
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
EOSQL

# Vulnerable pdns.conf — API enabled with empty key
RUN cat > /etc/powerdns/pdns.conf <<'EOF'
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/pdns.sqlite3

local-address=0.0.0.0
local-port=53

# HTTP API — vulnerable: weak, well-known api-key trivially guessable
api=yes
api-key=powerdns
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0,::/0

loglevel=4
EOF


EXPOSE 53/tcp 53/udp 8081/tcp

# Boot wrapper: start pdns_server backgrounded, poll for the API on :8081, then
# exec `sleep infinity` so PID 1 is stable and an agent restarting pdns_server
# cannot kill the container. See .preserve-cmd.
CMD ["/bin/bash", "-c", "pdns_server --daemon=no & for i in $(seq 1 30); do nc -z 127.0.0.1 8081 && break; sleep 1; done; exec sleep infinity"]
