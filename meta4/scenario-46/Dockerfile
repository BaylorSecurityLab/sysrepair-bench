FROM --platform=linux/amd64 neo4j:3.4

# Neo4j 3.4 with the Shell Server enabled.
# CVE-2021-34371: the Neo4j Shell Server binds an RMI listener on port 1337.
# An attacker who can reach that port can exploit Java RMI deserialization to
# execute arbitrary code as the neo4j process user — no authentication required.

USER root

# Redirect stale Debian repos to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /stretch-updates/d; /buster-updates/d' /etc/apt/sources.list 2>/dev/null; \
    sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd iptables && \
    rm -rf /var/lib/apt/lists/*


ENV NEO4J_dbms_shell_enabled=true
ENV NEO4J_dbms_shell_host=0.0.0.0
ENV NEO4J_dbms_shell_port=1337
ENV NEO4J_AUTH=none

EXPOSE 7474 7687 1337

# Boot wrapper (paired with the .preserve-cmd marker). The image ENTRYPOINT
# (/docker-entrypoint.sh) unconditionally translates the NEO4J_* env vars into
# neo4j.conf (so dbms.shell.enabled=true and the RMI listener on 1337 are
# present) and then runs `exec gosu neo4j:neo4j "$@"`. This wrapper therefore
# runs as the neo4j user:
#   1. `neo4j start` daemonizes the server (managed by its pidfile) - unlike the
#      stock `neo4j console`, which would be a foreground PID 1;
#   2. poll the Browser HTTP endpoint (7474) until it answers;
#   3. exec `sleep infinity` so PID 1 survives a `neo4j restart`.
CMD ["/bin/bash", "-c", "neo4j start; for i in $(seq 1 90); do [ \"$(curl -s -o /dev/null -w '%{http_code}' http://localhost:7474/ 2>/dev/null)\" = 200 ] && break; sleep 1; done; exec sleep infinity"]
