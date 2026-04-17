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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

ENV NEO4J_dbms_shell_enabled=true
ENV NEO4J_dbms_shell_host=0.0.0.0
ENV NEO4J_dbms_shell_port=1337
ENV NEO4J_AUTH=none

EXPOSE 7474 7687 1337

CMD ["neo4j"]
