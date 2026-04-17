FROM --platform=linux/amd64 neo4j:3.4

# Neo4j 3.4 with the Shell Server enabled.
# CVE-2021-34371: the Neo4j Shell Server binds an RMI listener on port 1337.
# An attacker who can reach that port can exploit Java RMI deserialization to
# execute arbitrary code as the neo4j process user — no authentication required.

USER root

RUN apt-get update && \
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
