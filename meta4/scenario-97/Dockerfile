FROM --platform=linux/amd64 ubuntu:22.04

# Kibana 6.5.4 / Elasticsearch 6.5.4 — CVE-2019-7609: Timelion prototype
# pollution leading to RCE. Timelion's expression parser does not sanitise
# prototype-polluting payloads, allowing an authenticated attacker to execute
# arbitrary OS commands on the Kibana server process.
# Remediation: disable Timelion in kibana.yml. Do NOT upgrade.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget gnupg ca-certificates \
        openjdk-11-jre-headless netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Install Elasticsearch 6.5.4
RUN wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.5.4.tar.gz -O /tmp/es.tar.gz && \
    tar xzf /tmp/es.tar.gz -C /opt && \
    mv /opt/elasticsearch-6.5.4 /opt/elasticsearch && \
    rm /tmp/es.tar.gz

# Install Kibana 6.5.4
RUN wget -q https://artifacts.elastic.co/downloads/kibana/kibana-6.5.4-linux-x86_64.tar.gz -O /tmp/kibana.tar.gz && \
    tar xzf /tmp/kibana.tar.gz -C /opt && \
    mv /opt/kibana-6.5.4-linux-x86_64 /opt/kibana && \
    rm /tmp/kibana.tar.gz

# Elasticsearch needs a non-root user
RUN useradd -m -s /bin/bash elastic && \
    chown -R elastic:elastic /opt/elasticsearch /opt/kibana

# Default kibana.yml — Timelion enabled (vulnerable)
RUN echo 'server.host: "0.0.0.0"' >> /opt/kibana/config/kibana.yml && \
    echo 'elasticsearch.url: "http://localhost:9200"' >> /opt/kibana/config/kibana.yml

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 5601

# Start ES and Kibana in the same container
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

CMD ["/opt/entrypoint.sh"]
