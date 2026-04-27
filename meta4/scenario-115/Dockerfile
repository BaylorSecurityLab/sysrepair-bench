FROM --platform=linux/amd64 solr:8.8

# Apache Solr 8.8 — DataImportHandler RCE (CVE-2019-0193 / CWE-94 / CVSS 7.5).
# DIH is enabled with no authentication; attacker-controlled dataConfig parameter
# can be used to execute arbitrary Java code on the server.
# Vulnerable state: DIH enabled, no auth, no access controls.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        && \
    rm -rf /var/lib/apt/lists/*

# Create a Solr core with DIH enabled (vulnerable configuration)
# We use an init script that runs after Solr starts
COPY create-core.sh /docker-entrypoint-initdb.d/create-core.sh
RUN chmod +x /docker-entrypoint-initdb.d/create-core.sh


EXPOSE 8983

USER solr
