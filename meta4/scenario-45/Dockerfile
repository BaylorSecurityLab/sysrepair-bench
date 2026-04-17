FROM --platform=linux/amd64 influxdb:1.7.6

# InfluxDB 1.7.6 with an empty JWT shared-secret.
# CVE-2019-20933: when shared-secret is empty (""), the JWT validation code
# accepts any token regardless of its signature, allowing an attacker to forge
# a valid bearer token for any username including admin accounts.

USER root

# influxdb:1.7.6 is Debian stretch (EOL) — redirect to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /stretch-updates/d' /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true update && \
    apt-get install -y --allow-unauthenticated --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Ensure [http] section has auth-enabled and an empty shared-secret
RUN mkdir -p /etc/influxdb && \
    printf '[meta]\n  dir = /var/lib/influxdb/meta\n\n[data]\n  dir = /var/lib/influxdb/data\n  wal-dir = /var/lib/influxdb/wal\n\n[http]\n  enabled = true\n  bind-address = ":8086"\n  auth-enabled = true\n  shared-secret = ""\n' \
    > /etc/influxdb/influxdb.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 8086

CMD ["influxd", "-config", "/etc/influxdb/influxdb.conf"]
