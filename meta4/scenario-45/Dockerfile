# InfluxDB 1.7.5 with an empty JWT shared-secret (CVE-2019-20933).
#
# DESIGN NOTE: CVE-2019-20933 affects InfluxDB *before* 1.7.6 - the fix landed
# in 1.7.6. The original scenario shipped influxdb:1.7.6, which is the PATCHED
# release: a forged empty-key JWT is refused with HTTP 401 ("bearer auth
# disabld") even with a matching account, so the vulnerability was NOT present.
# This image therefore pins the last vulnerable release, 1.7.5, by digest for a
# hermetic build.
#
# When shared-secret is empty (""), 1.7.5's JWT validation accepts any token
# whose HMAC-SHA256 signature was computed with an empty key, letting an
# attacker forge a valid bearer token for an existing account (e.g. admin) and
# gain full API access. The forged token only works if the claimed user
# actually exists, so the boot wrapper creates the `admin` account.
FROM --platform=linux/amd64 influxdb@sha256:7b140d300ba79b7813446281336da108657c3b4c8f27cf0a0527058d2bf639f5

USER root

# influxdb 1.7.5 is Debian stretch (EOL) - redirect to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /stretch-updates/d' /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true update && \
    apt-get install -y --allow-unauthenticated --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# [http] section: auth-enabled with an empty shared-secret (VULNERABLE).
# NOTE: InfluxDB config is TOML - path values MUST be quoted or influxd aborts
# at boot with "expected value but found '/'". (The original scenario shipped
# unquoted paths, so the daemon never started at all.)
RUN mkdir -p /etc/influxdb && \
    printf '[meta]\n  dir = "/var/lib/influxdb/meta"\n\n[data]\n  dir = "/var/lib/influxdb/data"\n  wal-dir = "/var/lib/influxdb/wal"\n\n[http]\n  enabled = true\n  bind-address = ":8086"\n  auth-enabled = true\n  shared-secret = ""\n' \
    > /etc/influxdb/influxdb.conf

EXPOSE 8086

# Boot wrapper (paired with the .preserve-cmd marker):
#   1. start influxd in the background with the vulnerable config;
#   2. wait for the HTTP API (/ping -> 204);
#   3. create the `admin` account the forged JWT targets (auth-enabled with no
#      users yet permits the unauthenticated bootstrap CREATE USER). /var/lib/
#      influxdb is a VOLUME, so this must happen at boot, not build time;
#   4. exec `sleep infinity` so PID 1 survives an influxd restart.
CMD ["/bin/bash", "-c", "influxd -config /etc/influxdb/influxdb.conf & for i in $(seq 1 60); do [ \"$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8086/ping 2>/dev/null)\" = 204 ] && break; sleep 1; done; curl -s -o /dev/null 'http://localhost:8086/query' --data-urlencode \"q=CREATE USER admin WITH PASSWORD 'S3cureInflux!' WITH ALL PRIVILEGES\" || true; exec sleep infinity"]
