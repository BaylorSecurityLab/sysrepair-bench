FROM --platform=linux/amd64 memcached:1.6.17

# Memcached 1.6.17 started with the default command listens on UDP port 11211,
# enabling a ~50,000x DDoS amplification attack (CVE-2018-1000115 / CWE-406).
# The vulnerable state: UDP enabled, listening on all interfaces.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        netcat-openbsd \
        && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 11211/tcp
EXPOSE 11211/udp

# Vulnerable default: UDP port open, all interfaces
CMD ["memcached", "-u", "memcache"]
