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


EXPOSE 11211/tcp
EXPOSE 11211/udp

# Vulnerable state: UDP listener EXPLICITLY enabled (-U 11211). memcached 1.6.x
# ships with UDP OFF by default (-U 0), so the bare `memcached -u memcache`
# command is NOT vulnerable — the amplification port must be turned on to
# recreate CVE-2018-1000115.
# Boot wrapper (paired with .preserve-cmd): start memcached in the BACKGROUND
# then exec `sleep infinity` so PID 1 is the sleep and restarting memcached
# cannot kill the container, which makes the "fixed but not restarted" case
# detectable. NOT a bare foreground CMD.
CMD ["/bin/bash","-c","memcached -u memcache -l 0.0.0.0 -p 11211 -U 11211 & exec sleep infinity"]
