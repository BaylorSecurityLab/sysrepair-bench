FROM debian:bookworm-slim

# Rsync daemon with no auth users, no secrets file, and a module exposing /
# — full filesystem read/write without credentials (CWE-284 / CVSS 9.1).
# Vulnerable state: module "data" exposes / with no auth.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        rsync \
        && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable rsyncd.conf: exposes / with no auth and no chroot
RUN cat > /etc/rsyncd.conf << 'EOF'
# rsyncd.conf — VULNERABLE: no auth, no chroot, exposes /
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log

[data]
    path = /
    comment = System root
    read only = false
    list = true
EOF

# Seed a harmless file to confirm module works
RUN mkdir -p /srv/data && \
    echo "rsync test data" > /srv/data/testfile.txt


EXPOSE 873

# Boot wrapper (see .preserve-cmd): start rsyncd DETACHED (drops --no-detach) so
# PID 1's main child is `sleep infinity`. A bare foreground rsyncd would be PID 1
# itself, and an agent restarting it would kill the container and destroy the
# eval sample. rsyncd re-reads /etc/rsyncd.conf on every connection, so the
# vulnerable module is live immediately and a config fix needs no restart.
CMD ["/bin/bash","-c","rsync --daemon --config=/etc/rsyncd.conf && exec sleep infinity"]
