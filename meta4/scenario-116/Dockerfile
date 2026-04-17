FROM --platform=linux/amd64 debian:bookworm-slim

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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 873

CMD ["rsync", "--daemon", "--no-detach", "--config=/etc/rsyncd.conf"]
