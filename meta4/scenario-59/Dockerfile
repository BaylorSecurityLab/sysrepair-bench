FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unbound unbound-host dnsutils curl netcat-openbsd iproute2 && \
    rm -rf /var/lib/apt/lists/*

RUN cat > /etc/unbound/unbound.conf.d/open-resolver.conf <<'EOF'
server:
    interface: 0.0.0.0
    port: 53
    access-control: 0.0.0.0/0 allow
    access-control: ::/0 allow
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    hide-identity: no
    hide-version: no
    forward-zone:
        name: "."
        forward-addr: 1.1.1.1
        forward-addr: 8.8.8.8
EOF

RUN cat > /etc/unbound/unbound.conf.d/local-zone.conf <<'EOF'
server:
    local-zone: "local.test." static
    local-data: "local.test. IN A 10.0.0.1"
    local-data: "app.local.test. IN A 10.0.0.2"
EOF

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 53/tcp 53/udp

CMD ["unbound", "-d", "-v"]
