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


# The Debian unbound package enables auto-trust-anchor-file
# (/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf) which requires
# /var/lib/unbound/root.key to exist, or unbound refuses to start. The slim image
# ships no root.key and no unbound-anchor, so the daemon would die at boot. Seed
# the well-known ICANN root KSK-2017 trust anchor (DS record) so the resolver
# actually runs hermetically (no internet needed).
RUN mkdir -p /var/lib/unbound && \
    printf '. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n' \
        > /var/lib/unbound/root.key && \
    chown -R unbound:unbound /var/lib/unbound

# Boot wrapper (NOT a bare foreground CMD): start unbound in the BACKGROUND (drop
# `-d`/`-v` so unbound self-daemonizes and is reparented to tini/PID 1), poll
# until :53 answers, then `exec sleep infinity`. Restarting unbound can never
# kill the container. See .preserve-cmd.
RUN cat > /boot.sh <<'EOF'
#!/bin/sh
unbound
i=0
while [ "$i" -lt 30 ]; do
    if dig +short +time=1 +tries=1 @127.0.0.1 local.test A 2>/dev/null | grep -q '10.0.0.1'; then
        break
    fi
    i=$((i+1)); sleep 1
done
exec sleep infinity
EOF
RUN chmod +x /boot.sh


EXPOSE 53/tcp 53/udp

CMD ["/bin/sh", "/boot.sh"]
