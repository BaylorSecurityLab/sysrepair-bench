FROM --platform=linux/amd64 coredns/coredns:1.11.1 AS coredns-bin

FROM --platform=linux/amd64 alpine:3.19

# CoreDNS 1.11.1 serving on 0.0.0.0 with no ACL or rate limiting.
# Any host can query without restriction, enabling DNS amplification
# and reconnaissance against this resolver.

RUN apk add --no-cache bash coreutils bind-tools curl

# Copy coredns binary from the official image
COPY --from=coredns-bin /coredns /coredns

# Seed a Corefile with no ACL or ratelimit — open to all
RUN cat > /Corefile <<'EOF'
local.test {
    file /zones/local.test.zone
    log
    errors
}

. {
    forward . 1.1.1.1 8.8.8.8
    cache
    log
    errors
}
EOF

# Seed zone file for local.test
RUN mkdir -p /zones && cat > /zones/local.test.zone <<'EOF'
$TTL 300
$ORIGIN local.test.
@   IN  SOA ns1 admin (
            2024010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            300 )      ; minimum TTL
    IN  NS  ns1
ns1 IN  A   10.0.0.1
@   IN  A   10.0.0.1
app IN  A   10.0.0.2
EOF


# Boot wrapper (NOT a bare foreground CMD): the base image's ENTRYPOINT is
# ["/coredns"], which would make CoreDNS PID 1 - restarting it to reload the
# Corefile would then kill the container and destroy the eval sample. Clear the
# ENTRYPOINT and start CoreDNS in the BACKGROUND inside a subshell so it is
# reparented to tini/PID 1 (which reaps it, making a clean restart possible),
# poll until :53 answers, then `exec sleep infinity`. See .preserve-cmd.
RUN cat > /boot.sh <<'EOF'
#!/bin/sh
( /coredns -conf /Corefile >/var/log/coredns.log 2>&1 & )
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

ENTRYPOINT []
CMD ["/bin/sh", "/boot.sh"]
