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


EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/coredns"]
CMD ["-conf", "/Corefile"]
