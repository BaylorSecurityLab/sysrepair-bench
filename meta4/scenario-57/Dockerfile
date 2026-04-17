FROM --platform=linux/amd64 alpine:3.19 AS tools
RUN apk add --no-cache bind-tools curl bash

# Pre-create config files
RUN cat > /tmp/Corefile <<'EOF'
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

RUN mkdir -p /tmp/zones && cat > /tmp/zones/local.test.zone <<'EOF'
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

# Pre-create busybox symlinks in a staging directory
RUN mkdir -p /staging/bin /staging/usr/bin && \
    cp /bin/busybox /staging/bin/busybox && \
    for cmd in sh cat grep sed chmod mkdir echo wc test expr; do \
        ln -s /bin/busybox /staging/bin/$cmd; \
    done && \
    cp /bin/bash /staging/bin/bash && \
    cp /usr/bin/curl /staging/usr/bin/curl && \
    cp /usr/bin/dig /staging/usr/bin/dig

FROM --platform=linux/amd64 coredns/coredns:1.11.1

# CoreDNS 1.11.1 serving on 0.0.0.0 with no ACL or rate limiting.
# Any host can query without restriction, enabling DNS amplification
# and reconnaissance against this resolver.

# coredns is a scratch image — bring in a shell, tools, and configs from Alpine
COPY --from=tools /staging/bin/ /bin/
COPY --from=tools /staging/usr/bin/ /usr/bin/
COPY --from=tools /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=tools /usr/lib/libreadline.so* /usr/lib/
COPY --from=tools /usr/lib/libncursesw.so* /usr/lib/
COPY --from=tools /usr/lib/libcurl.so* /usr/lib/
COPY --from=tools /usr/lib/libnghttp2.so* /usr/lib/
COPY --from=tools /usr/lib/libbrotlidec.so* /usr/lib/
COPY --from=tools /usr/lib/libbrotlicommon.so* /usr/lib/
COPY --from=tools /etc/ssl/ /etc/ssl/

# Copy pre-built config files
COPY --from=tools /tmp/Corefile /Corefile
COPY --from=tools /tmp/zones/ /zones/

COPY --chmod=755 verify.sh /opt/verify.sh

EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/coredns"]
CMD ["-conf", "/Corefile"]
