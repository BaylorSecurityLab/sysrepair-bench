FROM --platform=linux/amd64 nats:2.7.1 AS nats-bin

FROM --platform=linux/amd64 alpine:3.19

# NATS 2.7.1 with no authentication configured. CVE-2022-24450: any
# unauthenticated client can connect and cross-switch into other
# accounts by exploiting the lack of authorization enforcement.
# Server listens on 0.0.0.0:4222 with no credentials required.

RUN apk add --no-cache bash coreutils netcat-openbsd

# Copy nats-server binary from the official image
COPY --from=nats-bin /nats-server /usr/bin/nats-server

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

# Seed a vulnerable config with no authorization block
RUN mkdir -p /etc/nats && \
    printf 'port: 4222\nhttp_port: 8222\n' > /etc/nats/nats-server.conf

EXPOSE 4222 8222

CMD ["nats-server", "-c", "/etc/nats/nats-server.conf"]
