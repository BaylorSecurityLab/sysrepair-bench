FROM --platform=linux/amd64 nats:2.7.1 AS nats-bin

FROM --platform=linux/amd64 alpine:3.19

# NATS 2.7.1 with no authentication configured. CVE-2022-24450: any
# unauthenticated client can connect and cross-switch into other
# accounts by exploiting the lack of authorization enforcement.
# Server listens on 0.0.0.0:4222 with no credentials required.

RUN apk add --no-cache bash coreutils netcat-openbsd

# Copy nats-server binary from the official image
COPY --from=nats-bin /nats-server /usr/bin/nats-server


# Seed a vulnerable config with no authorization block
RUN mkdir -p /etc/nats && \
    printf 'port: 4222\nhttp_port: 8222\n' > /etc/nats/nats-server.conf

EXPOSE 4222 8222

# Boot wrapper: start nats-server backgrounded, poll for :4222, then exec
# `sleep infinity` so PID 1 is stable and an agent restarting nats-server cannot
# kill the container. See .preserve-cmd.
CMD ["/bin/bash", "-c", "nats-server -c /etc/nats/nats-server.conf & for i in $(seq 1 30); do nc -z 127.0.0.1 4222 && break; sleep 1; done; exec sleep infinity"]
