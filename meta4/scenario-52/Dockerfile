FROM --platform=linux/amd64 nats:2.7.1

# NATS 2.7.1 with no authentication configured. CVE-2022-24450: any
# unauthenticated client can connect and cross-switch into other
# accounts by exploiting the lack of authorization enforcement.
# Server listens on 0.0.0.0:4222 with no credentials required.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

# Seed a vulnerable config with no authorization block
RUN mkdir -p /etc/nats && \
    printf 'port: 4222\nhttp_port: 8222\n' > /etc/nats/nats-server.conf

EXPOSE 4222 8222

CMD ["nats-server", "-c", "/etc/nats/nats-server.conf"]
