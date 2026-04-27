FROM --platform=linux/amd64 mongo:4.4

# MongoDB 4.4 enables zlib wire compression by default.
# Misconfiguration: zlib wire-protocol compression can amplify BSON payloads
# and, when combined with unauthenticated access, may leak internal memory
# contents through compression side-channels. Disabling zlib is a required
# hardening step for any internet-facing MongoDB deployment.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Ensure zlib is listed as an accepted compressor (default behaviour retained)
RUN mkdir -p /etc/mongod && \
    printf 'net:\n  compression:\n    compressors: zlib,snappy,zstd\n' \
    > /etc/mongod/mongod.conf


EXPOSE 27017

CMD ["mongod", "--config", "/etc/mongod/mongod.conf", "--bind_ip_all"]
