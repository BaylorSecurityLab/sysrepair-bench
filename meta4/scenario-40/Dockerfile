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

# Boot wrapper (NOT a bare foreground CMD): start mongod with the zlib-enabled
# config in the background (--fork returns once it is listening) and then
# `exec sleep infinity`, so PID 1 stays sleep infinity. The vulnerable daemon
# runs from boot (so "edited the config but never restarted mongod" is testable)
# and a solution can restart mongod without killing the container.
CMD ["/bin/bash","-c","mongod --config /etc/mongod/mongod.conf --dbpath /data/db --bind_ip_all --fork --logpath /var/log/mongod.log && exec sleep infinity"]
