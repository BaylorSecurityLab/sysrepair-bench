FROM --platform=linux/amd64 mongo:4.4.29

# MongoDB 4.4.29 enables zlib wire compression by default.
# CVE-2025-14847 (MongoBleed): a malformed zlib-compressed message causes
# the server to disclose adjacent heap memory in its response, leaking
# in-memory data such as credentials, session tokens, and query results
# to an unauthenticated attacker.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Ensure zlib is listed as an accepted compressor (default behaviour retained)
RUN mkdir -p /etc/mongod && \
    printf 'net:\n  compression:\n    compressors: zlib,snappy,zstd\n' \
    > /etc/mongod/mongod.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 27017

CMD ["mongod", "--config", "/etc/mongod/mongod.conf", "--bind_ip_all"]
