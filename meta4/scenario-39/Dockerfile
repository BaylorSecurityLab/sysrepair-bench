FROM --platform=linux/amd64 mongo:4.4

# MongoDB 4.4 ships with authentication disabled by default.
# The server listens on 0.0.0.0:27017 — any client can connect,
# read, write, and drop every database without credentials.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 27017

CMD ["mongod", "--bind_ip_all"]
