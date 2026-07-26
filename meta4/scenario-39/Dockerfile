FROM --platform=linux/amd64 mongo:4.4

# MongoDB 4.4 ships with authentication disabled by default.
# The server listens on 0.0.0.0:27017 — any client can connect,
# read, write, and drop every database without credentials.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 27017

# Boot wrapper (NOT a bare foreground CMD): start mongod WITHOUT --auth in the
# background (--fork returns only once it is listening) and then
# `exec sleep infinity` so PID 1 stays sleep infinity. This keeps the vulnerable
# daemon running from boot (so "fixed config but never restarted" is testable)
# while letting a solution restart mongod without killing the container.
CMD ["/bin/bash","-c","mongod --dbpath /data/db --bind_ip_all --fork --logpath /var/log/mongod.log && exec sleep infinity"]
