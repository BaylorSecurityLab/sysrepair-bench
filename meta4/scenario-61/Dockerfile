FROM --platform=linux/amd64 debian:bullseye-slim

# Exim 4.96 advertises CHUNKING and PIPELINING by default, enabling SMTP
# smuggling attacks (CVE-2023-51766) that can bypass SPF/DKIM checks.

RUN apt-get update && \
    apt-get install -y --no-install-recommends exim4 curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 25

# Boot wrapper (see .preserve-cmd): start the Exim daemon in the BACKGROUND
# (`exim4 -bd` daemonizes; drop the foreground `-bdf`) then exec `sleep infinity`
# so PID 1 is the wrapper. The vulnerable SMTP service (advertising CHUNKING) is
# already listening on :25, and restarting Exim cannot kill the container.
CMD ["/bin/bash", "-c", "exim4 -bd -q30m && exec sleep infinity"]
