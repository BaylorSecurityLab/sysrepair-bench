FROM --platform=linux/amd64 docker:24.0.7-dind

# Leaky Vessels — runc 1.1.11 file-descriptor leak → host filesystem
# escape (CVE-2024-21626). The bundled runc leaks an open directory fd
# from the container init process; by setting WORKDIR (or processCwd) to
# `/proc/self/fd/N`, a child process inside the container ends up with a
# cwd rooted on the host filesystem, allowing writes to / arbitrary
# paths.
#
# This image pins `runc` to 1.1.11 inside a Docker-in-Docker host so the
# remediator must either upgrade runc or apply the AppArmor / seccomp
# compensating control documented in the threat file.

RUN set -eux; \
    apk add --no-cache curl bash; \
    curl -fsSL -o /usr/local/bin/runc.vulnerable https://github.com/opencontainers/runc/releases/download/v1.1.11/runc.amd64; \
    chmod +x /usr/local/bin/runc.vulnerable; \
    cp /usr/local/bin/runc.vulnerable /usr/local/bin/runc

EXPOSE 2375 2376
