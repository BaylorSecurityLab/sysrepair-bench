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

# Vendor the FIXED runc 1.1.12 binary (sha256-pinned) into a staging area so the
# remediation is hermetic (no network needed at solve time). The solution copies
# this over /usr/local/bin/runc.
RUN set -eux; \
    curl -fsSL -o /opt/runc-1.1.12 https://github.com/opencontainers/runc/releases/download/v1.1.12/runc.amd64; \
    echo "aadeef400b8f05645768c1476d1023f7875b78f52c7ff1967a6dbce236b8cbd8  /opt/runc-1.1.12" | sha256sum -c -; \
    chmod +x /opt/runc-1.1.12

EXPOSE 2375 2376

# .preserve-cmd boot wrapper. The base docker:dind image's ENTRYPOINT is
# `dockerd-entrypoint.sh`, which execs `docker-init -- dockerd` in the
# FOREGROUND, making dockerd part of PID 1's chain: an agent that restarts the
# daemon would stop the container and DESTROY the eval sample. Instead we run
# the entrypoint (dind setup + dockerd) in the BACKGROUND and keep PID 1 as
# `sleep infinity`, so remediation stays safe. runc itself is not a daemon, so
# the version-gate verifier does not depend on dockerd being up.
ENTRYPOINT ["/bin/bash","-c","dockerd-entrypoint.sh >/var/log/dockerd.log 2>&1 & exec sleep infinity"]
