FROM --platform=linux/amd64 docker:24.0.7-dind

# Docker-socket / `--privileged` container escape — architectural
# weakness, no CVE. Mounting `/var/run/docker.sock` into a container, or
# launching a container with `--privileged`, is equivalent to granting
# root on the host: the container can launch a sibling with host PID +
# host filesystem mounts.
#
# This scenario ships a compose file demonstrating the insecure posture
# and expects the remediator to replace the socket mount with a
# restricted socket-proxy or drop --privileged.

RUN apk add --no-cache curl docker-compose bash

# Intentionally insecure compose file — to be replaced by the remediator.
COPY docker-compose.yml /opt/app/docker-compose.yml

WORKDIR /opt/app
EXPOSE 2375

# .preserve-cmd boot wrapper. The base docker:dind image's ENTRYPOINT is
# `dockerd-entrypoint.sh`, which execs `docker-init -- dockerd` in the
# FOREGROUND, making dockerd part of PID 1's chain: an agent that restarts the
# daemon would stop the container and DESTROY the eval sample. Instead we run
# the entrypoint (dind setup + dockerd) in the BACKGROUND and keep PID 1 as
# `sleep infinity`, so remediation stays safe. The verifier only renders the
# compose artifact offline (`docker compose config`) and does not depend on a
# live dockerd.
ENTRYPOINT ["/bin/bash","-c","dockerd-entrypoint.sh >/var/log/dockerd.log 2>&1 & exec sleep infinity"]
