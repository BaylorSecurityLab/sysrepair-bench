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

RUN apk add --no-cache curl docker-compose

# Intentionally insecure compose file — to be replaced by the remediator.
COPY docker-compose.yml /opt/app/docker-compose.yml

WORKDIR /opt/app
EXPOSE 2375
