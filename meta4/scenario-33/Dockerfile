FROM --platform=linux/amd64 docker:24-dind

# Docker daemon exposed on TCP 2375 without TLS (misconfig).
# Anyone who can reach port 2375 has full unauthenticated control
# over all containers and the host Docker daemon.

# Create a custom daemon.json that disables TLS. The `hosts` list is
# omitted here because dockerd-entrypoint.sh injects -H flags itself;
# declaring hosts in both the config file and via flag makes dockerd
# refuse to start. Instead, DOCKER_TLS_CERTDIR="" switches the
# entrypoint into the insecure `tcp://0.0.0.0:2375` mode.
RUN mkdir -p /etc/docker && \
    printf '{\n  "tls": false\n}\n' \
        > /etc/docker/daemon.json

ENV DOCKER_TLS_CERTDIR=""

RUN apk add --no-cache bash curl


EXPOSE 2375 2376
# .preserve-cmd boot wrapper. The stock dind entrypoint execs
# `docker-init -- dockerd` in the FOREGROUND, making dockerd part of PID 1's
# chain: killing it to restart would stop the container and destroy the eval
# sample. Instead we run the entrypoint (which performs the dind setup and
# binds tcp://0.0.0.0:2375) in the BACKGROUND and keep PID 1 as `sleep
# infinity`, so a remediation can restart dockerd safely.
ENTRYPOINT ["/bin/bash","-c","dockerd-entrypoint.sh >/var/log/dockerd.log 2>&1 & exec sleep infinity"]
