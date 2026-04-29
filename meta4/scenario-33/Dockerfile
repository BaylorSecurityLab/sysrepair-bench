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
ENTRYPOINT ["dockerd-entrypoint.sh"]
