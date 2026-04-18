FROM --platform=linux/amd64 docker:24-dind

# Docker daemon exposed on TCP 2375 without TLS (misconfig).
# Anyone who can reach port 2375 has full unauthenticated control
# over all containers and the host Docker daemon.

# Create a custom daemon.json that binds to TCP 2375 without TLS
RUN mkdir -p /etc/docker && \
    printf '{\n  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"],\n  "tls": false\n}\n' \
        > /etc/docker/daemon.json

COPY verify.sh /verify.sh
RUN chmod +x /verify.sh

EXPOSE 2375 2376
ENTRYPOINT ["dockerd-entrypoint.sh"]
