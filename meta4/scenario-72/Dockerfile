FROM --platform=linux/amd64 ubuntu:22.04

# Docker AppArmor=unconfined (misconfig)
# This container is intentionally seeded to be run without an AppArmor profile.
# Run with: docker run --security-opt apparmor=unconfined <image>
# Without an AppArmor profile there is no MAC (Mandatory Access Control)
# enforcement — the container can perform operations the docker-default profile
# would deny, such as mounting filesystems and writing to /proc paths.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps && \
    rm -rf /var/lib/apt/lists/*


CMD ["/bin/bash", "-c", "sleep infinity"]
