FROM --platform=linux/amd64 ubuntu:22.04

# Cgroup Escape via CVE-2022-0492 (misconfig)
# This container is intentionally seeded to be run without a seccomp filter
# and without an AppArmor profile, enabling the cgroup notify_on_release escape.
# Run with: docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined <image>
# A container with user-namespace creation rights can mount cgroup and abuse
# notify_on_release to execute commands on the host as root (CVE-2022-0492).

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        util-linux && \
    rm -rf /var/lib/apt/lists/*


CMD ["/bin/bash", "-c", "sleep infinity"]
