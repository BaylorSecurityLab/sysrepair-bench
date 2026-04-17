FROM --platform=linux/amd64 ubuntu:22.04

# Docker seccomp=unconfined (misconfig)
# This container is intentionally seeded to be run without a seccomp profile.
# Run with: docker run --security-opt seccomp=unconfined <image>
# With seccomp disabled all 300+ Linux syscalls are available inside the
# container, removing a critical defence-in-depth layer. Dangerous syscalls
# such as unshare(CLONE_NEWUSER), keyctl, and perf_event_open are unrestricted.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["/bin/bash", "-c", "sleep infinity"]
