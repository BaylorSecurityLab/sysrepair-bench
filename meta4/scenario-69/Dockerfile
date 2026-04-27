FROM --platform=linux/amd64 ubuntu:22.04

# CAP_SYS_PTRACE Process Injection (misconfig)
# This container is intentionally seeded to be run with CAP_SYS_PTRACE added.
# Run with: docker run --cap-add SYS_PTRACE <image>
# That flag grants the SYS_PTRACE capability, allowing the container to ptrace
# host-visible PIDs, enabling process injection and potential container escape.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps \
        libcap2-bin && \
    rm -rf /var/lib/apt/lists/*


CMD ["/bin/bash", "-c", "sleep infinity"]
