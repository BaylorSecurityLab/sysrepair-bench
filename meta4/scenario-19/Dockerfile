FROM --platform=linux/amd64 ubuntu:20.04

# Dirty Pipe — kernel pipe-splice overwrite (CVE-2022-0847).
# Affected kernels: 5.8 through 5.16.10 / 5.15.25 / 5.10.102.
#
# NOTE: kernel-level CVEs cannot be fully virtualized inside a container —
# the container shares the host kernel. This image is the *userspace* half
# of the scenario: it ships a SUID marker file that a working Dirty Pipe
# exploit would overwrite, and a verify script that checks (a) the host
# kernel version reported by `uname -r` is on a fixed release, or (b)
# the compensating control is in place (the marker file's immutable bit
# is set via chattr +i).

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev ca-certificates e2fsprogs && \
    rm -rf /var/lib/apt/lists/*

# SUID marker whose contents a working Dirty Pipe PoC would overwrite
RUN printf '#!/bin/sh\necho original\n' > /opt/suid-marker && \
    chmod 4755 /opt/suid-marker && chown root:root /opt/suid-marker

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
