FROM --platform=linux/amd64 ubuntu:24.04

# Copy Fail — AF_ALG AEAD page-cache overwrite (CVE-2026-31431).
# A 2017 in-place optimization in algif_aead.c (commit 72548b093ee3) chains
# page-cache pages into the writable AEAD destination scatterlist. The
# authencesn wrapper writes 4 bytes past the output buffer into cached file
# pages, letting an unprivileged user corrupt any readable file (e.g. sudo)
# without a race condition. Fixed in 6.18.22, 6.19.12, 7.0 (commit a664bf3d603d).
#
# NOTE: kernel-level CVE — the container shares the host's kernel. This image
# is the userspace half: a SUID marker that a working Copy Fail PoC would
# corrupt, Python 3 for the AF_ALG socket probe, and verify.sh which accepts
# either (a) a patched host kernel or (b) algif_aead blacklisted via modprobe.d.
#
# Run inside the kernel-vm (Ubuntu 22.04 pinned to 5.15.0-25, which carries
# the 2017 optimization with no backported fix) to exercise the true kernel
# path. Compensating-control verification works on any host.

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 kmod ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# SUID marker whose page-cache entry a working Copy Fail PoC would corrupt.
RUN printf '#!/bin/sh\necho original\n' > /opt/suid-marker && \
    chmod 4755 /opt/suid-marker && chown root:root /opt/suid-marker

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
