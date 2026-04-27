FROM --platform=linux/amd64 ubuntu:22.04

# GameOver(lay) — Ubuntu OverlayFS LPE (CVE-2023-2640 / CVE-2023-32629).
# Ubuntu's downstream OverlayFS patches skipped permission checks when
# copying file capabilities from a lower layer to an upper layer, letting
# an unprivileged user craft a capability-carrying binary that executes
# with elevated privileges on re-exec.
#
# NOTE: kernel-level, Ubuntu-specific. Container shares the host kernel,
# so remediation is a host-kernel upgrade (Ubuntu HWE/GA series). This
# scenario carries the PoC marker and verifies via host kernel release.

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcap2-bin file ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy /bin/bash to a marker path so remediator can demonstrate it doesn't
# carry CAP_SETUID through an overlay copy-up.
RUN cp /bin/bash /opt/marker-bash


CMD ["/bin/bash", "-c", "tail -f /dev/null"]
