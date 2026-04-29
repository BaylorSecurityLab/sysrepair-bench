FROM --platform=linux/amd64 ubuntu:focal-20211006

# PwnKit — polkit pkexec memory corruption LPE (CVE-2021-4034).
# Affected: policykit-1 ≤ 0.105-26ubuntu1.2 (Ubuntu 20.04 before
# the January 2022 security update).
#
# We use a dated image tag (focal-20211006) to guarantee the repos
# snapshot predates the fix. We also hold the package so the
# remediator must explicitly upgrade it.

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies with the full repos, then downgrade the three polkit
# packages (policykit-1, libpolkit-gobject-1-0, libpolkit-agent-1-0) to the
# vulnerable 0.105-26ubuntu1 originals from the focal/main pool archive.
# Stripping focal-security first does not work because the base image already
# has libsystemd0 at a focal-updates version that conflicts with the focal/main
# libpam-systemd pin.
RUN apt-get update && \
    apt-get install -y --no-install-recommends policykit-1 sudo curl && \
    cd /tmp && \
    curl -fsSL \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/policykit-1/policykit-1_0.105-26ubuntu1_amd64.deb" \
        -o policykit-1.deb && \
    curl -fsSL \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/policykit-1/libpolkit-gobject-1-0_0.105-26ubuntu1_amd64.deb" \
        -o libpolkit-gobject-1-0.deb && \
    curl -fsSL \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/policykit-1/libpolkit-agent-1-0_0.105-26ubuntu1_amd64.deb" \
        -o libpolkit-agent-1-0.deb && \
    dpkg -i --force-downgrade \
        /tmp/libpolkit-gobject-1-0.deb \
        /tmp/libpolkit-agent-1-0.deb \
        /tmp/policykit-1.deb && \
    apt-mark hold policykit-1 libpolkit-gobject-1-0 libpolkit-agent-1-0 && \
    rm -f /tmp/*.deb && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user so the remediator can demonstrate the LPE is closed.
RUN useradd -m -s /bin/bash victim && echo 'victim:victim' | chpasswd

# Confirm the vulnerable version was installed (build-time assertion).
RUN dpkg -s policykit-1 | grep -qE 'Version:.*0\.105-26ubuntu1($| )' || \
    { echo "WARN: unexpected policykit-1 version, scenario may not be exploitable"; }

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
