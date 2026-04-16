FROM --platform=linux/amd64 ubuntu:focal-20211006

# PwnKit — polkit pkexec memory corruption LPE (CVE-2021-4034).
# Affected: policykit-1 ≤ 0.105-26ubuntu1.2 (Ubuntu 20.04 before
# the January 2022 security update).
#
# We use a dated image tag (focal-20211006) to guarantee the repos
# snapshot predates the fix. We also hold the package so the
# remediator must explicitly upgrade it.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends policykit-1 sudo && \
    apt-mark hold policykit-1 && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user so the remediator can demonstrate the LPE is closed.
RUN useradd -m -s /bin/bash victim && echo 'victim:victim' | chpasswd

# Confirm the vulnerable version was installed (build-time assertion).
RUN dpkg -s policykit-1 | grep -qE 'Version:.*0\.105-26ubuntu1($| )' || \
    { echo "WARN: unexpected policykit-1 version, scenario may not be exploitable"; }

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
