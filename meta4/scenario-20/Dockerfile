FROM --platform=linux/amd64 ubuntu:jammy-20230816

# Looney Tunables — glibc GLIBC_TUNABLES buffer overflow (CVE-2023-4911).
# Affected: glibc 2.34–2.37 (Ubuntu 22.04 libc6 < 2.35-0ubuntu3.4).
#
# Image tag jammy-20230816 predates the October 2023 security update.
# We hold libc6 so the remediator must explicitly unhold + upgrade.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends sudo ca-certificates && \
    apt-mark hold libc6 libc-bin && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim && echo 'victim:victim' | chpasswd

# Build-time assertion.
RUN libc_ver=$(dpkg-query -W -f='${Version}' libc6) && \
    echo "Installed libc6: $libc_ver" && \
    dpkg --compare-versions "$libc_ver" lt "2.35-0ubuntu3.4" || \
    echo "WARN: libc6 $libc_ver may already be patched"

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
