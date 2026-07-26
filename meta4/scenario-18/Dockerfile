FROM --platform=linux/amd64 ubuntu:focal-20210119

# Baron Samedit — sudo heap overflow (CVE-2021-3156).
# Affected: sudo 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1.
#
# The image tag focal-20210119 predates USN-4705-1 (2021-01-26), BUT the base
# image's apt sources point at the LIVE archive.ubuntu.com, so a plain
# `apt-get install sudo` pulls the already-PATCHED focal release
# (1.8.31-1ubuntu1.5) and the scenario shipped not-vulnerable. We therefore
# explicitly downgrade to the original focal-release sudo (1.8.31-1ubuntu1,
# pre-USN-4705-1) from the archive pool, sha256-pinned for a hermetic build,
# and hold it so it cannot auto-upgrade. This mirrors scenario-17's polkit
# downgrade and makes CVE-2021-3156 genuinely present.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends sudo curl ca-certificates && \
    cd /tmp && \
    curl -fsSL \
        "http://archive.ubuntu.com/ubuntu/pool/main/s/sudo/sudo_1.8.31-1ubuntu1_amd64.deb" \
        -o sudo.deb && \
    echo "de4106cd19a5b9f8acac9e0ab5f40f218d3ac321cc58143e051baab064a5fb36  sudo.deb" | sha256sum -c - && \
    dpkg -i --force-downgrade /tmp/sudo.deb && \
    apt-mark hold sudo && \
    rm -f /tmp/sudo.deb && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim && echo 'victim:victim' | chpasswd

# Build-time assertion: FAIL the build if sudo is not the vulnerable
# pre-USN-4705-1 revision (a hard check, not a WARN, so a not-vulnerable
# scenario can never ship silently again).
RUN dpkg --compare-versions "$(dpkg-query -W -f='${Version}' sudo)" lt "1.8.31-1ubuntu1.2" || \
    { echo "ERROR: sudo $(dpkg-query -W -f='${Version}' sudo) is not the vulnerable pre-fix version"; exit 1; }

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
