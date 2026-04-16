FROM --platform=linux/amd64 ubuntu:focal-20210119

# Baron Samedit — sudo heap overflow (CVE-2021-3156).
# Affected: sudo 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1.
#
# Image tag focal-20210119 predates the sudo security update
# (USN-4705-1, 2021-01-26). We hold the package to prevent
# auto-upgrade masking the vulnerability.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends sudo && \
    apt-mark hold sudo && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim && echo 'victim:victim' | chpasswd

# Build-time version check.
RUN sudo_ver=$(sudo -V 2>/dev/null | awk '/^Sudo version/{print $3; exit}') && \
    echo "Installed sudo: $sudo_ver" && \
    case "$sudo_ver" in 1.8.*|1.9.[0-4]*|1.9.5|1.9.5p1) ;; *) \
    echo "WARN: sudo $sudo_ver may be post-fix"; esac

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
