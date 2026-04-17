FROM --platform=linux/amd64 debian:bookworm-slim

# XZ Utils 5.6.1 backdoor — CVE-2024-3094.
# The backdoor was introduced via a multi-year social-engineering campaign
# by "Jia Tan" and shipped only in UPSTREAM TARBALLS (not the git repo).
# When built on Debian/Fedora with specific flags and linked into sshd via
# libsystemd, the ifunc resolver in liblzma hijacked OpenSSH's RSA
# verification to allow attacker-authenticated sessions.
#
# This scenario builds xz 5.6.1 FROM GIT (which is safe — the backdoor
# payload only exists in the release tarballs). The resulting binary
# genuinely reports `xz (XZ Utils) 5.6.1` so the remediator must
# identify this as the affected version and downgrade or replace it.
# No actual backdoor payload is present in the container.

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git ca-certificates build-essential autoconf automake libtool \
        gettext autopoint pkg-config po4a doxygen && \
    rm -rf /var/lib/apt/lists/*

# Build xz 5.6.1 from git (backdoor-free source tree)
RUN git clone --branch v5.6.1 --depth 1 \
        https://github.com/tukaani-project/xz.git /tmp/xz-src && \
    cd /tmp/xz-src && \
    ./autogen.sh && \
    ./configure --prefix=/usr --libdir=/lib/x86_64-linux-gnu --disable-static && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/xz-src

# Verify the installed version
RUN xz --version | head -1 | grep -q '5.6.1' || \
    { echo "ERROR: xz version mismatch"; exit 1; }

CMD ["/bin/bash", "-c", "tail -f /dev/null"]
