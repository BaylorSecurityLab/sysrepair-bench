FROM --platform=linux/amd64 debian:bookworm-slim

# OpenSSH regreSSHion — signal-handler race RCE (CVE-2024-6387).
#
# The vulnerability lives in the sshd BINARY (openssh-server 1:9.2p1-2 through
# 1:9.2p1-2+deb12u2). Debian's current bookworm package (1:9.2p1-2+deb12u10)
# already carries the +deb12u3 security fix, so installing from the live repo
# would ship a NON-vulnerable image. To recreate the CVE we install the stock
# vulnerable openssh-server 1:9.2p1-2 from a pinned, vendored .deb.
#
# Vendored, sha256-pinned .debs (from snapshot.debian.org, first_seen
# 2023-02-08) are committed to the build context so the build is hermetic.

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server ca-certificates procps && \
    rm -rf /var/lib/apt/lists/*

# Downgrade the openssh stack to the vulnerable 1:9.2p1-2 (openssh-server pins
# an exact-version dep on openssh-client and openssh-sftp-server, so all three
# must be downgraded together). Other deps are already satisfied above.
COPY openssh-server_9.2p1-2_amd64.deb /tmp/oss.deb
COPY openssh-sftp-server_9.2p1-2_amd64.deb /tmp/osftp.deb
COPY openssh-client_9.2p1-2_amd64.deb /tmp/oclient.deb
RUN printf '%s  %s\n' \
      20683093fdca3a7ba991f86225f4536995d3abdf900bbd720fd80167db1ddfe4 /tmp/oss.deb \
      778aa59441ff2396b95e7b204c8f1cd1598ff142ac2efbff7137088e4ad8f3df /tmp/osftp.deb \
      4ef0c0739c3028c75b5f8463c31cd7ff9ce79b9587abd4969fc6979d78c4edd4 /tmp/oclient.deb \
      | sha256sum -c - && \
    dpkg -i --force-downgrade /tmp/oclient.deb /tmp/osftp.deb /tmp/oss.deb && \
    rm -f /tmp/oss.deb /tmp/osftp.deb /tmp/oclient.deb && \
    apt-mark hold openssh-server openssh-sftp-server openssh-client && \
    mkdir -p /run/sshd && \
    echo 'root:toor' | chpasswd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Remove apt sources so the vulnerability cannot be masked by a trivial repo
# upgrade — the intended remediation is the LoginGraceTime 0 compensating
# control, which closes the SIGALRM race window.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true

EXPOSE 22
# Boot wrapper (paired with .preserve-cmd): start sshd in the BACKGROUND then
# exec `sleep infinity`, so PID 1 is the sleep (restarting sshd cannot kill the
# container) and the "fixed config but never restarted" case is detectable.
CMD ["/bin/bash","-c","/usr/sbin/sshd && exec sleep infinity"]
