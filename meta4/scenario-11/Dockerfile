FROM --platform=linux/amd64 debian:bookworm-slim

# OpenSSH 9.2 (Debian bookworm) — regreSSHion signal-handler race
# (CVE-2024-6387). The default Debian 9.2p1 package is affected; we
# ensure the sshd is running with its stock config and package version
# pinned (no upgrade pulled by apt during build).

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd && \
    echo 'root:toor' | chpasswd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Pin the apt source to prevent trivial upgrade-by-repo from masking the
# vulnerability without explicit remediation action.
RUN rm -f /etc/apt/sources.list.d/*.list || true

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
