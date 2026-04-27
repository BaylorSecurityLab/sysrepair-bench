FROM --platform=linux/amd64 ubuntu:22.04

# OpenSSH 9.5 — Terrapin prefix-truncation attack (CVE-2023-48795).
# The sshd_config explicitly enables ChaCha20-Poly1305 and CBC+EtM MACs,
# which are vulnerable to the Terrapin attack allowing prefix truncation
# of SSH handshake messages.

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server curl && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd && \
    echo 'root:root' | chpasswd

# Seed vulnerable ciphers and MACs in sshd_config
RUN printf '\n# Vulnerable configuration for Terrapin (CVE-2023-48795)\n\
Ciphers chacha20-poly1305@openssh.com,aes128-cbc,aes256-cbc,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\n\
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\n\
PermitRootLogin yes\n' >> /etc/ssh/sshd_config


EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
