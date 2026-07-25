FROM ubuntu:25.10
# Scenario 05: SSH password auth with no key restriction
# CWE-308: Use of Single-factor Authentication


RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vulnerable SSH configuration - password-only auth, no key enforcement
RUN mkdir -p /run/sshd && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config && \
    grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication no' >> /etc/ssh/sshd_config && \
    echo 'UsePAM yes' >> /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:admin' | chpasswd


EXPOSE 22

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it.
#   1. sshd must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live daemon vulnerable and verify.sh fails.
#   2. PID 1 must NOT be sshd - restarting the service would otherwise kill the
#      container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
