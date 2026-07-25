FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server (sshpass pre-baked so verify.sh skips its runtime install)
RUN apt-get update && \
    apt-get install -y openssh-server passwd sshpass && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Enable X11 forwarding (VULNERABLE)
RUN sed -i 's/^#*X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config && \
    grep -q '^X11Forwarding' /etc/ssh/sshd_config || echo "X11Forwarding yes" >> /etc/ssh/sshd_config

# Set high MaxAuthTries (VULNERABLE - allows brute force)
RUN sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 30/' /etc/ssh/sshd_config && \
    grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo "MaxAuthTries 30" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it.
#   1. sshd must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live daemon vulnerable and verify.sh fails.
#   2. PID 1 must NOT be sshd - restarting the service would otherwise kill the
#      container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
