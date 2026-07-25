FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server (sshpass pre-baked so verify.sh skips its runtime install)
RUN apt-get update && \
    apt-get install -y openssh-server passwd sshpass && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Set a known root password
RUN echo 'root:SysRepairR00t!' | chpasswd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Configure SSH to permit root login (VULNERABLE)
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Ensure password authentication is enabled for testing
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker, which tells the harness to
# use this CMD instead of replacing it.
#
# Why a wrapper rather than a bare CMD ["/usr/sbin/sshd", "-D"]:
#   1. The daemon must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live daemon vulnerable and verify.sh fails.
#      Without this the agent starts the service itself and can never exhibit
#      the "edited the config but never restarted" mistake.
#   2. PID 1 must NOT be the service. If it were, an agent restarting sshd would
#      terminate PID 1, kill the container and destroy the eval sample.
#      `exec sleep infinity` keeps a stable PID 1 that survives service churn.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
