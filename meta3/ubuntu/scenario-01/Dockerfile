FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs to mirrors.kernel.org
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list

# Install OpenSSH server
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean

# Create SSH run directory
RUN mkdir -p /var/run/sshd

# Set root password for SSH access
RUN echo 'root:toor' | chpasswd

# Allow root login via SSH
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Inject weak KEX algorithms — SHA1-based key exchange methods
# These are the vulnerable configuration lines introduced for this scenario
RUN echo 'KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1' \
    >> /etc/ssh/sshd_config

EXPOSE 22

# Boot sshd (with the vulnerable KEX config) then hand PID 1 to `sleep infinity`
# so the daemon is already running when the agent starts AND a restart of sshd
# cannot kill the container. See .preserve-cmd. Do NOT run sshd with -D as a
# bare foreground CMD: that would make sshd PID 1 and any restart would destroy
# the eval sample.
CMD ["/bin/bash", "-c", "mkdir -p /var/run/sshd && /usr/sbin/sshd && exec sleep infinity"]
