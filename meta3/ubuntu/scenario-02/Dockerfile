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

# Generate a DSA host key (weak, deprecated algorithm) and offer it. On
# OpenSSH 6.6.1 the `HostKeyAlgorithms` keyword is a client-only option and is
# rejected by sshd (added to sshd_config in 7.0) -- adding it here would make
# sshd refuse to start. The real, exploitable weakness is that a DSA host key
# exists and is served, so we only add the HostKey line.
RUN rm -f /etc/ssh/ssh_host_dsa_key && ssh-keygen -t dsa -N '' -f /etc/ssh/ssh_host_dsa_key
RUN echo 'HostKey /etc/ssh/ssh_host_dsa_key' >> /etc/ssh/sshd_config

EXPOSE 22

# Boot sshd (already offering the weak DSA host key) then keep PID 1 as
# `sleep infinity` so restarting sshd cannot kill the container. See .preserve-cmd.
CMD ["/bin/bash", "-c", "mkdir -p /var/run/sshd && /usr/sbin/sshd && exec sleep infinity"]
