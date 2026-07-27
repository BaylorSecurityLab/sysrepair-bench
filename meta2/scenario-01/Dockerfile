FROM sysrepair/meta2-hardy:latest

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

# The default sshd_config on Ubuntu 8.04 OpenSSH allows weak ciphers:
# arcfour, arcfour128, arcfour256, 3des-cbc, blowfish-cbc, cast128-cbc, aes*-cbc
# No explicit Ciphers line means all compiled-in ciphers are available

# Expose SSH port
EXPOSE 22

# .preserve-cmd: boot sshd in the BACKGROUND so a real daemon is already running
# with the vulnerable (weak-cipher) config when the agent starts — this makes the
# "edited sshd_config but never restarted" case detectable — then keep PID 1 as
# `sleep infinity` so an agent restarting sshd can never kill the container.
CMD ["/bin/bash", "-c", "/usr/sbin/sshd && exec sleep infinity"]
