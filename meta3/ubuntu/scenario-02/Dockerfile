FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs to old-releases.ubuntu.com
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

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

# Generate a DSA host key (weak, deprecated algorithm)
RUN ssh-keygen -t dsa -N '' -f /etc/ssh/ssh_host_dsa_key

# Inject weak host key algorithms — advertises ssh-rsa (SHA-1 based) and ssh-dss (DSA)
RUN echo 'HostKeyAlgorithms +ssh-rsa,ssh-dss' >> /etc/ssh/sshd_config
RUN echo 'HostKey /etc/ssh/ssh_host_dsa_key' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
