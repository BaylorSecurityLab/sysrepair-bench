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

# Inject weak KEX algorithms — SHA1-based key exchange methods
# These are the vulnerable configuration lines introduced for this scenario
RUN echo 'KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1' \
    >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
