FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install OpenSSH server
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean

# Create SSH run directory
RUN mkdir -p /var/run/sshd

# Create vulnerable users with weak/default credentials (Metasploitable 2 style)
RUN useradd -m -s /bin/bash msfadmin && \
    echo 'msfadmin:msfadmin' | chpasswd && \
    useradd -m -s /bin/bash user && \
    echo 'user:user' | chpasswd && \
    echo 'root:root' | chpasswd

# Ensure password authentication is enabled (the vulnerable condition)
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Allow root login via SSH
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Start SSH daemon in foreground
CMD ["/usr/sbin/sshd", "-D"]
