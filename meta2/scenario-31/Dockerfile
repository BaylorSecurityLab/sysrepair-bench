FROM navig/ubuntu:8.04

# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install rlogin server (rsh-server) and SSH as secure alternative
RUN apt-get update && \
    apt-get install -y rsh-server xinetd openssh-server

# Configure passwordless rlogin via /etc/hosts.equiv
# WARNING: This is extremely insecure - allows any host/user
RUN echo "+ +" > /etc/hosts.equiv && \
    chmod 644 /etc/hosts.equiv

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create start script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'service xinetd start' >> /start.sh && \
    echo '/usr/sbin/sshd -D' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 513

CMD ["/start.sh"]
