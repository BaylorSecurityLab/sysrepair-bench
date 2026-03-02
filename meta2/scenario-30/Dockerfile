FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install telnet server and SSH as the secure alternative
RUN apt-get update && \
    apt-get install -y telnetd xinetd openssh-server

# Configure xinetd to enable telnet service
RUN echo "service telnet" > /etc/xinetd.d/telnet && \
    echo "{" >> /etc/xinetd.d/telnet && \
    echo "  disable = no" >> /etc/xinetd.d/telnet && \
    echo "  flags = REUSE" >> /etc/xinetd.d/telnet && \
    echo "  socket_type = stream" >> /etc/xinetd.d/telnet && \
    echo "  wait = no" >> /etc/xinetd.d/telnet && \
    echo "  user = root" >> /etc/xinetd.d/telnet && \
    echo "  server = /usr/sbin/in.telnetd" >> /etc/xinetd.d/telnet && \
    echo "  log_on_failure += USERID" >> /etc/xinetd.d/telnet && \
    echo "}" >> /etc/xinetd.d/telnet

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create start script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'service xinetd start' >> /start.sh && \
    echo '/usr/sbin/sshd -D' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 23

CMD ["/start.sh"]
