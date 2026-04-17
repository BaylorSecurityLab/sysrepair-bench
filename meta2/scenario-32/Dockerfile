FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install netcat and SSH
RUN apt-get update && \
    apt-get install -y netcat-openbsd openssh-server

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create the Ingreslock backdoor script
# This simulates the famous Metasploitable 2 backdoor on port 1524
RUN echo '#!/bin/bash' > /opt/ingreslock_backdoor.sh && \
    echo 'while true; do' >> /opt/ingreslock_backdoor.sh && \
    echo '  nc -l -p 1524 -e /bin/sh' >> /opt/ingreslock_backdoor.sh && \
    echo '  sleep 1' >> /opt/ingreslock_backdoor.sh && \
    echo 'done' >> /opt/ingreslock_backdoor.sh && \
    chmod +x /opt/ingreslock_backdoor.sh

# Create start script that runs both backdoor and SSH
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/opt/ingreslock_backdoor.sh &' >> /start.sh && \
    echo '/usr/sbin/sshd -D' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 1524

CMD ["/start.sh"]
