FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install SSH (legitimate management channel). The base image already ships
# nc.traditional, which supports the -e "gaping security hole" flag the backdoor
# needs — netcat-openbsd removed -e, so we deliberately use nc.traditional.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create the Ingreslock backdoor script — the famous Metasploitable 2 backdoor.
# nc.traditional -e /bin/sh bound to 1524 gives an UNAUTHENTICATED ROOT SHELL.
RUN echo '#!/bin/bash' > /opt/ingreslock_backdoor.sh && \
    echo 'while true; do' >> /opt/ingreslock_backdoor.sh && \
    echo '  /bin/nc.traditional -l -p 1524 -e /bin/sh' >> /opt/ingreslock_backdoor.sh && \
    echo '  sleep 1' >> /opt/ingreslock_backdoor.sh && \
    echo 'done' >> /opt/ingreslock_backdoor.sh && \
    chmod +x /opt/ingreslock_backdoor.sh

# Boot wrapper: start the backdoor loop AND sshd in the BACKGROUND, then keep
# PID 1 as `sleep infinity` so an agent restarting a service can never kill the
# container. The live backdoor is already listening when the agent starts, so
# "removed the script from disk but never killed the running listener" is
# detectable. (.preserve-cmd marker makes the harness honor this CMD.)
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/opt/ingreslock_backdoor.sh &' >> /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 1524

CMD ["/start.sh"]
