FROM sysrepair/meta2-hardy:latest
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables openssh-server && \
    apt-get clean

RUN mkdir -p /var/run/sshd && echo 'root:toor' | chpasswd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# EOL OS: no upstream patches, no `do-release-upgrade` path that preserves the
# application stack. Compensating control = default-deny host firewall keeping
# only the critical management port (SSH) reachable.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
