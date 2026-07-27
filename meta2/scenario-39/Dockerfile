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
# Boot wrapper: start sshd in the BACKGROUND, keep PID 1 as `sleep infinity` so
# an agent reloading the firewall or restarting sshd cannot kill the container.
# The box boots with NO host firewall (INPUT policy ACCEPT) — the exposed EOL
# baseline — so "wrote firewall rules but never applied them" stays exposed.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
