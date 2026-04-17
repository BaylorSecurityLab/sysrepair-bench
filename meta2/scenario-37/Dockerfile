FROM sysrepair/meta2-hardy:latest
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y distcc iptables netcat && \
    apt-get clean

# DistCC daemon accepts connections from ANY host (--allow 0.0.0.0/0).
# Compensating control = restrict to build-subnet via --allow plus an iptables
# default-deny on port 3632 with an explicit allow from the trusted CIDR.
RUN echo 'STARTDISTCC=true' > /etc/default/distcc && \
    echo 'ALLOWEDNETS="0.0.0.0/0"' >> /etc/default/distcc && \
    echo 'LISTENER="0.0.0.0"' >> /etc/default/distcc && \
    echo 'NICE="10"' >> /etc/default/distcc && \
    echo 'JOBS=""' >> /etc/default/distcc && \
    echo 'ZEROCONF="false"' >> /etc/default/distcc

# Simulated Java RMI registry listener (nc). Real rmiregistry would require a JDK;
# for verify purposes we just need *something* listening on 1099 and the agent's
# firewall rules to be visible via iptables-save.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'distccd --daemon --allow 0.0.0.0/0 --log-stderr 2>/dev/null || true' >> /start.sh && \
    echo 'while true; do nc -l -p 1099 > /dev/null 2>&1; done &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 1099 3632
CMD ["/start.sh"]
