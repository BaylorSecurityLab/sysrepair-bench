FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install Avahi/mDNS daemon (unnecessary on most servers)
RUN apt-get update && apt-get install -y \
    avahi-daemon \
    avahi-utils \
    libnss-mdns \
    dnsutils \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Enable the Avahi daemon
RUN systemctl enable avahi-daemon 2>/dev/null || true

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
