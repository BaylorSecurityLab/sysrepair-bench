FROM ubuntu:rolling
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install CUPS printing system (unnecessary on a server)
RUN apt-get update && apt-get install -y \
    cups \
    cups-browsed \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Enable CUPS services (simulating a default desktop-like install on a server)
RUN systemctl enable cups 2>/dev/null || true
RUN systemctl enable cups-browsed 2>/dev/null || true

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
