FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install base system but explicitly remove unattended-upgrades
RUN apt-get update && apt-get install -y \
    apt-utils \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Ensure unattended-upgrades is NOT installed
RUN apt-get purge -y unattended-upgrades 2>/dev/null || true
RUN rm -f /etc/apt/apt.conf.d/20auto-upgrades
RUN rm -f /etc/apt/apt.conf.d/50unattended-upgrades

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
