FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Disable SYN cookies (vulnerable to SYN flood attacks)
# Enable source routing (allows attacker-controlled packet routing)
RUN echo "net.ipv4.tcp_syncookies = 0" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.accept_source_route = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.accept_source_route = 1" >> /etc/sysctl.conf


CMD ["sleep", "infinity"]
