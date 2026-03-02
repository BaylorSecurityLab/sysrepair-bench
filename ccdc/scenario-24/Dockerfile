FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Accept ICMP redirects (allows route manipulation attacks)
# Disable logging of martian packets (hides suspicious traffic)
RUN echo "net.ipv4.conf.all.accept_redirects = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.accept_redirects = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.log_martians = 0" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.log_martians = 0" >> /etc/sysctl.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
