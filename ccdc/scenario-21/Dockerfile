FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Insecure sysctl: enable IP forwarding and ICMP send_redirects
# This turns the host into a potential router/MitM pivot point
RUN echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.all.send_redirects = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.conf.default.send_redirects = 1" >> /etc/sysctl.conf


CMD ["sleep", "infinity"]
