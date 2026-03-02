FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    procps \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Disable ASLR - makes memory layout predictable for exploits
RUN echo "kernel.randomize_va_space = 0" >> /etc/sysctl.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
