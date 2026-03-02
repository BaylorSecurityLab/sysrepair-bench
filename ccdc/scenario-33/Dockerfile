FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSL but hold it at the initially installed version
# to simulate a system that has not been updated
RUN apt-get update && apt-get install -y \
    openssl \
    libssl-dev \
    ca-certificates \
    curl \
    wget \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Mark openssl as held to prevent automatic updates (simulates stale system)
RUN apt-mark hold openssl libssl3t64 2>/dev/null || apt-mark hold openssl libssl3 2>/dev/null || true

# Create a marker file indicating this system has a known-vulnerable OpenSSL
# and record the current version for comparison after remediation
RUN openssl version > /opt/.openssl_vulnerable_version
RUN echo "VULNERABLE_OPENSSL=true" > /opt/.openssl_status

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
