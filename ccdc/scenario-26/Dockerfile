FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    ncat \
    hydra \
    john \
    nikto \
    procps \
    curl \
    wget \
    iputils-ping \
    iproute2 \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*


CMD ["sleep", "infinity"]
