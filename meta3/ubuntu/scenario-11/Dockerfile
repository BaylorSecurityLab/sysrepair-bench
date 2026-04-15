FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get clean

# Install minimal tooling needed inside the container
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        sudo \
        curl \
        wget \
    && apt-get clean

# Create the docker group (mirrors what the docker install script does)
RUN groupadd -f docker

# Create the privileged service user and add them to the docker group
# This replicates the Metasploitable 3 design: meta3admin belongs to docker
RUN useradd -m -s /bin/bash meta3admin && \
    echo 'meta3admin:meta3admin' | chpasswd && \
    usermod -aG docker meta3admin

# Install the docker CLI binary so the privilege escalation path is realistic
# (daemon not started -- scenario is about group membership, not a running daemon)
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-19.03.15.tgz | \
        tar xz --strip-components=1 -C /usr/local/bin docker/docker 2>/dev/null || \
    ( apt-get install -y --no-install-recommends apt-transport-https ca-certificates && \
      echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu trusty stable" \
          > /etc/apt/sources.list.d/docker.list && \
      apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y docker-engine 2>/dev/null || true )

COPY scenario-11/verify.sh /verify.sh
RUN chmod +x /verify.sh

# No network service; container stays up with a sleep loop for exec-based testing
CMD ["bash", "-c", "while true; do sleep 60; done"]
