FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Create a backdoor user with UID 0 (same as root).
# This gives the "backdoor" user full root privileges, bypassing
# normal access controls and audit trails.
RUN useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor && \
    echo "backdoor:backdoor123" | chpasswd

# Create a normal test user
RUN useradd -m -s /bin/bash testuser

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
