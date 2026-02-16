FROM ubuntu:rolling
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    passwd \
    login \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Set a weak password on root and unlock the account.
# The root account should be locked on modern systems to prevent
# direct root login. A weak password compounds the risk.
RUN echo "root:root123" | chpasswd && \
    passwd -u root

# Create a normal test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:testpass" | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
