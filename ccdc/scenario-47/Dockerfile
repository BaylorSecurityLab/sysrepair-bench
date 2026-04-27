FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libpam-pwquality \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Configure extremely permissive password complexity.
# Set minlen=1 and disable all complexity requirements in pwquality.conf.
# This allows users to set trivially weak passwords like "a" or "1".
RUN sed -i 's/^# minlen.*/minlen = 1/' /etc/security/pwquality.conf && \
    sed -i 's/^minlen.*/minlen = 1/' /etc/security/pwquality.conf && \
    echo "minlen = 1" >> /etc/security/pwquality.conf && \
    echo "dcredit = 0" >> /etc/security/pwquality.conf && \
    echo "ucredit = 0" >> /etc/security/pwquality.conf && \
    echo "lcredit = 0" >> /etc/security/pwquality.conf && \
    echo "ocredit = 0" >> /etc/security/pwquality.conf && \
    echo "minclass = 0" >> /etc/security/pwquality.conf && \
    echo "maxrepeat = 0" >> /etc/security/pwquality.conf && \
    echo "maxclassrepeat = 0" >> /etc/security/pwquality.conf && \
    echo "gecoscheck = 0" >> /etc/security/pwquality.conf && \
    echo "dictcheck = 0" >> /etc/security/pwquality.conf && \
    echo "enforcing = 0" >> /etc/security/pwquality.conf

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:TestP@ss123" | chpasswd


CMD ["sleep", "infinity"]
