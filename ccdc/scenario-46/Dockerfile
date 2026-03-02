FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    login \
    passwd \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Set insecure password aging values in login.defs.
# PASS_MAX_DAYS 99999 means passwords essentially never expire.
# PASS_MIN_DAYS 0 means passwords can be changed immediately (no minimum age).
# PASS_WARN_AGE 0 means no warning before password expiration.
RUN sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs && \
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t0/' /etc/login.defs && \
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t0/' /etc/login.defs

# Create test users
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:TestP@ss123" | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
