FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Set SUID bit on python3 and perl interpreters.
# This allows any local user to execute scripts with root privileges,
# enabling trivial privilege escalation.
RUN chmod u+s /usr/bin/python3* /usr/bin/perl

# Create a non-root test user
RUN useradd -m -s /bin/bash testuser

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
