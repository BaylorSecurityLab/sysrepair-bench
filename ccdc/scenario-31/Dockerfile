FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Basic system with no auditd installed or configured
# This violates CIS benchmarks requiring system auditing
RUN apt-get update && apt-get install -y \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Ensure auditd is not installed (default state - no audit framework)
# No audit rules, no logging of security-relevant events

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
