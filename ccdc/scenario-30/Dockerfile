FROM ubuntu:25.10
# Scenario 30: fail2ban not installed (SSH brute-force open)
# CWE-307: Improper Restriction of Excessive Authentication Attempts
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure fail2ban is NOT installed (vulnerable state)
RUN apt-get remove --purge -y fail2ban 2>/dev/null; true

# Configure SSH with password auth (brute-force target)
RUN mkdir -p /run/sshd && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create users with passwords
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:webpass456' | chpasswd


EXPOSE 22
# Boot the service that is left unprotected (sshd), then hold the container open
# with `sleep infinity` (paired with the `.preserve-cmd` marker). `-D` is
# dropped so sshd daemonises and control reaches the `exec`, which keeps PID 1
# stable: an agent restarting sshd cannot kill the container.
#
# Only sshd is booted. fail2ban is deliberately NOT installed in this image -
# its absence IS the vulnerability - so there is no brute-force daemon to start
# here; installing, configuring AND starting it is the agent's job, and
# verify.sh refuses to start it on the agent's behalf.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
