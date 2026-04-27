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
CMD ["/usr/sbin/sshd", "-D"]
