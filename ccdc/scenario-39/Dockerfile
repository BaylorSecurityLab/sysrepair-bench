FROM ubuntu:rolling
# Scenario 39: /etc/shadow world-readable
# CWE-732: Incorrect Permission Assignment for Critical Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Make /etc/shadow world-readable (vulnerable)
RUN chmod 644 /etc/shadow

# Create users with passwords (hashes will be exposed)
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:webpass456' | chpasswd

RUN mkdir -p /run/sshd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
