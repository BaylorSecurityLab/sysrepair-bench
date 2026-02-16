FROM ubuntu:25.10
# Scenario 05: SSH password auth with no key restriction
# CWE-308: Use of Single-factor Authentication


RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vulnerable SSH configuration - password-only auth, no key enforcement
RUN mkdir -p /run/sshd && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication no/' /etc/ssh/sshd_config && \
    grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication no' >> /etc/ssh/sshd_config && \
    echo 'UsePAM yes' >> /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:admin' | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
