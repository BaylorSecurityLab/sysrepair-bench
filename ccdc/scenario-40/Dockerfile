FROM ubuntu:25.10
# Scenario 40: /etc/passwd writable by others
# CWE-732: Incorrect Permission Assignment for Critical Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Make /etc/passwd writable by others (vulnerable)
RUN chmod 666 /etc/passwd

# Create users
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:webpass456' | chpasswd

RUN mkdir -p /run/sshd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
