FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server (sshpass pre-baked so verify.sh skips its runtime install)
RUN apt-get update && \
    apt-get install -y openssh-server passwd sshpass && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configure weak ciphers (VULNERABLE)
# Includes deprecated 3des-cbc and CBC-mode ciphers alongside strong CTR ciphers
RUN echo "Ciphers 3des-cbc,aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
