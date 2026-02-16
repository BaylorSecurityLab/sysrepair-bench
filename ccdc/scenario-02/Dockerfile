FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server and utilities
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a user with an empty password (VULNERABLE)
RUN useradd -m -s /bin/bash emptyuser && \
    passwd -d emptyuser

# Create a normal user with a real password for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Configure SSH to allow empty passwords (VULNERABLE)
RUN sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config && \
    grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
