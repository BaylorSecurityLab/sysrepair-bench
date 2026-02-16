FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server
RUN apt-get update && \
    apt-get install -y openssh-server passwd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create the SSH run directory
RUN mkdir -p /run/sshd

# Create a normal user for regression testing
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:TestPass123!' | chpasswd

# Ensure password authentication is enabled
RUN sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Enable X11 forwarding (VULNERABLE)
RUN sed -i 's/^#*X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config && \
    grep -q '^X11Forwarding' /etc/ssh/sshd_config || echo "X11Forwarding yes" >> /etc/ssh/sshd_config

# Set high MaxAuthTries (VULNERABLE - allows brute force)
RUN sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 30/' /etc/ssh/sshd_config && \
    grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo "MaxAuthTries 30" >> /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
