FROM ubuntu:25.10
# Scenario 29: No firewall installed (ufw absent)
# CWE-1188: Insecure Default Initialization of Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure no firewall is installed (remove ufw if present)
RUN apt-get remove --purge -y ufw iptables 2>/dev/null; \
    apt-get autoremove -y 2>/dev/null; true

# Set up services that should be protected by a firewall
RUN mkdir -p /run/sshd && \
    echo '<html><body><h1>Web Server</h1></body></html>' > /var/www/html/index.html

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd


EXPOSE 22 80
# Boot BOTH services that the firewall is supposed to protect (sshd and nginx),
# then hold the container open with `sleep infinity` (paired with the
# `.preserve-cmd` marker). `-g "daemon off;"` is dropped so nginx daemonises and
# control reaches the `exec`, which keeps PID 1 stable: an agent restarting
# either daemon cannot kill the container, and both are already exposed with no
# packet filter at all when the agent is handed the box.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && service ssh start && nginx && exec sleep infinity"]
