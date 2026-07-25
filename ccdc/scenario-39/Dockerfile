FROM ubuntu:25.10
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


EXPOSE 22
# Boot the service, then hold the container open with `sleep infinity` (paired
# with the `.preserve-cmd` marker). `-D` is dropped so sshd daemonises and
# control reaches the `exec`, which keeps PID 1 stable: an agent restarting sshd
# cannot kill the container, and sshd is genuinely LIVE while /etc/shadow
# permissions change - so a chmod that breaks PAM/password auth is caught for
# real rather than being hidden behind a freshly started daemon.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
