FROM ubuntu:25.10
# Scenario 40: /etc/passwd writable by others
# CWE-732: Incorrect Permission Assignment for Critical Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create users
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd
RUN useradd -m -s /bin/bash webadmin && echo 'webadmin:webpass456' | chpasswd

# Make /etc/passwd writable by others (vulnerable)
# SCENARIO-DESIGN FIX: this chmod used to run BEFORE the useradd steps, but
# useradd rewrites /etc/passwd via a temp file + rename and resets the mode to
# 0664 - so the built image was NOT world-writable, the CWE-732 vulnerability
# was absent, and verify.sh's live write-probe could never fail. It must come
# last so the vulnerable mode actually survives into the image.
RUN chmod 666 /etc/passwd

RUN mkdir -p /run/sshd


EXPOSE 22
# Boot the service, then hold the container open with `sleep infinity` (paired
# with the `.preserve-cmd` marker). `-D` is dropped so sshd daemonises and
# control reaches the `exec`, which keeps PID 1 stable: an agent restarting sshd
# cannot kill the container, and sshd is genuinely LIVE while /etc/passwd is
# re-permissioned - so a chmod that breaks NSS/login is caught for real.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && exec sleep infinity"]
